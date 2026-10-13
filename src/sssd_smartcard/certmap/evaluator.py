"""Mapping Tester -- evaluate a certmap rule against a real certificate.

Two engines, deliberately kept apart:

``local``
    A pure-Python reimplementation of the matching and template rules.  It runs
    anywhere, including on a workstation with no SSSD, and explains term by term
    why a certificate matched or did not.

``sssctl``
    ``sssctl cert-eval-rule``, which is libsss_certmap itself.  When it is
    available its verdict is the authoritative one.

``evaluate()`` runs both when it can and reports disagreement loudly, because a
divergence means the local engine is wrong about something and the operator
should trust sssctl.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..errors import RuleSyntaxError
from ..util import CommandResult, run
from ..x509.inspect import CertificateInfo, normalise_eku
from .rules import BASE64_KEYWORDS, MapRule, MatchRule, MatchTerm


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


@dataclass
class TermResult:
    term: MatchTerm
    matched: bool
    observed: list[str] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "term": self.term.render(),
            "matched": self.matched,
            "observed": self.observed,
            "detail": self.detail,
        }


@dataclass
class MatchResult:
    matched: bool
    groups: list[list[TermResult]] = field(default_factory=list)
    engine: str = "local"

    @property
    def failed_terms(self) -> list[TermResult]:
        return [t for group in self.groups for t in group if not t.matched]

    def to_dict(self) -> dict:
        return {
            "matched": self.matched,
            "engine": self.engine,
            "groups": [[t.to_dict() for t in g] for g in self.groups],
        }


def _values_for(keyword: str, cert: CertificateInfo) -> list[str]:
    """The certificate values a ``<KEYWORD>`` component is tested against."""
    san = cert.san
    if keyword == "ISSUER":
        return [cert.issuer_dn]
    if keyword == "SUBJECT":
        return [cert.subject_dn]
    if keyword == "SAN":
        return cert.principals
    if keyword in ("SAN:Principal",):
        return cert.principals
    if keyword == "SAN:ntPrincipalName":
        return list(san.upn)
    if keyword == "SAN:pkinit":
        return list(san.pkinit)
    if keyword == "SAN:rfc822Name":
        return list(san.rfc822)
    if keyword == "SAN:dNSName":
        return list(san.dns)
    if keyword == "SAN:uniformResourceIdentifier":
        return list(san.uri)
    if keyword == "SAN:iPAddress":
        return list(san.ip)
    if keyword == "SAN:directoryName":
        return list(san.directory_name)
    if keyword == "SAN:registeredID":
        return list(san.registered_id)
    if keyword.startswith("SAN:") and re.fullmatch(r"[0-9.]+", keyword[4:]):
        oid = keyword[4:]
        return [value for name, value in san.other_name if name == oid]
    return []


def evaluate_term(term: MatchTerm, cert: CertificateInfo) -> TermResult:
    """Test one ``<KEYWORD>value`` component."""
    keyword = term.keyword

    if keyword == "EKU":
        wanted = [normalise_eku(t) for t in term.value.split(",") if t.strip()]
        present = cert.eku_oids
        missing = [oid for oid in wanted if oid not in present]
        return TermResult(
            term,
            not missing,
            cert.eku_labels,
            "" if not missing else "missing EKU: " + ", ".join(missing),
        )

    if keyword == "KU":
        wanted = [t.strip() for t in term.value.split(",") if t.strip()]
        present = cert.key_usage
        numeric = [w for w in wanted if w.isdigit()]
        named = [w for w in wanted if not w.isdigit()]
        missing = [w for w in named if w not in present]
        detail = "" if not missing else "missing key usage: " + ", ".join(missing)
        if numeric:
            detail = (detail + "; " if detail else "") + (
                "numeric key usage values are not evaluated locally: "
                + ", ".join(numeric)
            )
        return TermResult(term, not missing, present, detail)

    if keyword in BASE64_KEYWORDS:
        return TermResult(
            term,
            False,
            [],
            f"<{keyword}> compares raw DER against base64 and is only evaluated by "
            "sssctl cert-eval-rule; the local engine cannot decide it",
        )

    observed = _values_for(keyword, cert)
    if not observed:
        return TermResult(
            term, False, [], f"the certificate has no {keyword} value to compare"
        )
    try:
        pattern = re.compile(term.value)
    except re.error as exc:
        raise RuleSyntaxError(
            f"invalid regular expression in <{keyword}>{term.value}: {exc}"
        ) from exc
    hits = [value for value in observed if pattern.search(value)]
    return TermResult(
        term,
        bool(hits),
        observed,
        "" if hits else f"no value matched /{term.value}/",
    )


def evaluate_match(rule: MatchRule, cert: CertificateInfo) -> MatchResult:
    """Evaluate a whole matching rule.

    Components concatenated within a group are ANDed, which is both the
    documented default and what libsss_certmap does -- confirmed against SSSD
    2.9.4 with positive and negative controls on every component. Separate
    groups are ORed, but see :attr:`MatchRule.or_is_fragile`: SSSD mishandles
    ``||``, so an OR rule's verdict here can differ from the real one and
    ``sssctl cert-eval-rule`` is the authority.
    """
    if rule.empty:
        return MatchResult(True, [], "local")
    groups: list[list[TermResult]] = []
    matched = False
    for group in rule.groups:
        results = [evaluate_term(term, cert) for term in group]
        groups.append(results)
        if results and all(r.matched for r in results):
            matched = True
    return MatchResult(matched, groups, "local")


# ---------------------------------------------------------------------------
# Mapping templates
# ---------------------------------------------------------------------------

_TEMPLATE_RE = re.compile(
    r"\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P<selector>(?:\.[A-Za-z0-9_.-]+|\[-?[0-9]+\])*)"
    r"(?:!(?P<conv>[A-Za-z0-9_]+))?\}"
)


@dataclass
class MapResult:
    filter: str
    values: dict[str, str] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)
    engine: str = "local"

    @property
    def complete(self) -> bool:
        return not self.missing

    def to_dict(self) -> dict:
        return {
            "filter": self.filter,
            "values": self.values,
            "missing": self.missing,
            "engine": self.engine,
        }


def _hex_modifiers(suffix: str) -> tuple[bool, bool, bool]:
    """Decode the ``_ucr`` flags: upper case, colon separated, reversed."""
    return "u" in suffix, "c" in suffix, "r" in suffix


def _format_bytes(raw: bytes, suffix: str) -> str:
    upper, colon, reverse = _hex_modifiers(suffix)
    if reverse:
        raw = raw[::-1]
    text = ":".join(f"{b:02x}" for b in raw) if colon else raw.hex()
    return text.upper() if upper else text


def _short_name(value: str, separator: str = "@") -> str:
    return value.split(separator, 1)[0]


def _pick_component(components: list[tuple[str, str]], selector: str) -> str | None:
    """Implement ``{subject_dn_component[.attr][[n]]}`` selection."""
    attr: str | None = None
    index: int | None = None
    for part in re.findall(r"\.([A-Za-z0-9_-]+)|\[(-?[0-9]+)\]", selector or ""):
        if part[0]:
            attr = part[0]
        elif part[1]:
            index = int(part[1])
    pool = components
    if attr:
        pool = [(k, v) for k, v in components if k.lower() == attr.lower()]
    if not pool:
        return None
    if index is None:
        return pool[0][1]
    if index > 0:
        return pool[index - 1][1] if index <= len(pool) else None
    # Negative counts from the least specific component.
    return pool[index][1] if -index <= len(pool) else None


def expand_template(
    name: str, selector: str, conversion: str | None, cert: CertificateInfo
) -> str | None:
    """Produce the value libsss_certmap would substitute, or ``None``."""
    short = ".short_name" in (selector or "")

    if name in ("issuer_dn", "subject_dn"):
        source = cert.cert.issuer if name == "issuer_dn" else cert.cert.subject
        from ..x509.names import format_dn

        return format_dn(source, conversion or "nss_ldap")

    if name == "subject_directory_name":
        names = cert.san.directory_name
        return names[0] if names else None

    if name == "cert":
        conv = (conversion or "bin").lower()
        if conv == "base64":
            return cert.base64_der
        if conv == "bin":
            # sss-certmap renders the DER as an escaped hex sequence.
            return "".join(f"\\{b:02x}" for b in cert.der_bytes)
        algorithm = conv.split("_", 1)[0]
        suffix = conv.split("_", 1)[1] if "_" in conv else ""
        try:
            import hashlib

            digest = hashlib.new(algorithm, cert.der_bytes).digest()
        except ValueError:
            return None
        return _format_bytes(digest, suffix)

    if name == "subject_principal":
        values = cert.principals
        value = values[0] if values else None
    elif name == "subject_pkinit_principal":
        values = cert.san.pkinit
        value = values[0] if values else None
    elif name == "subject_nt_principal":
        values = cert.san.upn
        value = values[0] if values else None
    elif name == "subject_rfc822_name":
        values = cert.san.rfc822
        value = values[0] if values else None
    elif name == "subject_dns_name":
        values = cert.san.dns
        value = values[0] if values else None
        if value is not None and short:
            return _short_name(value, ".")
    elif name == "subject_uri":
        values = cert.san.uri
        value = values[0] if values else None
    elif name == "subject_ip_address":
        values = cert.san.ip
        value = values[0] if values else None
    elif name == "subject_registered_id":
        values = cert.san.registered_id
        value = values[0] if values else None
    elif name == "serial_number":
        conv = (conversion or "hex").lower()
        if conv == "dec":
            return str(cert.serial_int)
        suffix = conv.split("_", 1)[1] if "_" in conv else ""
        return _format_bytes(cert.serial_bytes(), suffix)
    elif name == "subject_key_id":
        raw = cert.subject_key_id
        if raw is None:
            return None
        conv = (conversion or "hex").lower()
        suffix = conv.split("_", 1)[1] if "_" in conv else ""
        return _format_bytes(raw, suffix)
    elif name == "sid":
        value = cert.sid
        if value and selector and ".rid" in selector:
            return value.rsplit("-", 1)[-1]
        return value
    elif name == "subject_dn_component":
        return _pick_component(cert.subject_components, selector)
    elif name == "issuer_dn_component":
        return _pick_component(cert.issuer_components, selector)
    elif name in ("subject_x400_address", "subject_ediparty_name"):
        # Rendered as an escaped hex sequence; we do not keep the raw DER for
        # these rare SAN types, so report them as unavailable rather than guess.
        return None
    else:
        return None

    if value is None:
        return None
    return _short_name(value) if short else value


def render_map(rule: MapRule, cert: CertificateInfo) -> MapResult:
    """Substitute every template in *rule* with values from *cert*."""
    values: dict[str, str] = {}
    missing: list[str] = []

    def replace(match: re.Match) -> str:
        placeholder = match.group(0)
        value = expand_template(
            match.group("name"), match.group("selector") or "", match.group("conv"), cert
        )
        if value is None:
            missing.append(placeholder)
            return placeholder
        values[placeholder] = value
        return value

    rendered = _TEMPLATE_RE.sub(replace, rule.template)
    return MapResult(rendered, values, missing, "local")


# ---------------------------------------------------------------------------
# sssctl -- the authority
# ---------------------------------------------------------------------------


@dataclass
class SssctlResult:
    available: bool
    matched: bool | None = None
    filter: str | None = None
    raw: str = ""
    command: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "matched": self.matched,
            "filter": self.filter,
            "command": " ".join(self.command),
            "raw": self.raw,
            "error": self.error,
        }


def sssctl_eval_rule(
    cert: CertificateInfo, matchrule: str | None, maprule: str | None
) -> SssctlResult:
    """Ask ``sssctl cert-eval-rule`` what libsss_certmap thinks."""
    argv = ["sssctl", "cert-eval-rule", cert.base64_der]
    if matchrule:
        argv.append(f"--match={matchrule}")
    if maprule:
        argv.append(f"--map={maprule}")
    result: CommandResult = run(argv, timeout=30)
    if not result.found:
        return SssctlResult(
            False, command=argv, error="sssctl is not installed on this host"
        )
    text = result.output
    lowered = text.lower()

    # sssctl refuses a rule libsss_certmap cannot parse, with a message such as
    # "Failed to add mapping and matching rules with error [22][Invalid
    # argument]." That is NOT a verdict about the certificate, and it must never
    # be reported as one. A substring test for "match" used to see the word
    # inside "matching" and report MATCH on this very error.
    rejected = (
        result.returncode != 0
        or "failed to add" in lowered
        or "invalid argument" in lowered
        or "failed to parse" in lowered
        or "error [" in lowered
    )
    if rejected:
        return SssctlResult(
            False,
            command=argv,
            raw=text,
            error=(
                "sssctl rejected the rule rather than evaluating it: "
                + (text.strip().splitlines()[0] if text.strip() else "no output")
            ),
        )
    if not text.strip():
        return SssctlResult(
            False, command=argv, error="sssctl produced no output to interpret"
        )

    # Only these exact phrases are a verdict.
    matched: bool | None = None
    if "does not match" in lowered or "no match" in lowered:
        matched = False
    elif "matches rule" in lowered or "certificate matches" in lowered:
        matched = True

    mapped: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("(") and stripped.endswith(")"):
            mapped = stripped
        elif ":" in stripped and stripped.split(":", 1)[0].strip().lower() in (
            "mapping rule",
            "mapped user filter",
            "ldap filter",
        ):
            mapped = stripped.split(":", 1)[1].strip()
    return SssctlResult(True, matched, mapped, text, argv)


# ---------------------------------------------------------------------------
# Combined
# ---------------------------------------------------------------------------


@dataclass
class EvaluationResult:
    """Local verdict, sssctl verdict, and whether they agree."""

    match: MatchResult
    mapping: MapResult
    sssctl: SssctlResult
    disagreement: str | None = None

    @property
    def matched(self) -> bool:
        if self.sssctl.available and self.sssctl.matched is not None:
            return self.sssctl.matched
        return self.match.matched

    @property
    def authority(self) -> str:
        return "sssctl" if self.sssctl.available and self.sssctl.matched is not None else "local"

    def to_dict(self) -> dict:
        return {
            "matched": self.matched,
            "authority": self.authority,
            "local_match": self.match.to_dict(),
            "local_mapping": self.mapping.to_dict(),
            "sssctl": self.sssctl.to_dict(),
            "disagreement": self.disagreement,
        }


def evaluate(
    cert: CertificateInfo,
    matchrule: MatchRule,
    maprule: MapRule,
    *,
    use_sssctl: bool = True,
) -> EvaluationResult:
    """Run both engines and compare them."""
    local_match = evaluate_match(matchrule, cert)
    local_map = render_map(maprule, cert)
    if use_sssctl:
        remote = sssctl_eval_rule(cert, matchrule.render() or None, maprule.render())
    else:
        remote = SssctlResult(False, error="sssctl engine disabled by --no-sssctl")

    disagreement = None
    if remote.available and remote.matched is not None:
        if remote.matched != local_match.matched:
            disagreement = (
                f"sssctl says {'MATCH' if remote.matched else 'NO MATCH'} while the local "
                f"engine says {'MATCH' if local_match.matched else 'NO MATCH'}. "
                "Trust sssctl -- it is libsss_certmap itself."
            )
        elif (
            remote.filter
            and local_map.complete
            and remote.filter.strip() != local_map.filter.strip()
        ):
            disagreement = (
                "sssctl produced a different LDAP filter than the local engine. "
                "Trust sssctl."
            )
    return EvaluationResult(local_match, local_map, remote, disagreement)
