"""Typed representation of SSSD matching and mapping rules.

Syntax follows ``sss-certmap(5)``:

* A *matching rule* is a list of ``<KEYWORD>value`` components joined with
  ``&&`` and ``||``.  Its default prefix is ``KRB5``.
* A *mapping rule* is an LDAP search filter with ``{template}`` placeholders.
  Its default prefix is ``LDAP``; the extended templates require ``LDAPU1``.

Building rules through these classes rather than string concatenation keeps
escaping in exactly one place and lets the renderer reason about which
templates a rule uses when it checks SSSD version compatibility.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..errors import RuleSyntaxError

#: Characters ``sss-certmap(5)`` says must be escaped inside a matching rule's
#: regular expression.  Note ``]`` and ``}`` are deliberately absent -- the man
#: page does not list them and POSIX ERE does not require them outside a
#: bracket expression.
REGEX_SPECIAL = "^.[$()|*+?{\\"

MATCH_PREFIXES = ("KRB5",)
MAP_PREFIXES = ("LDAP", "LDAPU1")

#: Keywords accepted in a matching rule, exactly as documented.
MATCH_KEYWORDS = (
    "ISSUER",
    "SUBJECT",
    "KU",
    "EKU",
    "SAN",
    "SAN:Principal",
    "SAN:ntPrincipalName",
    "SAN:pkinit",
    "SAN:rfc822Name",
    "SAN:dNSName",
    "SAN:x400Address",
    "SAN:directoryName",
    "SAN:ediPartyName",
    "SAN:uniformResourceIdentifier",
    "SAN:iPAddress",
    "SAN:registeredID",
    "SAN:otherName",
)

#: Keywords whose value is base64 rather than a regular expression.
BASE64_KEYWORDS = {"SAN:otherName", "SAN:x400Address", "SAN:ediPartyName"}

#: Keywords whose value is a comma separated token list.
LIST_KEYWORDS = {"KU", "EKU"}

_KEYWORD_LOOKUP = {k.lower(): k for k in MATCH_KEYWORDS}
_OID_RE = re.compile(r"[0-9]+(\.[0-9]+)+")

#: Start of a matching-rule component: an optional prefixed operator followed by
#: ``<KEYWORD>``. Everything up to the next such marker is that component's
#: value, which is exactly how libsss_certmap reads it.
_COMPONENT_RE = re.compile(
    r"(?P<op>&&|\|\|)?\s*<(?P<kw>SUBJECT|ISSUER|KU|EKU|SAN(?::[A-Za-z0-9._]+)?)>",
    re.IGNORECASE,
)


def escape_regex(value: str) -> str:
    """Escape *value* so it matches literally inside a matching rule."""
    return "".join("\\" + ch if ch in REGEX_SPECIAL else ch for ch in value)


def anchored(value: str) -> str:
    """Escape *value* and anchor it, so ``CN=CA`` cannot match ``CN=CA2``."""
    return "^" + escape_regex(value) + "$"


def canonical_keyword(keyword: str) -> str:
    """Normalise keyword case; unknown ``SAN:<oid>`` forms pass through."""
    known = _KEYWORD_LOOKUP.get(keyword.lower())
    if known:
        return known
    if keyword.upper().startswith("SAN:") and _OID_RE.fullmatch(keyword[4:]):
        return keyword
    raise RuleSyntaxError(
        f"unknown matching rule keyword <{keyword}>; expected one of "
        + ", ".join(MATCH_KEYWORDS)
        + " or SAN:<dotted-decimal-oid>"
    )


@dataclass(frozen=True)
class MatchTerm:
    """One ``<KEYWORD>value`` component of a matching rule."""

    keyword: str
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "keyword", canonical_keyword(self.keyword))

    def render(self) -> str:
        return f"<{self.keyword}>{self.value}"

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.render()


@dataclass
class MatchRule:
    """A matching rule as a disjunction of conjunctions.

    ``groups`` is OR-of-AND: ``[[a, b], [c]]`` renders as ``a && b || c``.
    """

    groups: list[list[MatchTerm]] = field(default_factory=list)
    prefix: str = "KRB5"

    @classmethod
    def all_of(cls, *terms: MatchTerm, prefix: str = "KRB5") -> "MatchRule":
        return cls([[t for t in terms if t is not None]], prefix)

    @property
    def terms(self) -> list[MatchTerm]:
        """Every term, flattened -- handy for inspection and compat checks."""
        return [term for group in self.groups for term in group]

    @property
    def empty(self) -> bool:
        return not any(self.groups)

    def render(self, *, include_prefix: bool = True) -> str:
        """Render the rule the way libsss_certmap actually parses it.

        Components within one rule are **concatenated with no operator**. This
        is not a stylistic choice: a component's value runs to the next ``<``,
        so writing ``<ISSUER>^CN=CA$ && <EKU>clientAuth`` puts the literal
        ``$ && `` inside the issuer regular expression, and either the rule
        never matches or ``<EKU>`` tries to parse ``clientAuth && <SAN:...>``
        as a key-usage list and the whole rule is rejected with EINVAL.

        ``sss-certmap(5)`` says only that pairs "can be either joined with '&&'
        (and) or '||' (or)", which reads like an infix operator. The SSSD design
        page is the one that disambiguates it: rules "can be grouped together
        with a prefixed && (and) or || (or) operator (&& is the default)", and
        every upstream example concatenates, for instance
        ``<ISSUER>^CN=AD-CA,dc=ISSUER,DC=COM$<EKU>clientAuth<SAN:ntPrincipalName>*@AD.DOM``.
        """
        if self.empty:
            return ""
        groups = ["".join(term.render() for term in group) for group in self.groups if group]
        # && is the default and is never written out. || prefixes an
        # alternative group; see or_is_fragile() for why that is risky.
        body = groups[0] + "".join("||" + group for group in groups[1:])
        return f"{self.prefix}:{body}" if include_prefix else body

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.render()

    @property
    def or_is_fragile(self) -> bool:
        """True when this rule needs ``||``, which SSSD handles badly.

        Measured against SSSD 2.9.4: the literal ``||`` is left in the value of
        the component before it, so ``<ISSUER>^CN=Good$||<SAN:...>x`` turns the
        issuer pattern into ``^CN=Good$||`` and that branch can never match.
        """
        return len([g for g in self.groups if g]) > 1

    def validate(self) -> list[str]:
        """Problems with this rule, as libsss_certmap would see them."""
        problems: list[str] = []
        rendered = self.render(include_prefix=False)
        if re.search(r"\s(&&|\|\|)\s", rendered):
            problems.append(
                "the matching rule contains an infix ' && ' or ' || '; component "
                "values run to the next '<', so the operator and the spaces around "
                "it become part of the preceding pattern. Concatenate components "
                "instead."
            )
        if self.or_is_fragile:
            problems.append(
                "this rule uses '||'. SSSD leaves the literal '||' in the "
                "preceding component's value, so the branch before it cannot "
                "match. Verify with: sssctl cert-eval-rule"
            )
        # Deliberately NOT flagged: <EKU> or <KU> appearing before another
        # component. Their comma separated value terminates at the next '<',
        # so the middle position is fine -- verified against SSSD 2.9.4 with
        # positive and negative controls, and it is what upstream's own example
        # does: <ISSUER>...$<EKU>clientAuth<SAN:ntPrincipalName>*@AD.DOM
        return problems

    # -- parsing --------------------------------------------------------
    @classmethod
    def parse(cls, text: str) -> "MatchRule":
        """Parse a rule as written in ``sssd.conf``.

        Accepts both the correct concatenated form and the mistaken infix form,
        so that reading an existing broken configuration still works and the
        mistake can be reported rather than crashing.
        """
        text = text.strip()
        if not text:
            return cls([])
        prefix = "KRB5"
        for candidate in MATCH_PREFIXES:
            if text.upper().startswith(candidate + ":"):
                prefix = candidate
                text = text[len(candidate) + 1 :]
                break

        starts = list(_COMPONENT_RE.finditer(text))
        if not starts:
            raise RuleSyntaxError(
                f"no <KEYWORD> component found in matching rule: {text!r}"
            )
        if starts[0].start() != 0 and text[: starts[0].start()].strip():
            raise RuleSyntaxError(
                f"unexpected text before the first component: "
                f"{text[: starts[0].start()]!r}"
            )

        groups: list[list[MatchTerm]] = [[]]
        for index, match in enumerate(starts):
            end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
            value = text[match.end() : end]
            # Tolerate the infix form by stripping a trailing operator, so a
            # configuration written the wrong way can still be read back.
            value = re.sub(r"\s*(&&|\|\|)\s*$", "", value)
            if match.group("op") == "||" and groups[-1]:
                groups.append([])
            groups[-1].append(MatchTerm(match.group("kw"), value.strip()))
        if not groups[-1]:
            groups.pop()
        return cls(groups, prefix)


#: Templates documented for the base ``LDAP`` prefix.
LDAP_TEMPLATES = {
    "issuer_dn",
    "subject_dn",
    "cert",
    "subject_principal",
    "subject_pkinit_principal",
    "subject_nt_principal",
    "subject_rfc822_name",
    "subject_dns_name",
    "subject_uri",
    "subject_ip_address",
    "subject_x400_address",
    "subject_directory_name",
    "subject_ediparty_name",
    "subject_registered_id",
}

#: Templates that require the ``LDAPU1`` prefix.
LDAPU1_TEMPLATES = {
    "serial_number",
    "subject_key_id",
    "subject_dn_component",
    "issuer_dn_component",
    "sid",
}

_TEMPLATE_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)((?:\.[^}!\[]+)|(?:\[[^\]]*\]))*(![^}]*)?\}")


@dataclass
class MapRule:
    """A mapping rule: an LDAP filter with ``{template}`` placeholders."""

    template: str
    prefix: str = "LDAP"

    def __post_init__(self) -> None:
        self.prefix = self.prefix.upper()
        if self.prefix not in MAP_PREFIXES:
            raise RuleSyntaxError(
                f"unknown mapping rule prefix {self.prefix!r}; expected LDAP or LDAPU1"
            )

    def render(self, *, include_prefix: bool = True) -> str:
        return f"{self.prefix}:{self.template}" if include_prefix else self.template

    def __str__(self) -> str:  # pragma: no cover - convenience
        return self.render()

    @property
    def template_names(self) -> list[str]:
        """Names of every ``{...}`` placeholder used, in order."""
        return [m.group(1) for m in _TEMPLATE_RE.finditer(self.template)]

    @property
    def requires_ldapu1(self) -> bool:
        return any(name in LDAPU1_TEMPLATES for name in self.template_names)

    def validate(self) -> list[str]:
        """Return a list of problems; empty means the rule looks sane."""
        problems: list[str] = []
        filter_text = self.template.strip()
        if not (filter_text.startswith("(") and filter_text.endswith(")")):
            problems.append(
                "mapping rule should be a complete LDAP filter starting with '(' "
                "and ending with ')'"
            )
        if filter_text.count("(") != filter_text.count(")"):
            problems.append("unbalanced parentheses in the LDAP filter")
        for name in self.template_names:
            if name not in LDAP_TEMPLATES and name not in LDAPU1_TEMPLATES:
                problems.append(f"unknown template {{{name}}}")
        if self.requires_ldapu1 and self.prefix != "LDAPU1":
            used = sorted(set(self.template_names) & LDAPU1_TEMPLATES)
            problems.append(
                "templates "
                + ", ".join("{" + u + "}" for u in used)
                + " require the LDAPU1: prefix"
            )
        return problems

    @classmethod
    def parse(cls, text: str) -> "MapRule":
        text = text.strip()
        prefix = "LDAP"
        for candidate in sorted(MAP_PREFIXES, key=len, reverse=True):
            if text.upper().startswith(candidate + ":"):
                prefix = candidate
                text = text[len(candidate) + 1 :]
                break
        return cls(text.strip(), prefix)


def ldap_filter_escape(value: str) -> str:
    """Escape a literal for use inside an LDAP filter (RFC 4515)."""
    out = []
    for ch in value:
        if ch in "\\*()":
            out.append("\\%02x" % ord(ch))
        elif ch == "\0":
            out.append("\\00")
        else:
            out.append(ch)
    return "".join(out)
