"""Command line interface.

Command groups follow the workflow rather than the code layout::

    cert     inspect a certificate and derive a configuration from it
    card     find readers, tokens and the certificates on them
    profile  manage SmartCardProfile files
    mapping  test a profile against a real certificate
    domain   check that identity lookup through the trust works at all
    ca       inspect and build the CA trust bundle
    config   render, diff, validate and apply
    doctor   everything at once
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .certmap.compat import DEFAULT_VERSION, Version, detect_sssd
from .certmap.evaluator import evaluate
from .certmap.mappings import build_rule, get_mechanism, mechanisms
from .certmap.renderer import render
from .errors import SmartCardError
from .model.profile import SmartCardProfile
from .model.store import (
    dump_profile,
    find_profile,
    list_profiles,
    load_profile_file,
    profile_dirs,
    save_profile,
)
from .report import Printer
from .util import Check
from .x509.inspect import CertificateInfo, load_certificate, load_certificate_file
from .x509.recommend import build_profile, recommend

EPILOG = """\
examples:
  sssd-smartcard cert inspect --from-card
  sssd-smartcard cert autoconfig --file user.pem --save-profile ~/AD-PIV-UPN.yaml
  sssd-smartcard mapping test AD-PIV-UPN --from-card
  sssd-smartcard config diff AD-PIV-UPN
  sssd-smartcard config apply AD-PIV-UPN --dry-run
  sssd-smartcard doctor --user jan.kowalski@domain-a.local
"""


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def target_version(args) -> Version:
    """Which SSSD the output should target."""
    if getattr(args, "sssd_version", None):
        return Version.parse(args.sssd_version)
    detected = detect_sssd()
    return detected.effective_version


def add_cert_source(parser: argparse.ArgumentParser, *, required: bool = True) -> None:
    group = parser.add_argument_group("certificate source")
    source = group.add_mutually_exclusive_group(required=required)
    source.add_argument("--file", "-f", metavar="PATH", help="PEM or DER certificate file")
    source.add_argument(
        "--base64", metavar="B64", help="base64 DER, as produced by openssl x509 -outform der"
    )
    source.add_argument(
        "--from-card", action="store_true", help="read the certificate off a Smart Card"
    )
    source.add_argument("--stdin", action="store_true", help="read the certificate from stdin")
    group.add_argument("--module", help="PKCS#11 module to use with --from-card")
    group.add_argument("--slot", help="PKCS#11 slot id to use with --from-card")
    group.add_argument("--cert-id", help="PKCS#11 certificate object id to read")


def resolve_certificate(args, printer: Printer) -> CertificateInfo:
    """Load the certificate the user pointed at."""
    if getattr(args, "file", None):
        return load_certificate_file(args.file)
    if getattr(args, "base64", None):
        return load_certificate(args.base64.encode(), source="<--base64>")
    if getattr(args, "stdin", False):
        return load_certificate(sys.stdin.buffer.read(), source="<stdin>")

    from .pkcs11.detect import pick_authentication_certificate, read_certificate, scan

    if getattr(args, "cert_id", None):
        from .pkcs11.detect import pick_module

        module = pick_module(getattr(args, "module", None))
        return read_certificate(module, args.cert_id, slot=getattr(args, "slot", None))

    result = scan(module=getattr(args, "module", None), slot=getattr(args, "slot", None))
    chosen = pick_authentication_certificate(result)
    if chosen is None or chosen.certificate is None:
        raise SmartCardError(
            "no readable certificate found on the card. Run `sssd-smartcard card detect` "
            "to see what the reader reports."
        )
    if len(result.certificates) > 1:
        printer.note(
            f"the card holds {len(result.certificates)} certificates; using "
            f"{chosen.label or chosen.object_id!r} because it looks like the "
            "authentication certificate. Use --cert-id to pick another."
        )
    return chosen.certificate


def emit_json(payload) -> int:
    json.dump(payload, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    return 0


# ---------------------------------------------------------------------------
# cert
# ---------------------------------------------------------------------------


def print_certificate(printer: Printer, cert: CertificateInfo) -> None:
    printer.heading("Certificate")
    printer.kv("Source", cert.source)
    printer.kv("Subject", cert.subject_dn)
    printer.kv("Issuer", cert.issuer_dn)
    printer.kv("Serial Number", f"{cert.serial_hex(colon=True, upper=True)}  ({cert.serial_int})")
    printer.kv("Valid from", f"{cert.not_before:%Y-%m-%d %H:%M UTC}")
    printer.kv(
        "Valid to",
        f"{cert.not_after:%Y-%m-%d %H:%M UTC}"
        + (
            "  [EXPIRED]"
            if cert.expired
            else f"  ({cert.days_remaining} days left)"
        ),
    )
    printer.kv("Public key", cert.public_key_algorithm)
    printer.kv("Signature", cert.signature_algorithm)
    printer.kv("SHA-256", cert.fingerprint("sha256"))
    if cert.subject_key_id:
        printer.kv("SKI", cert.subject_key_id.hex().upper())
    if cert.authority_key_id:
        printer.kv("AKI", cert.authority_key_id.hex().upper())
    bc = cert.basic_constraints
    if bc:
        printer.kv(
            "Basic Constraints",
            f"CA:{'TRUE' if bc[0] else 'FALSE'}"
            + (f", pathlen:{bc[1]}" if bc[1] is not None else ""),
        )
    printer.kv("Key Usage", ", ".join(cert.key_usage) or None)
    printer.kv("Extended Key Usage", cert.eku_labels or None)

    san = cert.san
    printer.heading("Subject Alternative Name")
    if san.empty:
        printer.write("  (none)")
    else:
        printer.kv("UPN (otherName)", san.upn or None)
        printer.kv("PKINIT principal", san.pkinit or None)
        printer.kv("RFC822 / e-mail", san.rfc822 or None)
        printer.kv("DNS", san.dns or None)
        printer.kv("URI", san.uri or None)
        printer.kv("IP address", san.ip or None)
        printer.kv("directoryName", san.directory_name or None)
        printer.kv("registeredID", san.registered_id or None)
        for oid, value in san.other_name:
            printer.kv(f"otherName {oid}", value)

    if cert.sid or cert.crl_urls or cert.ocsp_urls or cert.ca_issuer_urls:
        printer.heading("PKI metadata")
        printer.kv("AD SID extension", cert.sid)
        printer.kv("OCSP responder", cert.ocsp_urls or None)
        printer.kv("CRL distribution", cert.crl_urls or None)
        printer.kv("CA issuers", cert.ca_issuer_urls or None)


def print_recommendation(printer: Printer, rec, version: Version) -> None:
    printer.heading("Analysis")
    for observation in rec.observations:
        if observation.level == "error":
            printer.warn(observation.text)
        elif observation.level == "warn":
            printer.warn(observation.text)
        else:
            printer.note(observation.text)
        if observation.hint:
            printer.write(f"      {printer.dim(observation.hint)}")

    printer.heading("Recommended mapping")
    printer.kv("Target SSSD", str(version))
    printer.kv("Domain", f"{rec.domain or '(unknown)'}  ({rec.domain_reason})")
    best = rec.best
    if best is None:
        printer.warn("no mapping mechanism fits this certificate")
        return
    printer.kv("Mechanism", f"{best.key}  -- {best.mechanism.title}")
    printer.kv(
        "Confidence",
        f"{best.score}/100"
        + (
            f"  ({best.intrinsic_score} minus {best.penalty} because it needs "
            "provisioning on the user object)"
            if best.penalty
            else ""
        ),
    )
    printer.kv("Why", best.reason)
    printer.kv("Resolves to", best.identity)
    if best.mechanism.needs_directory_setup:
        printer.warn(
            "this mechanism needs the value above written onto the user object in the "
            "directory before it can resolve anybody"
        )

    printer.heading("Alternatives")
    for candidate in rec.alternatives:
        marker = "x" if candidate.blocked else "-"
        suffix = (
            f"  [-{candidate.penalty}: needs provisioning]" if candidate.penalty else ""
        )
        printer.write(
            f"  {marker} {candidate.score:3d}  {candidate.key:22s} "
            f"{candidate.reason}{suffix}"
        )
        if candidate.blocked:
            printer.write(f"        {printer.dim(candidate.blocked)}")


def detect_joined_domain(config_path: str) -> str | None:
    """The SSSD domain this host is joined to, if sssd.conf can be read.

    This is what decides whether the generated rule needs ``domains=``: the
    certmap section belongs to the joined domain, while the accounts may live in
    a trusted one.
    """
    from .sssdconf.conf import SssdConfig

    try:
        configured = SssdConfig.load(config_path).domains()
    except SmartCardError:
        return None
    return configured[0] if configured else None


def known_sssd_domains(config_path: str) -> list[str]:
    """Every domain SSSD knows: configured in sssd.conf plus discovered trusts."""
    from .sssdconf.conf import SssdConfig
    from .util import is_linux

    names: list[str] = []
    try:
        names.extend(SssdConfig.load(config_path).domains())
    except SmartCardError:
        pass
    if is_linux():
        from .sssdconf.runtime import domain_list

        discovered, _ = domain_list()
        for name in discovered:
            if name.lower() not in {n.lower() for n in names}:
                names.append(name)
    return names


def check_account_domain(
    account_domain: str | None, section_domain: str | None, config_path: str
) -> str | None:
    """Warn when the certificate's domain is not a domain SSSD can search.

    A certificate whose UPN suffix differs from the joined domain usually means
    one of two very different things:

    * the accounts really live in a trusted domain, which is what ``domains=``
      is for; or
    * Active Directory has an **alternative UPN suffix** -- the same domain, with
      users logging in as ``user@example.com`` while the domain is
      ``ad.example.com``.

    The second case is not a trusted domain, and emitting ``domains=`` for it
    points SSSD at something it has never heard of, so every lookup fails. We
    cannot tell the two apart from the certificate alone, but we can check the
    inferred domain against the domains SSSD actually knows.
    """
    if not account_domain or not section_domain:
        return None
    if account_domain.lower() == section_domain.lower():
        return None
    known = {n.lower() for n in known_sssd_domains(config_path)}
    if not known or account_domain.lower() in known:
        return None
    return (
        f"{account_domain} is not a domain SSSD knows (it has "
        + ", ".join(sorted(known))
        + f"), so it is being treated as an alternative UPN suffix of "
        f"{section_domain} rather than a trusted domain: no domains= line, and "
        "any UPN suffix accepted. A domains= line would name a domain SSSD "
        "cannot search, and pinning this one suffix would reject cards issued "
        f"under any other. If {account_domain} really is a separate trusted "
        "domain, set mapping.domains in the profile."
    )


def cmd_cert_inspect(args, printer: Printer) -> int:
    cert = resolve_certificate(args, printer)
    version = target_version(args)
    rec = recommend(
        cert, domain=args.domain, provider=args.provider, version=version
    )

    section_domain = args.sssd_domain or detect_joined_domain(args.config)
    trust_note = None
    unknown_domain_warning = check_account_domain(
        rec.domain, section_domain, args.config
    )
    if section_domain and rec.domain and section_domain.lower() != rec.domain.lower():
        # Only claim domains= when domains= is what gets generated. The
        # alternative-suffix case has its own message from
        # check_account_domain, and two explanations of one decision is one
        # too many.
        if not unknown_domain_warning:
            trust_note = (
                f"this host is joined to {section_domain} while the certificate "
                f"points at {rec.domain}, which SSSD knows as a domain: the rule "
                f"is attached to {section_domain} and directed at {rec.domain} "
                "through domains=."
            )

    # The name inside the profile becomes the [certmap/<domain>/<name>] section,
    # while the file name is what `profile show` and `mapping test` are given. If
    # they disagree the operator ends up looking for a section that is not there,
    # so derive the name from the file stem unless one was asked for explicitly.
    profile_name = args.profile_name
    if not profile_name and args.save_profile:
        stem = Path(args.save_profile).stem
        if stem and not any(c in stem for c in "/[] \t"):
            profile_name = stem

    profile = None
    rendered = None
    if not args.no_config:
        try:
            profile = build_profile(
                rec,
                name=profile_name,
                mechanism_key=args.mapping,
                pin_issuer=not args.no_pin_issuer,
                pin_eku=not args.no_pin_eku,
                with_revocation=args.with_revocation,
                require_smartcard=args.require_smartcard,
                ca_bundle=args.ca_bundle,
                section_domain=section_domain,
                # So the generator can tell a trusted domain from an
                # alternative UPN suffix, instead of assuming the first.
                sssd_domains=known_sssd_domains(args.config),
            )
            rendered = render(profile, version=version, allow_degraded=True)
        except SmartCardError as exc:
            if args.json:
                raise
            printer.warn(f"could not generate a profile: {exc}")

    if args.json:
        payload = rec.to_dict()
        if profile is not None:
            payload["generated_profile"] = profile.to_dict()
        if rendered is not None:
            payload["generated_config"] = rendered.to_dict()
        if unknown_domain_warning:
            payload["account_domain_warning"] = unknown_domain_warning
        return emit_json(payload)

    print_certificate(printer, cert)
    print_recommendation(printer, rec, version)
    if trust_note:
        printer.note(trust_note)
    if unknown_domain_warning:
        printer.warn(unknown_domain_warning)

    if profile is not None and rendered is not None:
        printer.heading(f"Generated profile: {profile.name}")
        printer.block(dump_profile(profile))
        printer.heading("Generated sssd.conf")
        printer.block(rendered.to_ini())
        if rendered.notes:
            printer.heading("Notes")
            for note in rendered.notes:
                printer.note(note)
        if rendered.warnings:
            printer.heading("Warnings")
            for warning in rendered.warnings:
                printer.warn(warning)
        if rendered.manual_steps:
            printer.heading("Manual steps")
            for step in rendered.manual_steps:
                printer.bullet(step.title)
                if step.command:
                    printer.write(f"      $ {step.command}")
                if step.detail:
                    printer.write(f"      {printer.dim(step.detail)}")

        if args.save_profile:
            path = save_profile(profile, args.save_profile)
            printer.write()
            printer.write(f"Profile written to {path}")
            printer.write(
                printer.dim(
                    f"Next: sssd-smartcard mapping test {path} --file <cert>  then  "
                    f"sssd-smartcard config apply {path} --dry-run"
                )
            )

    return 1 if rec.blocking else 0


# ---------------------------------------------------------------------------
# card
# ---------------------------------------------------------------------------


def cmd_card_detect(args, printer: Printer) -> int:
    from .pkcs11.detect import pick_authentication_certificate, scan

    result = scan(module=args.module, slot=args.slot, read_certs=not args.no_read)
    if args.json:
        return emit_json(result.to_dict())

    printer.heading("Smart Card")
    for check in result.checks:
        printer.status(check)

    if result.readers:
        printer.heading("Readers")
        for reader in result.readers:
            printer.write(f"  {reader.name}")
    if result.slots:
        printer.heading("Tokens")
        for slot in result.slots:
            printer.kv("Slot", slot.slot_id or slot.slot_description)
            printer.kv("Token", slot.token_label, indent="    ")
            printer.kv("Manufacturer", slot.manufacturer, indent="    ")
            printer.kv("Model", slot.model, indent="    ")
            printer.kv("Serial", slot.serial, indent="    ")
            printer.kv("URI", slot.uri, indent="    ")

    chosen = pick_authentication_certificate(result)
    if result.certificates:
        printer.heading("Certificates on the card")
        for entry in result.certificates:
            marker = "*" if entry is chosen else " "
            printer.write(
                f" {marker} id={entry.object_id or '?':<8} label={entry.label or '(none)'}"
            )
            if entry.error:
                printer.write(f"      {printer.dim(entry.error)}")
            elif entry.certificate:
                cert = entry.certificate
                printer.kv("Subject", cert.subject_dn, indent="      ")
                printer.kv("Issuer", cert.issuer_dn, indent="      ")
                printer.kv("Serial", cert.serial_hex(colon=True, upper=True), indent="      ")
                printer.kv("UPN", cert.san.upn or None, indent="      ")
                printer.kv("EKU", cert.eku_labels or None, indent="      ")
                printer.kv(
                    "Validity",
                    f"{cert.not_before:%Y-%m-%d} .. {cert.not_after:%Y-%m-%d}"
                    + (" [EXPIRED]" if cert.expired else ""),
                    indent="      ",
                )
        if chosen:
            printer.write()
            printer.write(
                printer.dim(
                    "* the certificate `cert inspect --from-card` would use. "
                    "The private key is never read."
                )
            )
    return 0 if not any(c.failed for c in result.checks) else 1


# ---------------------------------------------------------------------------
# profile
# ---------------------------------------------------------------------------


def cmd_profile_list(args, printer: Printer) -> int:
    entries = list_profiles()
    if args.json:
        return emit_json(
            [
                {
                    "path": str(path),
                    "name": profile.name if profile else None,
                    "domain": profile.domain if profile else None,
                    "mapping": profile.mapping.type if profile else None,
                    "error": error,
                }
                for path, profile, error in entries
            ]
        )
    if not entries:
        printer.write("No profiles found. Searched:")
        for directory in profile_dirs():
            printer.write(f"  {directory}")
        printer.write()
        printer.write(
            printer.dim("Create one from a real card: sssd-smartcard cert autoconfig "
                        "--from-card --save-profile <path>")
        )
        return 0
    printer.heading("Profiles")
    for path, profile, error in entries:
        if error:
            printer.status(Check(path.name, "FAIL", error))
            continue
        printer.write(
            f"  {profile.name:24s} {profile.mapping.type:22s} {profile.domain}"
        )
        printer.write(f"  {'':24s} {printer.dim(str(path))}")
    return 0


def cmd_profile_show(args, printer: Printer) -> int:
    profile = find_profile(args.name)
    version = target_version(args)
    rule = build_rule(profile, version=version)
    if args.json:
        return emit_json(
            {
                "profile": profile.to_dict(),
                "certmap_section": profile.section,
                "matchrule": rule.matchrule.render() or None,
                "maprule": rule.maprule.render(),
                "domains": rule.domains,
            }
        )
    printer.heading(f"Profile: {profile.name}")
    printer.kv("Source", profile.source_path)
    printer.kv("Description", profile.description)
    printer.kv("SSSD domain", profile.domain)
    printer.kv("Provider", profile.provider)
    mechanism = get_mechanism(profile.mapping.type)
    printer.kv("Mapping", f"{mechanism.key} -- {mechanism.title}")
    if profile.mapping.options:
        printer.kv("Options", [f"{k} = {v}" for k, v in profile.mapping.options.items()])
    printer.kv("Search domains", ", ".join(rule.domains))
    printer.kv("Auth mode", profile.authentication.mode)
    printer.kv(
        "Revocation",
        f"{profile.revocation.method} (fail {profile.revocation.fail_mode})"
        if profile.revocation.enabled
        else "disabled",
    )
    printer.kv("CA bundle", profile.ca_trust.bundle_path)

    printer.heading("Rendered rule")
    printer.write(f"  [{profile.section}]")
    if rule.matchrule.render():
        printer.write(f"  matchrule = {rule.matchrule.render()}")
    printer.write(f"  maprule   = {rule.maprule.render()}")
    for note in rule.notes:
        printer.note(note)
    for warning in rule.warnings:
        printer.warn(warning)
    if profile.metadata:
        printer.heading("Metadata")
        for key, value in profile.metadata.items():
            printer.kv(key, value)
    return 0


def cmd_profile_validate(args, printer: Printer) -> int:
    targets = args.name or [str(p) for p, _, _ in list_profiles()]
    if not targets:
        printer.write("No profiles to validate.")
        return 0
    version = target_version(args)
    failures = 0
    results = []
    for target in targets:
        try:
            profile = (
                load_profile_file(target) if Path(target).exists() else find_profile(target)
            )
            rendered = render(profile, version=version, allow_degraded=True)
            checks = [Check(profile.name, "PASS", f"renders for SSSD {version}")]
            for warning in rendered.warnings:
                checks.append(Check(profile.name, "WARN", warning))
            results.append({"target": target, "ok": True, "warnings": rendered.warnings})
        except SmartCardError as exc:
            failures += 1
            checks = [Check(str(target), "FAIL", str(exc))]
            results.append({"target": target, "ok": False, "error": str(exc)})
        if not args.json:
            for check in checks:
                printer.status(check)
    if args.json:
        return emit_json(results)
    return 1 if failures else 0


# ---------------------------------------------------------------------------
# mapping
# ---------------------------------------------------------------------------


def cmd_mapping_types(args, printer: Printer) -> int:
    version = target_version(args)
    if args.json:
        return emit_json(
            [
                {
                    "key": m.key,
                    "aliases": list(m.aliases),
                    "title": m.title,
                    "summary": m.summary,
                    "requires": list(m.requires),
                    "options": m.options,
                    "needs_directory_setup": m.needs_directory_setup,
                }
                for m in mechanisms()
            ]
        )
    printer.heading("Mapping mechanisms")
    for mechanism in mechanisms():
        printer.write(f"  {printer.bold(mechanism.key)}  {mechanism.title}")
        printer.bullet(mechanism.summary, marker=" ", indent="    ")
        if mechanism.requires:
            from .certmap.compat import feature

            for key in mechanism.requires:
                feat = feature(key)
                printer.write(
                    f"      {printer.dim(f'requires SSSD >= {feat.since} ({feat.description})')}"
                )
        if mechanism.needs_directory_setup:
            printer.write(
                f"      {printer.dim('requires data to be written on the user object')}"
            )
        for name, doc in mechanism.options.items():
            printer.write(f"      {printer.dim(f'option {name}: {doc}')}")
        printer.write()
    return 0


def cmd_mapping_test(args, printer: Printer) -> int:
    profile = find_profile(args.profile)
    cert = resolve_certificate(args, printer)
    version = target_version(args)
    rule = build_rule(profile, version=version, cert=cert)
    result = evaluate(cert, rule.matchrule, rule.maprule, use_sssctl=not args.no_sssctl)

    lookup = None
    identity = None
    mechanism = get_mechanism(profile.mapping.type)
    identity = mechanism.expected_identity(cert)
    from .util import is_linux

    if (
        result.matched
        and identity
        and not args.no_lookup
        and "@" in str(identity)
        and is_linux()
    ):
        from .sssdconf.runtime import lookup_user

        lookup = lookup_user(str(identity))

    if args.json:
        return emit_json(
            {
                "profile": profile.name,
                "certificate": cert.to_dict(),
                "matchrule": rule.matchrule.render() or None,
                "maprule": rule.maprule.render(),
                "evaluation": result.to_dict(),
                "mapped_identity": identity,
                "lookup": lookup.to_dict() if lookup else None,
            }
        )

    printer.heading("Mapping test")
    printer.kv("Certificate", cert.subject_dn)
    printer.kv("Issuer", cert.issuer_dn)
    printer.kv("SAN UPN", cert.san.upn or None)
    printer.kv("Profile", f"{profile.name} ({profile.mapping.type})")

    printer.heading("Matching rule")
    printer.write(f"  {rule.matchrule.render() or '(none -- SSSD default applies)'}")
    for group_index, group in enumerate(result.match.groups):
        if len(result.match.groups) > 1:
            printer.write(f"  alternative {group_index + 1}:")
        for term in group:
            printer.status(
                Check(
                    term.term.render(),
                    "PASS" if term.matched else "FAIL",
                    term.detail or (", ".join(term.observed[:3]) if term.observed else ""),
                ),
                indent="  ",
            )

    printer.heading("Verdict")
    printer.verdict(result.matched, "MATCH", "NO MATCH")
    printer.kv("Decided by", result.authority)
    if result.sssctl.available:
        printer.kv("sssctl", result.sssctl.command and " ".join(result.sssctl.command[:2]))
    else:
        printer.note(
            f"sssctl cert-eval-rule not used ({result.sssctl.error}); the local engine "
            "decided this. Confirm on the SSSD host before relying on it."
        )
    if result.disagreement:
        printer.warn(result.disagreement)

    printer.heading("Mapping rule")
    printer.write(f"  {rule.maprule.render()}")
    printer.heading("Calculated identity")
    if result.mapping.missing:
        printer.warn(
            "the certificate has no value for: " + ", ".join(result.mapping.missing)
        )
        printer.note("SSSD cannot build a search filter, so this rule can never resolve a user.")
    for placeholder, value in result.mapping.values.items():
        printer.kv(placeholder, value if len(value) < 200 else value[:197] + "...")
    printer.kv("LDAP filter", result.mapping.filter if len(result.mapping.filter) < 400 else result.mapping.filter[:397] + "...")
    if identity:
        printer.kv("Mapped identity", identity)

    if lookup is not None:
        printer.heading("SSSD identity lookup")
        for check in lookup.checks:
            printer.status(check)
        if lookup.resolved:
            printer.kv("UID", lookup.uid)
            printer.kv("Groups", lookup.groups or None)
        else:
            printer.warn(
                "Identity lookup through the trusted domain failed.\n"
                "Fix AD/SSSD/trust configuration before enabling Smart Card authentication."
            )
    elif not args.no_lookup and result.matched:
        printer.heading("SSSD identity lookup")
        printer.note(
            "skipped: not running on the SSSD host, or no user-like identity to resolve. "
            "Re-run this on the domain member to verify the lookup through the trust."
        )

    ok = result.matched and result.mapping.complete
    if lookup is not None:
        ok = ok and lookup.resolved
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# domain
# ---------------------------------------------------------------------------


def cmd_domain_test(args, printer: Printer) -> int:
    from .sssdconf.runtime import lookup_user, trust_report

    report = trust_report(args.config)
    lookup = lookup_user(args.user) if args.user else None

    if args.json:
        return emit_json(
            {"trust": report.to_dict(), "lookup": lookup.to_dict() if lookup else None}
        )

    printer.heading("SSSD domains")
    primary = [d for d in report.domains if d.configured]
    trusted = [d for d in report.domains if d.trusted]
    printer.kv("Primary domain", [d.name for d in primary] or report.primary or None)
    printer.kv("Trusted domains", [d.name for d in trusted] or "(none discovered)")
    for domain in report.domains:
        if domain.online is None:
            continue
        printer.kv(
            f"{domain.name} status",
            "ONLINE" if domain.online else "OFFLINE",
        )

    printer.heading("Checks")
    for check in report.checks:
        printer.status(check)

    if args.domain:
        match = report.find(args.domain)
        if match is None:
            printer.write()
            printer.status(
                Check(
                    f"domain {args.domain}",
                    "FAIL",
                    "SSSD does not know this domain",
                    hint="If the accounts live there, the trust is not working. "
                    "Smart Card authentication cannot succeed until it is.",
                )
            )
            return 1
        printer.status(
            Check(
                f"domain {args.domain}",
                "PASS" if match.online is not False else "FAIL",
                "online" if match.online else ("offline" if match.online is False else "known"),
            )
        )

    if lookup is not None:
        printer.heading(f"User lookup: {args.user}")
        for check in lookup.checks:
            printer.status(check)
        if lookup.resolved:
            printer.kv("UID", lookup.uid)
            printer.kv("Groups", lookup.groups or None)
            printer.kv("Domain", lookup.domain)
        else:
            printer.write()
            printer.warn(
                "Identity lookup through the trusted domain failed.\n"
                "Fix AD/SSSD/trust configuration before enabling Smart Card authentication."
            )
            return 1
    return 0 if report.available else 1


# ---------------------------------------------------------------------------
# ca
# ---------------------------------------------------------------------------


def cmd_ca_show(args, printer: Printer) -> int:
    from .ca.trust import load_bundle, load_ca_files

    entries = load_ca_files(args.file) if args.file else load_bundle(args.bundle)
    if args.json:
        return emit_json([e.to_dict() for e in entries])
    if not entries:
        printer.write(f"No certificates in {args.bundle}")
        return 1
    for entry in entries:
        printer.heading(f"{entry.role}: {entry.cert.common_name or entry.cert.subject_dn}")
        printer.kv("Subject", entry.cert.subject_dn)
        printer.kv("Issuer", entry.cert.issuer_dn)
        printer.kv("Serial Number", entry.cert.serial_hex(colon=True, upper=True))
        printer.kv("SHA-256", entry.fingerprint)
        printer.kv(
            "Validity",
            f"{entry.cert.not_before:%Y-%m-%d} .. {entry.cert.not_after:%Y-%m-%d}"
            + (" [EXPIRED]" if entry.cert.expired else f" ({entry.cert.days_remaining}d left)"),
        )
        bc = entry.cert.basic_constraints
        printer.kv(
            "Basic Constraints",
            f"CA:{'TRUE' if bc[0] else 'FALSE'}"
            + (f", pathlen:{bc[1]}" if bc and bc[1] is not None else "")
            if bc
            else "(absent)",
        )
        printer.kv("Source", entry.cert.source)
        for problem in entry.problems:
            printer.warn(problem)
    return 0


def cmd_ca_import(args, printer: Printer) -> int:
    from .backup import new_backup_set
    from .ca.trust import apply_bundle, plan_bundle

    plan = plan_bundle(args.file, args.bundle)
    if args.json:
        return emit_json(plan.to_dict())

    printer.heading(f"CA trust bundle: {plan.path}")
    printer.kv("Already present", len(plan.existing))
    printer.kv("To add", len(plan.added))
    printer.kv("Skipped (duplicate)", len(plan.skipped))
    for entry in plan.added:
        printer.write(f"  + [{entry.role}] {entry.cert.subject_dn}")
        printer.write(f"        {printer.dim('SHA-256 ' + entry.fingerprint)}")
    for entry in plan.skipped:
        printer.write(f"  = {entry.cert.subject_dn} (already in the bundle)")
    for warning in plan.warnings:
        printer.warn(warning)

    if args.dry_run:
        printer.write()
        printer.write(printer.dim("dry run: nothing was written"))
        return 0
    if not plan.changed:
        printer.write()
        printer.write("Bundle already contains everything; nothing to do.")
        return 0

    backups = new_backup_set(args.backup_dir)
    apply_bundle(plan, backups)
    printer.write()
    printer.write(f"Wrote {plan.path} ({len(plan.final)} certificates, mode 0644)")
    for entry in backups.entries:
        if entry.existed:
            printer.write(printer.dim(f"Backup: {entry.saved}"))
    return 0


def cmd_ca_crl_show(args, printer: Printer) -> int:
    from .ca.crl import DEFAULT_CRL_FILE, installed_crl_checks, load_crl_file

    target = args.file or DEFAULT_CRL_FILE
    try:
        crls = load_crl_file(target)
    except Exception as exc:
        printer.write(str(exc))
        return 1
    if args.json:
        return emit_json({"file": str(target), "crls": [c.to_dict() for c in crls]})

    printer.heading(f"CRL file: {target}")
    for crl in crls:
        printer.write(f"  {crl.issuer}")
        printer.kv("    This update", f"{crl.last_update:%Y-%m-%d %H:%M} UTC")
        if crl.next_update:
            days = f" ({crl.days_left:.1f} days)" if crl.days_left is not None else ""
            printer.kv("    Next update", f"{crl.next_update:%Y-%m-%d %H:%M} UTC{days}")
        else:
            printer.kv("    Next update", "not set")
        printer.kv("    Revoked", crl.revoked_count)

    printer.heading("Checks")
    checks = installed_crl_checks(target, ca_bundle=args.bundle)
    for check in checks:
        printer.status(check)
    return 1 if any(c.failed for c in checks) else 0


def cmd_ca_crl_update(args, printer: Printer) -> int:
    """Fetch one CRL per CA in the bundle, combine them and install."""
    from .backup import new_backup_set, write_atomic
    from .ca.crl import DEFAULT_CRL_FILE, build_crl_plan, crl_plan_checks

    # A CA advertises its CRL through the certificates it signed, never through
    # its own certificate, so an end-entity certificate is what makes the
    # issuing CA CRL discoverable at all.
    leaf_certs = []
    if args.file or args.base64 or args.from_card or args.stdin or args.cert_id:
        try:
            leaf_certs.append(resolve_certificate(args, printer))
        except SmartCardError as exc:
            printer.warn(f"could not read the certificate: {exc}")

    plan = build_crl_plan(
        ca_bundle=args.bundle,
        crl_file=args.crl_file or DEFAULT_CRL_FILE,
        local_files=args.from_file or None,
        leaf_certs=leaf_certs or None,
        fetch=not args.no_fetch,
    )
    checks = crl_plan_checks(plan)
    if args.json:
        data = plan.to_dict()
        data["checks"] = [
            {"name": c.name, "status": c.status, "detail": c.detail, "hint": c.hint}
            for c in checks
        ]
        return emit_json(data)

    printer.heading("CRL set")
    printer.kv("CAs in the bundle", len(plan.cas))
    printer.kv("CRLs collected", len(plan.crls))
    printer.kv("Target", plan.crl_file)
    for crl in plan.crls:
        printer.write(f"  + {crl.issuer}")
        when = (
            f"        next update {crl.next_update:%Y-%m-%d}"
            if crl.next_update
            else "        no nextUpdate"
        )
        printer.write(printer.dim(when))

    printer.heading("Checks")
    for check in checks:
        printer.status(check)

    if not plan.complete:
        printer.write()
        printer.verdict(
            False,
            "",
            "incomplete CRL set -- refusing to install, because SSSD would then "
            "reject every card",
        )
        return 1
    if plan.expired:
        printer.warn(
            "at least one CRL is expired; installing it stops all card logins "
            "unless revocation.fail_mode is open, which emits soft_crl."
        )
        if not args.force:
            printer.write("Re-run with --force to install anyway.")
            return 1

    if args.dry_run:
        printer.write()
        printer.write(printer.dim(f"dry run: {len(plan.content)} bytes not written"))
        return 0

    backups = new_backup_set(args.backup_dir)
    backups.add(plan.crl_file)
    # A PEM CRL is ASCII text; write_atomic normalises line endings.
    write_atomic(plan.crl_file, plan.content.decode("ascii"), mode=0o644)
    # Record where each CRL came from, so the timer -- which runs with no card
    # inserted -- can refresh without rediscovering the URLs.
    if plan.sources:
        from .ca.crl import save_sources

        save_sources(plan.sources)
    printer.write()
    printer.write(f"Wrote {plan.crl_file} ({len(plan.crls)} CRLs, mode 0644)")
    for entry in backups.entries:
        if entry.existed:
            printer.write(printer.dim(f"Backup: {entry.saved}"))
    soonest = plan.soonest_expiry
    if soonest and soonest.next_update:
        printer.write(
            printer.dim(
                f"Refresh before {soonest.next_update:%Y-%m-%d %H:%M} UTC -- after "
                "that, card logins fail unless soft_crl is set."
            )
        )
    printer.write()
    printer.write("Keep it fresh with a timer:")
    printer.write("    sssd-smartcard ca crl timer --install")
    return 0


def cmd_ca_crl_timer(args, printer: Printer) -> int:
    """Show or install a systemd timer that refreshes the CRL."""
    from .ca.crl import DEFAULT_CRL_FILE, timer_units

    crl_file = args.crl_file or DEFAULT_CRL_FILE
    units = timer_units(
        bundle=args.bundle, crl_file=crl_file, on_calendar=args.on_calendar
    )
    if args.json:
        return emit_json(units)

    if not args.install:
        printer.heading("systemd units for CRL refresh")
        for name, text in units.items():
            printer.write(f"--- /etc/systemd/system/{name} ---")
            printer.write(text)
        printer.write(printer.dim("Re-run with --install to write and enable these."))
        return 0

    from .backup import new_backup_set, write_atomic
    from .util import run

    backups = new_backup_set(args.backup_dir)
    for name, text in units.items():
        path = f"/etc/systemd/system/{name}"
        backups.add(path)
        write_atomic(path, text, mode=0o644)
        printer.write(f"Wrote {path}")
    run(["systemctl", "daemon-reload"], timeout=60)
    timer = [n for n in units if n.endswith(".timer")][0]
    result = run(["systemctl", "enable", "--now", timer], timeout=60)
    printer.write()
    if not result.ok:
        printer.verdict(False, "", f"could not enable {timer}: {result.output}")
        return 1
    printer.verdict(True, f"{timer} is enabled and running", "")
    printer.write(printer.dim(f"Check it with: systemctl list-timers {timer}"))
    return 0


def cmd_ca_discover(args, printer: Printer) -> int:
    """Follow a certificate's own pointers, fetch the PKI, report what works."""
    from .backup import new_backup_set, write_atomic
    from .ca.discover import discover, discovery_checks

    # With only a PKI address and no certificate, read the directory and report
    # what it publishes. This is the first-contact case: a PKI nobody has a
    # card from yet.
    have_cert = bool(
        args.file or args.base64 or args.from_card or args.stdin or args.cert_id
    )
    if args.pki_url and not have_cert:
        from .ca.discover import browse_pki, listing_checks

        listing = browse_pki(args.pki_url, timeout=args.timeout)
        checks = listing_checks(listing)
        if args.json:
            data = listing.to_dict()
            data["checks"] = [
                {"name": c.name, "status": c.status, "detail": c.detail, "hint": c.hint}
                for c in checks
            ]
            return emit_json(data)

        printer.heading(f"PKI at {listing.base}")
        for url in listing.listed:
            printer.write(printer.dim(f"  {url}"))
        printer.heading("Checks")
        for check in checks:
            printer.status(check)

        if not args.install:
            printer.write()
            if listing.certificates:
                printer.write(printer.dim(
                    "Re-run with --install to import these CA certificates, or "
                    "with a certificate (--from-card) to have the chain and the "
                    "revocation configuration derived from it."
                ))
            return 1 if any(c.failed for c in checks) else 0

        if not listing.certificates:
            printer.verdict(False, "", "nothing to install")
            return 1
        printer.heading("Importing")
        for entry in listing.certificates:
            printer.write(f"  + {entry.subject_dn}")
            printer.write(printer.dim(f"        SHA-256 {entry.fingerprint()}"))
        printer.warn(
            "anything in this bundle can issue a certificate that logs in -- "
            "compare these fingerprints against the PKI before relying on them"
        )
        backups = new_backup_set(args.backup_dir)
        backups.add(args.bundle)
        write_atomic(
            args.bundle,
            "".join(c.pem for c in listing.certificates),
            mode=0o644,
        )
        printer.write()
        printer.write(
            f"Wrote {args.bundle} ({len(listing.certificates)} certificates, mode 0644)"
        )
        for entry in backups.entries:
            if entry.existed:
                printer.write(printer.dim(f"Backup: {entry.saved}"))
        printer.write(printer.dim(
            "CRLs still need a certificate to discover the issuing CA's own CRL "
            "URL: sssd-smartcard ca crl update --from-card"
        ))
        return 0

    cert = resolve_certificate(args, printer)
    report = discover(
        cert,
        pki_url=args.pki_url,
        probe_responders=not args.no_probe,
        timeout=args.timeout,
    )
    checks = discovery_checks(report)

    if args.json:
        data = report.to_dict()
        data["checks"] = [
            {"name": c.name, "status": c.status, "detail": c.detail, "hint": c.hint}
            for c in checks
        ]
        return emit_json(data)

    printer.heading("Certificate")
    printer.kv("Subject", cert.subject_dn)
    printer.kv("Issuer", cert.issuer_dn)

    printer.heading("Discovered")
    for note in report.notes:
        printer.write(printer.dim(f"  {note}"))

    printer.heading("Checks")
    for check in checks:
        printer.status(check)

    printer.heading("Configuration this implies")
    method = report.revocation_method
    printer.kv("revocation.method", method)
    if method == "crl":
        printer.kv("revocation.crl_file", "/etc/sssd/pki/revocation.crl.pem")
        printer.write(printer.dim("  certificate_verification = no_ocsp, crl_file=..."))
    elif method == "ocsp":
        printer.write(printer.dim("  certificate_verification = ocsp_dgst=sha256"))
    else:
        printer.write(printer.dim("  certificate_verification = no_ocsp"))
        printer.warn(
            "no revocation mechanism is available, so a revoked certificate still "
            "logs in. Stated plainly rather than left implied."
        )

    if not args.install:
        printer.write()
        printer.write(printer.dim("Nothing was written. Re-run with --install to:"))
        printer.write(printer.dim("  - import the fetched CA chain into the trust bundle"))
        if report.crl_urls:
            printer.write(printer.dim("  - fetch and install the CRLs"))
        return 0 if report.chain else 1

    if not report.chain:
        printer.verdict(False, "", "nothing to install: no CA certificate was fetched")
        return 1

    # Downloading a CA is not trusting it, so the fingerprints are shown again
    # at the point of import rather than buried in the report above.
    printer.heading("Importing")
    for entry in report.chain:
        printer.write(f"  + {entry.subject_dn}")
        printer.write(printer.dim(f"        SHA-256 {entry.fingerprint()}"))
    printer.warn(
        "anything in this bundle can issue a certificate that logs in -- compare "
        "these fingerprints against the PKI before relying on them"
    )

    backups = new_backup_set(args.backup_dir)
    backups.add(args.bundle)
    write_atomic(args.bundle, report.bundle_pem().decode("ascii"), mode=0o644)
    printer.write()
    printer.write(f"Wrote {args.bundle} ({len(report.chain)} certificates, mode 0644)")

    if report.crl_urls:
        from .ca.crl import DEFAULT_CRL_FILE, build_crl_plan, crl_plan_checks, save_sources

        plan = build_crl_plan(
            ca_bundle=args.bundle,
            crl_file=DEFAULT_CRL_FILE,
            leaf_certs=[cert],
        )
        printer.heading("CRLs")
        for check in crl_plan_checks(plan):
            printer.status(check)
        if plan.complete and not plan.expired:
            backups.add(plan.crl_file)
            write_atomic(plan.crl_file, plan.content.decode("ascii"), mode=0o644)
            if plan.sources:
                save_sources(plan.sources)
            printer.write(f"Wrote {plan.crl_file} ({len(plan.crls)} CRLs, mode 0644)")
            printer.write(printer.dim("Keep it fresh: sssd-smartcard ca crl timer --install"))
        else:
            printer.warn(
                "the CRL set is incomplete or expired, so it was not installed -- "
                "SSSD would reject every card. Run 'ca crl update --from-card' and "
                "read what it reports."
            )

    for entry in backups.entries:
        if entry.existed:
            printer.write(printer.dim(f"Backup: {entry.saved}"))
    return 0


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


def _plan_for(args, printer: Printer):
    from .sssdconf.apply import build_plan

    profile = find_profile(args.profile)
    return build_plan(
        profile,
        config_path=args.config,
        version=target_version(args),
        verification_scope=args.verification_scope,
        allow_degraded=args.allow_degraded,
        import_ca=not args.skip_ca,
    )


def cmd_config_render(args, printer: Printer) -> int:
    profile = find_profile(args.profile)
    version = target_version(args)
    rendered = render(
        profile,
        version=version,
        verification_scope=args.verification_scope,
        allow_degraded=args.allow_degraded,
    )
    if args.json:
        return emit_json(rendered.to_dict())
    printer.write(rendered.to_ini(with_comments=not args.no_comments))
    if rendered.notes:
        printer.heading("Notes")
        for note in rendered.notes:
            printer.note(note)
    if rendered.warnings:
        printer.heading("Warnings")
        for warning in rendered.warnings:
            printer.warn(warning)
    if rendered.manual_steps:
        printer.heading("Manual steps (not applied by this tool)")
        for step in rendered.manual_steps:
            printer.bullet(step.title)
            if step.command:
                printer.write(f"      $ {step.command}")
            if step.detail:
                printer.write(f"      {printer.dim(step.detail)}")
    return 0


def cmd_config_diff(args, printer: Printer) -> int:
    plan = _plan_for(args, printer)
    if args.json:
        return emit_json(plan.to_dict())
    printer.heading(f"{plan.config_path}")
    printer.diff(plan.diff)
    if plan.bundle and plan.bundle.changed:
        printer.heading(f"{plan.bundle.path}")
        for entry in plan.bundle.added:
            printer.write(f"  + [{entry.role}] {entry.cert.subject_dn}")
    printer.heading("Checks")
    for check in plan.checks:
        printer.status(check)
    for warning in plan.warnings + plan.rendered.warnings:
        printer.warn(warning)
    if plan.rendered.notes:
        printer.heading("Notes")
        for note in plan.rendered.notes:
            printer.note(note)
    if not plan.changed:
        printer.write()
        printer.write("Nothing to change: the configuration already matches the profile.")
    return 0


def cmd_config_validate(args, printer: Printer) -> int:
    from .sssdconf.runtime import config_check

    plan = _plan_for(args, printer)
    result = config_check(args.config)
    payload = {
        "plan": plan.to_dict(),
        "sssctl_config_check": {
            "available": result.found,
            "ok": result.ok,
            "output": result.output,
        },
    }
    if args.json:
        return emit_json(payload)
    printer.heading("Profile")
    for check in plan.checks:
        printer.status(check)
    for warning in plan.warnings + plan.rendered.warnings:
        printer.warn(warning)
    if plan.rendered.notes:
        printer.heading("Notes")
        for note in plan.rendered.notes:
            printer.note(note)
    printer.heading("sssctl config-check (current configuration on disk)")
    if not result.found:
        printer.status(Check("sssctl", "SKIP", "not installed"))
    else:
        printer.status(
            Check("sssctl config-check", "PASS" if result.ok else "FAIL", result.output)
        )
    return 1 if plan.blocking or (result.found and not result.ok) else 0


def cmd_config_apply(args, printer: Printer) -> int:
    from .sssdconf.apply import apply_plan

    plan = _plan_for(args, printer)
    dry_run = not args.yes if args.dry_run is None else args.dry_run

    if not args.json:
        printer.heading(f"Plan for profile {plan.profile.name}")
        printer.diff(plan.diff)
        if plan.bundle and plan.bundle.changed:
            printer.heading(f"CA bundle {plan.bundle.path}")
            for entry in plan.bundle.added:
                printer.write(f"  + [{entry.role}] {entry.cert.subject_dn}")
        printer.heading("Checks")
        for check in plan.checks:
            printer.status(check)
        for warning in plan.warnings + plan.rendered.warnings:
            printer.warn(warning)
        # The renderer's notes were reaching 'config render' and 'cert
        # autoconfig' but not this command -- the one an operator runs to change
        # the system.  Everything the renderer knows about an option it just
        # wrote (that SSSD never refreshes crl_file, that OCSP does not relax the
        # per-CA CRL rule) was therefore invisible exactly where it is acted on.
        if plan.rendered.notes:
            printer.heading("Notes")
            for note in plan.rendered.notes:
                printer.note(note)

    result = apply_plan(
        plan,
        dry_run=dry_run,
        restart=not args.no_restart,
        validate=not args.no_validate,
        backup_dir=args.backup_dir,
        force=args.force,
    )
    if args.json:
        return emit_json(result.to_dict())

    printer.heading("Result")
    for line in result.log:
        printer.write(f"  {line}")
    if dry_run:
        printer.write(printer.dim("  Re-run with --yes to write these changes."))
    if result.backups and result.backups.entries:
        printer.write()
        printer.write(printer.dim(f"  Backups: {result.backups.directory}"))
    if plan.rendered.manual_steps:
        printer.heading("Still to do by hand")
        for step in plan.rendered.manual_steps:
            printer.bullet(step.title)
            if step.command:
                printer.write(f"      $ {step.command}")
            if step.detail:
                printer.write(f"      {printer.dim(step.detail)}")
    return 0


# ---------------------------------------------------------------------------
# krb5
# ---------------------------------------------------------------------------


def cmd_krb5_status(args, printer: Printer) -> int:
    from .krb5.check import default_ccache_name, read_ccache

    cache = read_ccache(args.cache)
    if args.json:
        return emit_json(
            {"default_ccache_name": default_ccache_name(), **cache.to_dict()}
        )
    printer.heading("Kerberos credential cache")
    printer.kv("Expected location", default_ccache_name())
    if not cache.available:
        printer.warn(cache.error or "no credential cache in this shell")
        printer.note(
            "Run this inside the logged-in user's session -- a ticket obtained by "
            "Smart Card login lives in that session's cache, not in root's."
        )
        return 1
    printer.kv("Cache", cache.cache_name)
    printer.kv("Principal", cache.principal)
    printer.kv("Realm", cache.realm)
    printer.heading("Tickets")
    for ticket in cache.tickets:
        marker = "TGT" if ticket.is_tgt else "   "
        printer.write(f"  [{marker}] {ticket.service}")
        printer.kv("valid from", ticket.valid_from, indent="        ")
        printer.kv("expires", ticket.expires, indent="        ")
        printer.kv("renew until", ticket.renew_until or None, indent="        ")
        printer.kv("flags", ticket.flags or None, indent="        ")
    printer.write()
    if cache.tgt:
        printer.verdict(True, "TGT present: the KDC has issued a ticket", "")
        return 0
    printer.verdict(False, "", "no krbtgt ticket: Kerberised services will fail")
    return 1


def cmd_krb5_test(args, printer: Printer) -> int:
    from .krb5 import check as krb5
    from .sssdconf.conf import SssdConfig

    cert = None
    if args.file or args.base64 or args.from_card or args.stdin or args.cert_id:
        cert = resolve_certificate(args, printer)

    config = None
    try:
        config = SssdConfig.load(args.config)
    except SmartCardError:
        config = None

    report = krb5.report(
        realm=args.realm,
        principal=args.principal,
        cert=cert,
        module=args.module,
        anchors=args.anchors,
        cert_id=args.cert_id,
        do_pkinit=args.pkinit,
        enterprise=args.enterprise,
        keep_cache=args.keep_cache,
        sssd_config=config,
    )
    if args.json:
        return emit_json(report.to_dict())

    printer.heading("Kerberos")
    printer.kv("Realm", report.realm or None)
    printer.kv("KDCs", report.kdcs or None)
    printer.heading("Checks")
    for check in report.checks:
        printer.status(check)

    if report.suggested_command and not args.pkinit:
        printer.heading("Prove it end to end")
        printer.write("  " + " ".join(report.suggested_command))
        printer.note(
            "Add --pkinit to run exactly this. kinit prompts for the PIN on your "
            "terminal; this tool never reads, stores or forwards it."
        )

    printer.write()
    if report.pkinit and report.pkinit.succeeded:
        printer.verdict(True, "PKINIT succeeded: the KDC issued a ticket for this card", "")
    elif report.pkinit:
        printer.verdict(False, "", "PKINIT failed: the card cannot obtain a ticket")
    return 0 if report.ok else 1


# ---------------------------------------------------------------------------
# pam / doctor
# ---------------------------------------------------------------------------


def cmd_pam_check(args, printer: Printer) -> int:
    from .sssdconf.runtime import pam_report

    report = pam_report(args.config)
    if args.json:
        return emit_json(report.to_dict())
    printer.heading("PAM stack")
    printer.kv("Files examined", sorted(report.files) or None)
    printer.kv(
        "Card authentication",
        {
            "required": "Smart Card only (require_cert_auth)",
            "optional": "card or password (try_cert_auth)",
            "off": "not enabled",
        }[report.cert_auth_mode],
    )
    printer.kv("authselect profile", report.authselect_profile or None)
    printer.kv("authselect features", report.authselect_features or None)
    printer.kv(
        "local_auth_policy",
        [f"{domain} = {value}" for domain, value in sorted(report.local_auth_policy.items())]
        or "unset (default 'match')",
    )
    printer.heading("Checks")
    for check in report.checks:
        printer.status(check)
    printer.write()
    # Name the mechanism this distribution actually has. Saying "authselect"
    # right after reporting that authselect is not installed is worse than
    # saying nothing.
    from .platform import detect_distro

    plan = detect_distro().pam_plan()
    owner = {
        "authselect": "authselect",
        "pam-auth-update": "pam-auth-update",
        "manual": "you, by hand",
    }.get(plan.kind, "you")
    printer.note(
        "This tool never edits PAM files. A broken PAM stack locks you out of the "
        f"machine, so changes are left to {owner}."
    )
    if plan.detail:
        printer.note(plan.detail)
    return 1 if any(c.failed for c in report.checks) else 0


def cmd_doctor(args, printer: Printer) -> int:
    from .doctor import run_doctor

    report = run_doctor(
        config_path=args.config,
        check_domains=not args.no_domains,
        check_card=not args.no_card,
        check_krb5=not args.no_krb5,
        user=args.user,
    )
    if args.json:
        return emit_json(report.to_dict())
    printer.heading("sssd-smartcard doctor")
    for check in report.checks:
        printer.status(check)
    printer.write()
    if report.failures:
        printer.verdict(False, "", f"{len(report.failures)} check(s) failed")
    elif report.warnings:
        printer.verdict(True, f"no failures, {len(report.warnings)} warning(s)", "")
    else:
        printer.verdict(True, "all checks passed", "")
    return 1 if report.failures else 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _add_common_flags(parser: argparse.ArgumentParser, *, root: bool) -> None:
    """Options that make sense wherever the user types them.

    On the root parser they carry real defaults; on every leaf they default to
    ``SUPPRESS`` so that not passing them leaves the root's value alone.  That
    is what makes both spellings work::

        sssd-smartcard --json cert inspect --file x.pem
        sssd-smartcard cert inspect --file x.pem --json
    """
    suppress = {} if root else {"default": argparse.SUPPRESS}
    group = parser if root else parser.add_argument_group("common options")
    group.add_argument("--json", action="store_true", help="machine readable output", **suppress)
    group.add_argument("--no-color", action="store_true", help="disable colour", **suppress)
    group.add_argument(
        "--sssd-version",
        metavar="X.Y.Z",
        help="target this SSSD version instead of the detected one",
        **suppress,
    )
    group.add_argument(
        "--config",
        help="path to sssd.conf (default: /etc/sssd/sssd.conf)",
        **({"default": "/etc/sssd/sssd.conf"} if root else suppress),
    )


def _apply_common_flags(parser: argparse.ArgumentParser) -> None:
    """Walk the subparser tree and give every leaf the common flags."""
    for action in parser._actions:  # noqa: SLF001 - the documented way to recurse
        if isinstance(action, argparse._SubParsersAction):
            for child in action.choices.values():
                _apply_common_flags(child)
            return
    _add_common_flags(parser, root=False)


# ---------------------------------------------------------------------------
# debug: raising the logging, and collecting what it produced


def _write_sssd_config(args, printer, config, *, what: str) -> int:
    """Back up, write, validate, restart -- and roll back if sssctl objects.

    The same order as every other change here, for the same reason: a host must
    never be left with an sssd.conf that SSSD will not load, least of all by the
    command someone ran *because* something was already wrong.
    """
    from .backup import new_backup_set, write_atomic
    from .sssdconf.runtime import config_check, restart_sssd

    path = Path(args.config)
    backups = new_backup_set(args.backup_dir)
    if path.exists():
        backups.add(path)
    write_atomic(path, config.render(), mode=0o600)

    check = config_check(args.config)
    if check.found and not check.ok:
        for line in backups.rollback():
            printer.write(f"  {line}")
        printer.status(Check("sssctl config-check", "FAIL", check.output.strip()))
        printer.write("  rolled back; nothing was changed")
        return 1

    printer.write(f"  wrote {path} ({what})")
    if check.found:
        printer.write("  sssctl config-check passed")
    restart = restart_sssd()
    if restart.ok:
        printer.write("  sssd restarted")
    else:
        printer.write(f"  sssd restart failed: {restart.output.strip()}")
    if backups.entries:
        printer.write(printer.dim(f"  Backups: {backups.directory}"))
    return 0 if restart.ok else 1


def cmd_debug_on(args, printer: Printer) -> int:
    from .sssdconf.conf import SssdConfig
    from .support import (
        SSHD_DROPIN,
        SSHD_DROPIN_BODY,
        debug_changes,
        sections_to_debug,
        sshd_reload_ok,
    )

    dry_run = not args.yes if args.dry_run is None else args.dry_run
    config = SssdConfig.load(args.config)
    sections = sections_to_debug(config.domain_sections())
    changes = debug_changes(sections, args.level)

    printer.heading("Verbose logging")
    for section, key, value in changes:
        printer.write(f"  [{section}] {key} = {value}")
    if args.sshd:
        printer.write(f"  {SSHD_DROPIN}  (LogLevel VERBOSE)")

    printer.heading("Cost")
    printer.note(
        f"At level {args.level} SSSD logs the full base64 of every certificate it "
        "reads, on every authentication. On a host with real users that fills a "
        "disk. Put it back with 'sssd-smartcard debug off' as soon as the "
        "mechanism is confirmed -- doctor warns while it is raised."
    )

    if dry_run:
        printer.heading("Result")
        printer.write("  dry run: nothing was written")
        printer.write(printer.dim("  Re-run with --yes to apply."))
        return 0

    working = config.copy()
    for section, key, value in changes:
        working.set(section, key, value)

    printer.heading("Result")
    rc = _write_sssd_config(args, printer, working, what=f"debug_level {args.level}")

    if args.sshd and rc == 0:
        from .backup import write_atomic

        SSHD_DROPIN.parent.mkdir(parents=True, exist_ok=True)
        write_atomic(SSHD_DROPIN, SSHD_DROPIN_BODY, mode=0o644)
        ok, detail = sshd_reload_ok()
        if not ok:
            SSHD_DROPIN.unlink(missing_ok=True)
            printer.status(Check("sshd -t", "FAIL", detail))
            printer.write(f"  removed {SSHD_DROPIN}; sshd left alone")
            return 1
        reload = run(["systemctl", "reload", "ssh"], timeout=60)
        if reload.ok:
            printer.write(f"  wrote {SSHD_DROPIN} and reloaded ssh")
        else:
            printer.write(f"  wrote {SSHD_DROPIN}; reload failed: {reload.output.strip()}")
    return rc


def cmd_debug_off(args, printer: Printer) -> int:
    from .sssdconf.conf import SssdConfig
    from .support import SSHD_DROPIN, sshd_reload_ok

    dry_run = not args.yes if args.dry_run is None else args.dry_run
    config = SssdConfig.load(args.config)

    removing = [s for s in config.sections() if config.get(s, "debug_level")]
    printer.heading("Returning logging to its default")
    if removing:
        for section in removing:
            printer.write(f"  [{section}] debug_level removed")
    else:
        printer.write("  no debug_level is set in sssd.conf")
    if SSHD_DROPIN.exists():
        printer.write(f"  {SSHD_DROPIN} removed")

    if dry_run:
        printer.heading("Result")
        printer.write("  dry run: nothing was written")
        printer.write(printer.dim("  Re-run with --yes to apply."))
        return 0

    printer.heading("Result")
    rc = 0
    if removing:
        working = config.copy()
        for section in removing:
            working.unset(section, "debug_level")
        rc = _write_sssd_config(args, printer, working, what="debug_level removed")
    else:
        printer.write("  sssd.conf unchanged")

    if SSHD_DROPIN.exists():
        SSHD_DROPIN.unlink()
        ok, detail = sshd_reload_ok()
        if ok:
            reload = run(["systemctl", "reload", "ssh"], timeout=60)
            if reload.ok:
                printer.write(f"  removed {SSHD_DROPIN} and reloaded ssh")
            else:
                printer.write(f"  removed {SSHD_DROPIN}; reload failed: {reload.output.strip()}")
        else:
            printer.status(Check("sshd -t", "FAIL", detail))
            rc = 1
    return rc


def cmd_debug_status(args, printer: Printer) -> int:
    from .support import SSHD_DROPIN, debug_state_checks

    checks = debug_state_checks(args.config)
    if args.json:
        return emit_json(
            {
                "raised": [
                    {"name": c.name, "status": c.status, "detail": c.detail}
                    for c in checks
                ],
                "sshd_dropin": str(SSHD_DROPIN) if SSHD_DROPIN.exists() else None,
            }
        )
    printer.heading("Logging")
    if not checks:
        printer.status(Check("debug logging", "PASS", "at its default level"))
        return 0
    for check in checks:
        printer.status(check)
    return 0


def cmd_debug_bundle(args, printer: Printer) -> int:
    from .backup import timestamp
    from .support import collect, write_bundle

    dest = Path(args.output or f"sssd-smartcard-bundle-{timestamp()}.tar.gz")
    printer.heading("Collecting")
    bundle = collect()
    for item in bundle.items:
        line = f"  {'ok  ' if item.ok else 'FAIL'} {item.name}"
        if item.note:
            line += f"  -- {item.note}"
        printer.write(line)

    printer.heading("Deliberately not collected")
    for skipped in bundle.skipped:
        printer.write(f"  {skipped}")

    path = write_bundle(bundle, dest)
    if args.json:
        return emit_json({"bundle": str(path), "items": len(bundle.items)})
    printer.heading("Result")
    printer.write(f"  wrote {path} (mode 0o600, {path.stat().st_size} bytes)")
    printer.note(
        "Values of options named like secrets are replaced. Certificates are "
        "included -- they are public and they are what the bundle is for. Read "
        "MANIFEST.txt inside before sending it anywhere."
    )
    return 0


from .support import DEBUG_LEVEL as _DEBUG_LEVEL  # noqa: E402  (parser default)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sssd-smartcard",
        description="Generate, validate and deploy SSSD Smart Card / PIV configuration.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"sssd-smartcard {__version__}")
    _add_common_flags(parser, root=True)
    subparsers = parser.add_subparsers(dest="group", required=True)

    # -- cert ------------------------------------------------------------
    cert = subparsers.add_parser("cert", help="inspect certificates and derive config")
    cert_sub = cert.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("inspect", "show everything SSSD cares about and propose a configuration"),
        ("autoconfig", "alias of inspect, emphasising the generated configuration"),
    ):
        sub = cert_sub.add_parser(name, help=help_text)
        add_cert_source(sub)
        sub.add_argument(
            "--domain", help="override the account domain inferred from the certificate"
        )
        sub.add_argument(
            "--sssd-domain",
            help="the domain this host is joined to, which owns the [certmap/...] "
            "section (default: read from sssd.conf)",
        )
        sub.add_argument(
            "--provider", default="ad", choices=("ad", "ldap", "ipa"), help="identity provider"
        )
        sub.add_argument("--mapping", help="force a mapping mechanism instead of the best one")
        sub.add_argument("--profile-name", help="name for the generated profile")
        sub.add_argument("--save-profile", metavar="PATH", help="write the generated profile")
        sub.add_argument("--ca-bundle", help="pam_cert_db_path to put in the profile")
        sub.add_argument("--no-pin-issuer", action="store_true", help="do not pin the issuer DN")
        sub.add_argument("--no-pin-eku", action="store_true", help="do not pin the EKUs")
        sub.add_argument(
            "--with-revocation", action="store_true", help="enable revocation in the profile"
        )
        sub.add_argument(
            "--require-smartcard", action="store_true", help="profile demands Smart Card only"
        )
        sub.add_argument(
            "--no-config", action="store_true", help="only inspect, do not generate config"
        )
        sub.set_defaults(func=cmd_cert_inspect)

    # -- card ------------------------------------------------------------
    card = subparsers.add_parser("card", help="Smart Card and PKCS#11 discovery")
    card_sub = card.add_subparsers(dest="command", required=True)
    detect = card_sub.add_parser("detect", help="readers, tokens, slots and certificates")
    detect.add_argument("--module", help="PKCS#11 module path")
    detect.add_argument("--slot", help="PKCS#11 slot id")
    detect.add_argument(
        "--no-read", action="store_true", help="list objects without reading certificates"
    )
    detect.set_defaults(func=cmd_card_detect)

    # -- profile ---------------------------------------------------------
    profile = subparsers.add_parser("profile", help="manage SmartCardProfile files")
    profile_sub = profile.add_subparsers(dest="command", required=True)
    listing = profile_sub.add_parser("list", help="list known profiles")
    listing.set_defaults(func=cmd_profile_list)
    show = profile_sub.add_parser("show", help="show one profile and its rendered rule")
    show.add_argument("name")
    show.set_defaults(func=cmd_profile_show)
    validate = profile_sub.add_parser("validate", help="check profiles for errors")
    validate.add_argument("name", nargs="*")
    validate.set_defaults(func=cmd_profile_validate)

    # -- mapping ---------------------------------------------------------
    mapping = subparsers.add_parser("mapping", help="certificate to user mapping")
    mapping_sub = mapping.add_subparsers(dest="command", required=True)
    types = mapping_sub.add_parser("types", help="list the available mapping mechanisms")
    types.set_defaults(func=cmd_mapping_types)
    test = mapping_sub.add_parser("test", help="run a certificate through a profile")
    test.add_argument("profile")
    add_cert_source(test)
    test.add_argument(
        "--no-sssctl", action="store_true", help="skip sssctl cert-eval-rule, use the local engine"
    )
    test.add_argument("--no-lookup", action="store_true", help="skip the SSSD identity lookup")
    test.set_defaults(func=cmd_mapping_test)

    # -- domain ----------------------------------------------------------
    domain = subparsers.add_parser("domain", help="domains, trusts and identity lookup")
    domain_sub = domain.add_subparsers(dest="command", required=True)
    for name in ("test", "list"):
        sub = domain_sub.add_parser(name, help="show domains, trusts and their status")
        sub.add_argument("domain", nargs="?", help="domain to check specifically")
        sub.add_argument("--user", help="also resolve this user")
        sub.set_defaults(func=cmd_domain_test)

    # -- ca --------------------------------------------------------------
    ca = subparsers.add_parser("ca", help="CA trust bundle")
    ca_sub = ca.add_subparsers(dest="command", required=True)
    ca_show = ca_sub.add_parser("show", help="inspect the bundle or a CA file")
    ca_show.add_argument("file", nargs="*", help="CA files to inspect instead of the bundle")
    ca_show.add_argument(
        "--bundle", default="/etc/sssd/pki/sssd_auth_ca_db.pem", help="trust bundle path"
    )
    ca_show.set_defaults(func=cmd_ca_show)
    ca_import = ca_sub.add_parser("import", help="merge CA certificates into the bundle")
    ca_import.add_argument("file", nargs="+", help="CA certificate files (PEM or DER)")
    ca_import.add_argument(
        "--bundle", default="/etc/sssd/pki/sssd_auth_ca_db.pem", help="trust bundle path"
    )
    ca_import.add_argument("--dry-run", action="store_true", help="show what would change")
    ca_import.add_argument("--backup-dir", help="where to keep backups")
    ca_import.set_defaults(func=cmd_ca_import)

    ca_crl = ca_sub.add_parser("crl", help="revocation lists (CRL)")
    ca_crl_sub = ca_crl.add_subparsers(dest="crl_command", required=True)

    crl_show = ca_crl_sub.add_parser("show", help="inspect a CRL file")
    crl_show.add_argument(
        "file", nargs="?", help="CRL file (default: the installed one)"
    )
    crl_show.add_argument(
        "--bundle",
        default="/etc/sssd/pki/sssd_auth_ca_db.pem",
        help="trust bundle to check coverage against",
    )
    crl_show.set_defaults(func=cmd_ca_crl_show)

    crl_update = ca_crl_sub.add_parser(
        "update", help="fetch one CRL per CA in the bundle, combine and install"
    )
    crl_update.add_argument(
        "--bundle", default="/etc/sssd/pki/sssd_auth_ca_db.pem", help="trust bundle path"
    )
    crl_update.add_argument("--crl-file", dest="crl_file", help="where to write the CRL")
    crl_update.add_argument(
        "--from-file",
        dest="from_file",
        action="append",
        help="use this local CRL instead of downloading it (repeatable)",
    )
    crl_update.add_argument(
        "--no-fetch", action="store_true", help="only use --from-file, download nothing"
    )
    # Not required: with --from-file the CRLs are supplied directly.
    add_cert_source(crl_update, required=False)
    crl_update.add_argument(
        "--dry-run", action="store_true", help="show what would change"
    )
    crl_update.add_argument(
        "--force", action="store_true", help="install even if a CRL is expired"
    )
    crl_update.add_argument("--backup-dir", help="where to keep backups")
    crl_update.set_defaults(func=cmd_ca_crl_update)

    crl_timer = ca_crl_sub.add_parser(
        "timer", help="systemd timer that keeps the CRL fresh"
    )
    crl_timer.add_argument(
        "--bundle", default="/etc/sssd/pki/sssd_auth_ca_db.pem", help="trust bundle path"
    )
    crl_timer.add_argument(
        "--crl-file", dest="crl_file", help="CRL path the timer writes"
    )
    crl_timer.add_argument(
        "--on-calendar",
        dest="on_calendar",
        default="daily",
        help="systemd OnCalendar expression (default: daily)",
    )
    crl_timer.add_argument(
        "--install", action="store_true", help="write the units and enable the timer"
    )
    crl_timer.add_argument("--backup-dir", help="where to keep backups")
    crl_timer.set_defaults(func=cmd_ca_crl_timer)

    ca_discover = ca_sub.add_parser(
        "discover",
        help="follow the certificate's AIA, CDP and OCSP pointers and fetch them",
    )
    ca_discover.add_argument(
        "--pki-url",
        dest="pki_url",
        help="base HTTP URL the CA publishes under. On its own, with no "
        "certificate, the directory is listed and whatever it publishes is "
        "fetched and reported; with a certificate it is a fallback for an AIA "
        "that is missing or LDAP-only",
    )
    ca_discover.add_argument(
        "--bundle",
        default="/etc/sssd/pki/sssd_auth_ca_db.pem",
        help="trust bundle to write with --install",
    )
    ca_discover.add_argument(
        "--install",
        action="store_true",
        help="write the fetched CA chain and CRLs (shows fingerprints first)",
    )
    ca_discover.add_argument(
        "--no-probe",
        action="store_true",
        help="do not send a live OCSP request; only report the advertised URL",
    )
    ca_discover.add_argument(
        "--timeout", type=int, default=20, help="per-request timeout in seconds"
    )
    ca_discover.add_argument("--backup-dir", help="where to keep backups")
    # Not required: with --pki-url alone the PKI's own directory is read.
    add_cert_source(ca_discover, required=False)
    ca_discover.set_defaults(func=cmd_ca_discover)

    # -- config ----------------------------------------------------------
    config = subparsers.add_parser("config", help="render, diff, validate and apply")
    config_sub = config.add_subparsers(dest="command", required=True)

    def add_render_flags(sub):
        sub.add_argument("profile")
        sub.add_argument(
            "--verification-scope",
            default="sssd",
            choices=("sssd", "pam"),
            help="write certificate_verification globally or pam_cert_verification only",
        )
        sub.add_argument(
            "--allow-degraded",
            action="store_true",
            help="warn instead of failing when the target SSSD lacks an option",
        )

    render_cmd = config_sub.add_parser("render", help="print the configuration fragment")
    add_render_flags(render_cmd)
    render_cmd.add_argument("--no-comments", action="store_true")
    render_cmd.set_defaults(func=cmd_config_render)

    diff_cmd = config_sub.add_parser("diff", help="diff against the configuration on disk")
    add_render_flags(diff_cmd)
    diff_cmd.add_argument("--skip-ca", action="store_true", help="ignore the CA bundle")
    diff_cmd.set_defaults(func=cmd_config_diff)

    validate_cmd = config_sub.add_parser("validate", help="validate profile and current config")
    add_render_flags(validate_cmd)
    validate_cmd.add_argument("--skip-ca", action="store_true")
    validate_cmd.set_defaults(func=cmd_config_validate)

    apply_cmd = config_sub.add_parser("apply", help="apply the profile (dry run by default)")
    add_render_flags(apply_cmd)
    apply_cmd.add_argument("--skip-ca", action="store_true")
    apply_cmd.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_const",
        const=True,
        default=None,
        help="show what would change and stop (the default without --yes)",
    )
    apply_cmd.add_argument("--yes", action="store_true", help="actually write the changes")
    apply_cmd.add_argument("--no-restart", action="store_true", help="do not restart SSSD")
    apply_cmd.add_argument("--no-validate", action="store_true", help="skip sssctl config-check")
    apply_cmd.add_argument("--backup-dir", help="where to keep backups")
    apply_cmd.add_argument("--force", action="store_true", help="apply despite failed checks")
    apply_cmd.set_defaults(func=cmd_config_apply)

    # -- krb5 ------------------------------------------------------------
    krb5 = subparsers.add_parser("krb5", help="Kerberos tickets and PKINIT")
    krb5_sub = krb5.add_subparsers(dest="command", required=True)
    status = krb5_sub.add_parser("status", help="show the credential cache and its TGT")
    status.add_argument("--cache", help="credential cache to read instead of the default")
    status.set_defaults(func=cmd_krb5_status)

    krb_test = krb5_sub.add_parser(
        "test", help="check realm, KDC and optionally obtain a real ticket with the card"
    )
    add_cert_source(krb_test, required=False)
    krb_test.add_argument("--realm", help="Kerberos realm (default: from krb5.conf)")
    krb_test.add_argument(
        "--principal", help="principal to request a ticket for (default: from the certificate)"
    )
    krb_test.add_argument(
        "--pkinit",
        action="store_true",
        help="actually run kinit with the card; kinit prompts for the PIN itself",
    )
    krb_test.add_argument(
        "--anchors", help="PEM file with the CA that signs the KDC certificate"
    )
    krb_test.add_argument(
        "--enterprise",
        action="store_true",
        help="pass the principal as an AD enterprise principal (kinit -E)",
    )
    krb_test.add_argument(
        "--keep-cache", action="store_true", help="keep the test ticket instead of destroying it"
    )
    krb_test.set_defaults(func=cmd_krb5_test)

    # -- pam / doctor ----------------------------------------------------
    pam = subparsers.add_parser("pam", help="inspect the PAM stack (read only)")
    pam_sub = pam.add_subparsers(dest="command", required=True)
    pam_check = pam_sub.add_parser("check", help="report on pam_sss and authselect")
    pam_check.set_defaults(func=cmd_pam_check)

    debug = subparsers.add_parser(
        "debug", help="turn verbose logging on or off, and collect a bundle"
    )
    debug_sub = debug.add_subparsers(dest="debug_command", required=True)

    dbg_on = debug_sub.add_parser("on", help="raise SSSD (and optionally sshd) logging")
    dbg_on.add_argument("--level", type=int, default=_DEBUG_LEVEL,
                        help=f"SSSD debug_level (default {_DEBUG_LEVEL})")
    dbg_on.add_argument("--sshd", action="store_true",
                        help="also raise sshd's LogLevel, through a drop-in file")
    dbg_on.add_argument("--yes", action="store_true", help="write the changes")
    dbg_on.add_argument("--dry-run", action="store_true", default=None)
    dbg_on.add_argument("--backup-dir", help="where to keep backups")
    dbg_on.set_defaults(func=cmd_debug_on)

    dbg_off = debug_sub.add_parser("off", help="put logging back where it was")
    dbg_off.add_argument("--yes", action="store_true", help="write the changes")
    dbg_off.add_argument("--dry-run", action="store_true", default=None)
    dbg_off.add_argument("--backup-dir", help="where to keep backups")
    dbg_off.set_defaults(func=cmd_debug_off)

    dbg_status = debug_sub.add_parser("status", help="report what is currently raised")
    dbg_status.set_defaults(func=cmd_debug_status)

    dbg_bundle = debug_sub.add_parser(
        "bundle", help="collect configuration, logs and state into one archive"
    )
    dbg_bundle.add_argument("-o", "--output", help="path to write (default: a dated file in the current directory)")
    dbg_bundle.set_defaults(func=cmd_debug_bundle)

    doctor = subparsers.add_parser("doctor", help="run every diagnostic")
    doctor.add_argument("--user", help="also verify this user resolves")
    doctor.add_argument("--no-domains", action="store_true", help="skip domain/trust checks")
    doctor.add_argument("--no-card", action="store_true", help="skip Smart Card checks")
    doctor.add_argument("--no-krb5", action="store_true", help="skip Kerberos checks")
    doctor.set_defaults(func=cmd_doctor)

    _apply_common_flags(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    printer = Printer(colour=False if args.no_color else None)
    try:
        return args.func(args, printer)
    except SmartCardError as exc:
        printer.error(str(exc))
        return exc.exit_code
    except KeyboardInterrupt:  # pragma: no cover
        printer.write()
        printer.error("interrupted")
        return 130
    except BrokenPipeError:  # pragma: no cover
        return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
