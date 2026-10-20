"""``sssd-smartcard doctor`` -- one pass over everything that has to be right.

The checks are ordered the way a login actually flows: the host, then SSSD,
then the identity side (domains and trusts), then the credential side (PAM, CA
trust, reader, card).  A failure early on explains failures later, so the
output is meant to be read top to bottom.
"""

from __future__ import annotations

import re

import os
from dataclasses import dataclass, field
from pathlib import Path

from .backup import check_mode
from .ca.trust import load_bundle
from .certmap.compat import detect_sssd
from .model.profile import DEFAULT_CA_DB
from .sssdconf.conf import DEFAULT_CONFIG, SssdConfig
from .sssdconf.runtime import pam_report, service_active, trust_report
from .util import Check, is_linux, run, service_or_socket_active, which

#: Where distributions install SSSD's PKCS#11 helper.
P11_CHILD_PATHS = (
    "/usr/libexec/sssd/p11_child",
    "/usr/lib/x86_64-linux-gnu/sssd/p11_child",
    "/usr/lib/sssd/p11_child",
    "/usr/lib64/sssd/p11_child",
)

#: SSSD looks for this marker to offer Smart Card pre-authentication.
PREAUTH_MARKER = "/var/lib/sss/pubconf/pam_preauth_available"


@dataclass
class DoctorReport:
    checks: list[Check] = field(default_factory=list)

    def add(self, *checks: Check) -> None:
        self.checks.extend(checks)

    @property
    def failures(self) -> list[Check]:
        return [c for c in self.checks if c.status == "FAIL"]

    @property
    def warnings(self) -> list[Check]:
        return [c for c in self.checks if c.status == "WARN"]

    @property
    def ok(self) -> bool:
        return not self.failures

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "failures": len(self.failures),
            "warnings": len(self.warnings),
            "checks": [
                {
                    "name": c.name,
                    "status": c.status,
                    "detail": c.detail,
                    "hint": c.hint,
                    **({"data": c.data} if c.data else {}),
                }
                for c in self.checks
            ],
        }


def _check_platform(report: DoctorReport) -> bool:
    if is_linux():
        report.add(Check("platform", "PASS", "Linux"))
        return True
    report.add(
        Check(
            "platform",
            "SKIP",
            f"{os.name}: this is not an SSSD host",
            hint="Offline work still functions: `cert inspect`, `config render`, "
            "`mapping test --no-sssctl` and `profile` all run here.",
        )
    )
    return False


def _check_sssd(report: DoctorReport) -> None:
    info = detect_sssd()
    if info.detected:
        report.add(
            Check(
                "SSSD installed",
                "PASS",
                f"{info.version} ({info.binary})",
                data={"version": str(info.version)},
            )
        )
    else:
        report.add(
            Check(
                "SSSD installed",
                "FAIL",
                info.detail,
                hint="Install sssd and sssd-tools.",
            )
        )
        return

    active, state = service_active()
    if active is None:
        report.add(Check("SSSD running", "SKIP", state))
    else:
        report.add(
            Check(
                "SSSD running",
                "PASS" if active else "FAIL",
                f"sssd.service is {state}",
                hint="" if active else "systemctl enable --now sssd",
            )
        )

    for tool, package in (("sssctl", "sssd-tools"), ("openssl", "openssl")):
        report.add(
            Check(
                f"{tool} available",
                "PASS" if info.tools.get(tool) else "WARN",
                "found" if info.tools.get(tool) else "not found",
                hint="" if info.tools.get(tool) else f"Install {package}.",
            )
        )

    for path in P11_CHILD_PATHS:
        if os.path.exists(path):
            report.add(Check("p11_child", "PASS", path))
            break
    else:
        report.add(
            Check(
                "p11_child",
                "FAIL",
                "SSSD's PKCS#11 helper was not found",
                hint="Smart Card authentication cannot work without it. It ships in the "
                "sssd or sssd-common package depending on the distribution.",
            )
        )

    report.add(
        Check(
            "pre-auth marker",
            "PASS" if os.path.exists(PREAUTH_MARKER) else "INFO",
            PREAUTH_MARKER
            + (" is present" if os.path.exists(PREAUTH_MARKER) else " is missing"),
            hint=""
            if os.path.exists(PREAUTH_MARKER)
            else "SSSD creates it when Smart Card pre-authentication is in use; if card "
            "prompts never appear, check this file.",
        )
    )


def _check_config(report: DoctorReport, config_path: str) -> SssdConfig | None:
    path = Path(config_path)
    if not path.exists():
        report.add(
            Check(
                "sssd.conf",
                "FAIL",
                f"{path} does not exist",
                hint="Join and configure the host's domain first.",
            )
        )
        return None

    ok, mode = check_mode(path, 0o600)
    report.add(
        Check(
            "sssd.conf permissions",
            "PASS" if ok else "FAIL",
            f"mode {oct(mode) if mode is not None else '?'}",
            hint="" if ok else f"SSSD refuses to start with a group/world readable "
            f"config: chmod 600 {path}",
        )
    )

    try:
        config = SssdConfig.load(path)
    except Exception as exc:
        report.add(Check("sssd.conf readable", "FAIL", str(exc)))
        return None

    domains = config.domains()
    report.add(
        Check(
            "sssd.conf domains",
            "PASS" if domains else "FAIL",
            ", ".join(domains) if domains else "[sssd] domains is empty",
        )
    )

    pam_cert_auth = (config.get("pam", "pam_cert_auth") or "").strip().lower()
    report.add(
        Check(
            "pam_cert_auth",
            "PASS" if pam_cert_auth in ("true", "yes", "1") else "FAIL",
            f"[pam] pam_cert_auth = {pam_cert_auth or '(not set, defaults to False)'}",
            hint=""
            if pam_cert_auth in ("true", "yes", "1")
            else "Smart Card authentication is off. Apply a profile, or set it by hand.",
        )
    )

    certmaps = config.certmap_sections()
    report.add(
        Check(
            "certmap rules",
            "PASS" if certmaps else "WARN",
            ", ".join(certmaps) if certmaps else "no [certmap/...] section configured",
            hint=""
            if certmaps
            else "Without a rule SSSD falls back to KRB5:<EKU>clientAuth with "
            "LDAP:(userCertificate;binary={cert!bin}), which needs the certificate "
            "stored on the user object.",
        )
    )

    verification = config.get("sssd", "certificate_verification") or config.get(
        "pam", "pam_cert_verification"
    )
    if verification:
        level = "WARN" if "no_verification" in verification else "INFO"
        report.add(
            Check(
                "certificate_verification",
                level,
                verification,
                hint="no_verification accepts any certificate the card offers -- "
                "troubleshooting only."
                if "no_verification" in verification
                else "",
            )
        )
    else:
        report.add(
            Check(
                "certificate_verification",
                "INFO",
                "not set (SSSD default: verification is not restricted)",
            )
        )
    return config


def _check_ca_bundle(report: DoctorReport, config: SssdConfig | None) -> None:
    path = DEFAULT_CA_DB
    if config:
        path = config.get("pam", "pam_cert_db_path") or DEFAULT_CA_DB
    bundle = Path(path)
    if not bundle.exists():
        report.add(
            Check(
                "CA trust bundle",
                "FAIL",
                f"{bundle} does not exist",
                hint="SSSD verifies card certificates against this PEM file only. "
                "Build it with: sssd-smartcard ca import <ca.pem>",
            )
        )
        return
    try:
        entries = load_bundle(bundle)
    except Exception as exc:
        report.add(Check("CA trust bundle", "FAIL", f"{bundle}: {exc}"))
        return
    if not entries:
        report.add(
            Check("CA trust bundle", "FAIL", f"{bundle} contains no certificates")
        )
        return
    expired = [e for e in entries if e.cert.expired]
    soon = [e for e in entries if not e.cert.expired and e.cert.days_remaining < 90]
    status = "FAIL" if expired else ("WARN" if soon else "PASS")
    detail = f"{bundle}: {len(entries)} certificate(s)"
    if expired:
        detail += "; expired: " + ", ".join(e.cert.subject_dn for e in expired)
    if soon:
        detail += "; expiring soon: " + ", ".join(
            f"{e.cert.subject_dn} ({e.cert.days_remaining}d)" for e in soon
        )
    report.add(Check("CA trust bundle", status, detail))

    ok, mode = check_mode(bundle, 0o644)
    if mode is not None and mode & 0o022:
        report.add(
            Check(
                "CA bundle permissions",
                "FAIL",
                f"mode {oct(mode)} is group or world writable",
                hint=f"chmod 644 {bundle}",
            )
        )


def _check_nsswitch(report: DoctorReport) -> None:
    path = Path("/etc/nsswitch.conf")
    if not path.exists():
        report.add(Check("nsswitch.conf", "SKIP", "file not found"))
        return
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        report.add(Check("nsswitch.conf", "WARN", str(exc)))
        return
    for line in text.splitlines():
        if line.strip().startswith("passwd:"):
            ok = "sss" in line
            report.add(
                Check(
                    "nsswitch passwd",
                    "PASS" if ok else "FAIL",
                    line.strip(),
                    hint="" if ok else "Add 'sss' to the passwd line, or users will "
                    "never resolve.",
                )
            )
            return
    report.add(Check("nsswitch passwd", "WARN", "no passwd line found"))


def _check_smartcard_stack(report: DoctorReport) -> None:
    for tool, package in (
        ("pkcs11-tool", "opensc"),
        ("opensc-tool", "opensc"),
        ("p11-kit", "p11-kit"),
    ):
        report.add(
            Check(
                f"{tool}",
                "PASS" if which(tool) else "WARN",
                "found" if which(tool) else "not found",
                hint="" if which(tool) else f"Install {package} to inspect cards.",
            )
        )

    available, detail = service_or_socket_active("pcscd.service", "pcscd.socket")
    if available is None:
        report.add(Check("pcscd", "SKIP", detail))
    else:
        report.add(
            Check(
                "pcscd",
                "PASS" if available else "WARN",
                detail,
                hint="" if available else "systemctl enable --now pcscd.socket",
            )
        )

    from .pkcs11.detect import find_modules

    modules = find_modules()
    report.add(
        Check(
            "PKCS#11 modules",
            "PASS" if modules else "WARN",
            ", ".join(modules) if modules else "none found",
            hint="" if modules else "Install opensc for the OpenSC PKCS#11 module.",
        )
    )


def _check_revocation(report: DoctorReport, config) -> None:
    """Report on CRL freshness, coverage and the refresh timer.

    Silent unless the configuration asks for CRL checking: a host doing OCSP,
    or not checking revocation at all, has nothing to report here. When CRL
    checking IS on, an expired file is a total outage, so the checks are loud.
    """
    if config is None:
        return
    verification = ""
    for section in ("sssd", "pam"):
        for key in ("certificate_verification", "pam_cert_verification"):
            value = config.get(section, key)
            if value:
                verification += value + ","
    match = re.search(r"crl_file\s*=\s*([^,\s]+)", verification)
    if not match:
        if "no_verification" in verification:
            report.add(
                Check(
                    "revocation",
                    "WARN",
                    "certificate_verification contains no_verification",
                    hint="Verification is disabled completely; sssd.conf(5) says this "
                    "is for testing only. A revoked -- or forged -- certificate is "
                    "accepted.",
                )
            )
        else:
            report.add(
                Check(
                    "revocation",
                    "WARN" if "no_ocsp" in verification else "INFO",
                    "no crl_file in certificate_verification"
                    + (" and OCSP is disabled" if "no_ocsp" in verification else ""),
                    hint="A revoked certificate still logs in. Where there is no OCSP "
                    "responder, CRLs are the only mechanism: set revocation.method to "
                    "crl in the profile and run 'sssd-smartcard ca crl update "
                    "--from-card'."
                    if "no_ocsp" in verification
                    else "",
                )
            )
        return

    from .ca.crl import installed_crl_checks, timer_checks

    bundle = (
        config.get("pam", "pam_cert_db_path")
        or "/etc/sssd/pki/sssd_auth_ca_db.pem"
    )
    report.add(*installed_crl_checks(match.group(1), ca_bundle=bundle))
    report.add(*timer_checks())
    if "soft_crl" not in verification:
        report.add(
            Check(
                "CRL fail mode",
                "INFO",
                "crl_file without soft_crl: revocation is enforced strictly",
                hint="An expired CRL then stops every card login. That is the point "
                "of enforcing revocation, but keep the refresh timer healthy. Set "
                "revocation.fail_mode to open to emit soft_crl instead.",
            )
        )


def run_doctor(
    *,
    config_path: str = DEFAULT_CONFIG,
    check_domains: bool = True,
    check_card: bool = True,
    check_krb5: bool = True,
    user: str | None = None,
) -> DoctorReport:
    """Run every check and return the collected report."""
    report = DoctorReport()
    if not _check_platform(report):
        return report

    _check_sssd(report)
    config = _check_config(report, config_path)
    _check_nsswitch(report)
    _check_ca_bundle(report, config)

    pam = pam_report(config_path)
    report.add(*pam.checks)

    # Revocation. Only meaningful when sssd.conf actually asks for a CRL --
    # and then it matters a great deal, because crl_file fails closed: once
    # nextUpdate passes, every card login stops.
    _check_revocation(report, config)

    # Host-level, so it is worth reporting even when no --user was given: with
    # no provisioning, the first login of every domain user lands in a session
    # with no writable home.
    if not user:
        from .sssdconf.runtime import UserLookup, home_directory_checks

        report.add(*home_directory_checks(UserLookup(user="")))

    # The account phase refuses logins the card already passed, and nothing
    # else in this report looks at it: every check above concerns the auth
    # phase. Read from the configuration on disk, which is what is deciding.
    if config is not None:
        from .sssdconf.runtime import gpo_access_checks

        for name in config.domain_sections():
            report.add(*gpo_access_checks(config.get, name))

    # SSH is a separate mechanism, not a consequence of the local login
    # working: the token is on the client, so pam_cert_auth and
    # local_auth_policy take no part, and sshd needs its own directive. Worth
    # reporting on a host that is otherwise configured for cards, because the
    # CA bundle, CRL and certmap rule already do the validation.
    if pam.cert_auth_enabled:
        from .sssdconf.runtime import ssh_certificate_checks

        report.add(*ssh_certificate_checks(user))

    # sudo is a separate consumer of the same identity, and its two halves --
    # the nsswitch source and the package implementing it -- look configured
    # apart while doing nothing together.
    from .sssdconf.runtime import sudo_agent_checks, sudo_rules_checks

    report.add(*sudo_rules_checks())
    # And whether sudo can use a card held by an SSH client, which pam_sss
    # cannot: over SSH the token never reaches the server.
    report.add(*sudo_agent_checks())

    if check_domains:
        trust = trust_report(config_path)
        report.add(*trust.checks)
        for domain in trust.domains:
            if domain.online is None:
                continue
            report.add(
                Check(
                    f"domain {domain.name}",
                    "PASS" if domain.online else "FAIL",
                    ("online" if domain.online else "offline")
                    + (" (trusted)" if domain.trusted else " (primary)"),
                    hint=""
                    if domain.online
                    else "Smart Card authentication cannot resolve users in an offline "
                    "domain. Fix connectivity, DNS and the trust first.",
                )
            )

    if user:
        from .sssdconf.runtime import lookup_user

        lookup = lookup_user(user)
        report.add(*lookup.checks)
        report.add(
            Check(
                f"identity lookup {user}",
                "PASS" if lookup.resolved else "FAIL",
                f"uid={lookup.uid}" if lookup.resolved else "not resolvable",
                hint=""
                if lookup.resolved
                else "Identity lookup through the trusted domain failed. Fix "
                "AD/SSSD/trust configuration before enabling Smart Card "
                "authentication.",
            )
        )

    if check_krb5:
        from .krb5 import check as krb5

        krb_report = krb5.report(sssd_config=config)
        # The live PKINIT test needs a card and a PIN, so doctor only reports on
        # configuration and on any ticket that already exists.
        report.add(*[c for c in krb_report.checks if c.name != "PKINIT"])
        if krb_report.suggested_command:
            report.add(
                Check(
                    "PKINIT test",
                    "INFO",
                    "not run by doctor",
                    hint="Prove the KDC issues a ticket for the card with: "
                    "sssd-smartcard krb5 test --from-card --pkinit",
                )
            )

    if check_card:
        _check_smartcard_stack(report)

    return report
