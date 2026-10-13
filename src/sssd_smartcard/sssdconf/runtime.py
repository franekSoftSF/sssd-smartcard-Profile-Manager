"""Talking to a running SSSD: domains, trusts, user lookups, PAM, services.

The trusted-domain story is the one that bites people: the Linux host joins
DOMAIN B, the accounts live in DOMAIN A, and Smart Card authentication cannot
possibly work until SSSD can already resolve those users by name.  This module
provides that pre-flight so the Smart Card configuration is never blamed for a
broken trust.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ..util import Check, CommandResult, is_linux, run, which
from .conf import DEFAULT_CONFIG, SssdConfig

PAM_DIR = Path("/etc/pam.d")
PAM_FILES = ("system-auth", "password-auth", "smartcard-auth", "common-auth", "sshd", "login")
#: Session stacks, read separately: home directory provisioning lives here, and
#: a card that authenticates into a session with no home gives a black screen.
PAM_SESSION_FILES = ("common-session", "system-auth", "password-auth")

#: Modules that create a missing home directory at login.
HOME_PROVISIONERS = ("pam_mkhomedir.so", "pam_oddjob_mkhomedir.so")


# ---------------------------------------------------------------------------
# Services and configuration validation
# ---------------------------------------------------------------------------


def service_active(unit: str = "sssd.service") -> tuple[bool | None, str]:
    """``(active?, detail)``; ``None`` when systemd is not reachable."""
    result = run(["systemctl", "is-active", unit], timeout=10)
    if not result.found:
        return None, "systemctl not available"
    state = result.stdout.strip() or result.stderr.strip()
    return state == "active", state


def config_check(path: str = DEFAULT_CONFIG) -> CommandResult:
    """Run ``sssctl config-check``, SSSD's own validator."""
    argv = ["sssctl", "config-check"]
    if path != DEFAULT_CONFIG:
        argv += ["--config", path]
    return run(argv, timeout=60)


def restart_sssd() -> CommandResult:
    return run(["systemctl", "restart", "sssd.service"], timeout=120)


def clear_cache() -> CommandResult:
    return run(["sss_cache", "-E"], timeout=60)


# ---------------------------------------------------------------------------
# Domains and trusts
# ---------------------------------------------------------------------------


@dataclass
class DomainInfo:
    name: str
    configured: bool = False  # listed in [sssd] domains =
    trusted: bool = False  # discovered, i.e. reached through a trust
    online: bool | None = None
    status_raw: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "configured": self.configured,
            "trusted": self.trusted,
            "online": self.online,
        }


def domain_list() -> tuple[list[str], CommandResult]:
    result = run(["sssctl", "domain-list"], timeout=30)
    if not result.ok:
        return [], result
    names = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return names, result


def domain_status(domain: str) -> tuple[bool | None, str, CommandResult]:
    """``(online?, raw_text, result)`` from ``sssctl domain-status``."""
    result = run(["sssctl", "domain-status", domain], timeout=30)
    if not result.found:
        return None, "", result
    text = result.output
    lowered = text.lower()
    online: bool | None = None
    if "online status: online" in lowered or re.search(r"\bonline\b", lowered):
        online = True
    if "online status: offline" in lowered or "offline" in lowered:
        online = False
    return online, text, result


@dataclass
class TrustReport:
    """What SSSD knows about its domains right now."""

    primary: list[str] = field(default_factory=list)
    domains: list[DomainInfo] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    available: bool = True

    def find(self, name: str) -> DomainInfo | None:
        lowered = name.lower()
        for domain in self.domains:
            if domain.name.lower() == lowered:
                return domain
        return None

    @property
    def trusted(self) -> list[DomainInfo]:
        return [d for d in self.domains if d.trusted]

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "primary_domains": self.primary,
            "domains": [d.to_dict() for d in self.domains],
            "checks": [
                {"name": c.name, "status": c.status, "detail": c.detail, "hint": c.hint}
                for c in self.checks
            ],
        }


def trust_report(config_path: str = DEFAULT_CONFIG, *, probe_status: bool = True) -> TrustReport:
    """Enumerate primary and trusted domains and their online state."""
    report = TrustReport()
    if not is_linux():
        report.available = False
        report.checks.append(
            Check("sssctl", "SKIP", "domain diagnostics require the SSSD host")
        )
        return report

    try:
        configured = SssdConfig.load(config_path).domains()
    except Exception:  # unreadable sssd.conf is not fatal here
        configured = []
    report.primary = configured

    names, result = domain_list()
    if not result.found:
        report.available = False
        report.checks.append(
            Check("sssctl", "FAIL", "sssctl is not installed", hint="Install the sssd-tools package.")
        )
        return report
    if not result.ok:
        report.available = False
        report.checks.append(
            Check(
                "sssctl domain-list",
                "FAIL",
                result.output or "command failed",
                hint="SSSD may not be running, or you may need root.",
            )
        )
        return report

    lowered_configured = {c.lower() for c in configured}
    for name in names:
        info = DomainInfo(
            name=name,
            configured=name.lower() in lowered_configured,
            trusted=name.lower() not in lowered_configured,
        )
        if probe_status:
            info.online, info.status_raw, _ = domain_status(name)
        report.domains.append(info)

    report.checks.append(
        Check("sssctl domain-list", "PASS", f"{len(names)} domain(s): " + ", ".join(names))
    )
    if not report.trusted:
        report.checks.append(
            Check(
                "trusted domains",
                "WARN",
                "SSSD reports no trusted domains",
                hint="If the accounts live in a trusted forest, the trust is not working "
                "yet. Fix that before configuring Smart Card authentication.",
            )
        )
    else:
        report.checks.append(
            Check(
                "trusted domains",
                "PASS",
                ", ".join(d.name for d in report.trusted),
            )
        )
    return report


# ---------------------------------------------------------------------------
# User lookups
# ---------------------------------------------------------------------------


@dataclass
class UserLookup:
    """Whether SSSD can resolve a user, and by which route."""

    user: str
    resolved: bool = False
    uid: str | None = None
    gid: str | None = None
    home: str | None = None
    groups: list[str] = field(default_factory=list)
    domain: str | None = None
    checks: list[Check] = field(default_factory=list)
    raw: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "user": self.user,
            "resolved": self.resolved,
            "uid": self.uid,
            "gid": self.gid,
            "home": self.home,
            "groups": self.groups,
            "domain": self.domain,
            "checks": [
                {"name": c.name, "status": c.status, "detail": c.detail, "hint": c.hint}
                for c in self.checks
            ],
        }


def lookup_user(name: str) -> UserLookup:
    """Run getent, id and sssctl user-checks against *name*."""
    out = UserLookup(user=name)
    if not is_linux():
        out.checks.append(Check("lookup", "SKIP", "user lookups require the SSSD host"))
        return out

    getent = run(["getent", "passwd", name], timeout=30)
    out.raw["getent"] = getent.output
    if getent.ok and getent.stdout.strip():
        fields = getent.stdout.strip().split(":")
        if len(fields) >= 6:
            out.uid, out.gid, out.home = fields[2], fields[3], fields[5]
        out.resolved = True
        out.checks.append(Check("getent passwd", "PASS", getent.stdout.strip()))
    else:
        out.checks.append(
            Check(
                "getent passwd",
                "FAIL",
                f"{name} is not resolvable through NSS",
                hint="Check that 'sss' is in the passwd line of /etc/nsswitch.conf and "
                "that the domain is online.",
            )
        )

    id_result = run(["id", name], timeout=30)
    out.raw["id"] = id_result.output
    if id_result.ok:
        out.checks.append(Check("id", "PASS", id_result.stdout.strip()))
        # Only the groups= segment. Scanning the whole line also matches the
        # uid=…(name) and gid=…(name) parentheses, which listed the user's own
        # account as one of their groups.
        groups_part = re.search(r"\bgroups=(.*)$", id_result.stdout.strip())
        if groups_part:
            for match in re.finditer(r"\d+\(([^)]+)\)", groups_part.group(1)):
                group = match.group(1)
                if group not in out.groups:
                    out.groups.append(group)
    else:
        out.checks.append(Check("id", "FAIL", id_result.output or "lookup failed"))

    checks = run(["sssctl", "user-checks", name], timeout=60)
    out.raw["sssctl user-checks"] = checks.output
    if not checks.found:
        out.checks.append(Check("sssctl user-checks", "SKIP", "sssctl is not installed"))
    elif checks.ok:
        out.checks.append(Check("sssctl user-checks", "PASS", checks.output.splitlines()[0] if checks.output else ""))
        match = re.search(r"domain[:=]\s*(\S+)", checks.output, re.IGNORECASE)
        if match:
            out.domain = match.group(1)
    else:
        out.checks.append(Check("sssctl user-checks", "FAIL", checks.output))

    if "@" in name and not out.domain:
        out.domain = name.rsplit("@", 1)[1]

    # Resolving the user is not the same as being able to log in as them.
    out.checks.extend(home_directory_checks(out))
    return out



# ---------------------------------------------------------------------------
# SSH: the card is on the client, so this is a different mechanism entirely

#: What sshd must call to get a user's keys from SSSD.
SSH_KEYS_COMMAND = "sss_ssh_authorizedkeys"


def sshd_effective_config() -> dict[str, str]:
    """``sshd -T`` as a dict, or ``{}`` when it cannot be read.

    Parsed from sshd itself rather than from sshd_config, because Ubuntu splits
    the configuration across sshd_config.d/ and the last matching Include wins;
    reading one file would report a setting another file overrides.
    """
    result = run(["sshd", "-T"])
    if not result.ok:
        # Ubuntu does not put sbin on a non-root PATH.
        result = run(["/usr/sbin/sshd", "-T"])
    if not result.ok:
        return {}
    out: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, _, value = line.partition(" ")
        if key:
            out[key.strip().lower()] = value.strip()
    return out


def ssh_certificate_checks(user: str = "") -> list[Check]:
    """Whether a Smart Card can be used for SSH, which it cannot by default.

    SSH is not the local login path and reusing its conclusions is wrong: the
    token is on the *client*, so the server never sees a PIN and
    ``pam_cert_auth`` and ``local_auth_policy`` play no part.  What happens
    instead is that SSSD derives an SSH public key from the X.509 certificate
    in the user's directory entry, and sshd asks for it through
    ``AuthorizedKeysCommand``.

    The useful part for this tool: ``sss_ssh_authorizedkeys(1)`` validates those
    certificates with ``ca_db`` and ``certificate_verification`` and filters
    them through the certmap rules -- the same bundle, the same CRL and the same
    rule this tool already configures.  So revocation covers SSH as well, and
    the only piece missing on a configured host is the sshd directive.
    """
    checks: list[Check] = []
    if not is_linux():
        return checks

    helper = which(SSH_KEYS_COMMAND)
    if helper is None:
        checks.append(
            Check(
                "ssh key helper",
                "SKIP",
                f"{SSH_KEYS_COMMAND} is not installed",
                hint="It ships with sssd; without it sshd cannot obtain keys from "
                "SSSD and Smart Card SSH is not available.",
            )
        )
        return checks

    config = sshd_effective_config()
    if not config:
        checks.append(
            Check(
                "sshd AuthorizedKeysCommand",
                "SKIP",
                "cannot read the effective sshd configuration (needs root)",
            )
        )
    else:
        command = config.get("authorizedkeyscommand", "none")
        if SSH_KEYS_COMMAND in command:
            checks.append(
                Check(
                    "sshd AuthorizedKeysCommand",
                    "PASS",
                    command,
                )
            )
        else:
            checks.append(
                Check(
                    "sshd AuthorizedKeysCommand",
                    "WARN",
                    "not set to " + SSH_KEYS_COMMAND
                    + ("" if command in ("", "none") else f" (currently {command})"),
                    hint="Smart Card login works locally without this; SSH does not "
                    "use that path at all. Add to /etc/ssh/sshd_config.d/: "
                    f"AuthorizedKeysCommand {helper} / AuthorizedKeysCommandUser "
                    "nobody, then 'sshd -t' before reloading. The CA bundle, CRL "
                    "and certmap rule are already what validates those keys.",
                )
            )

    if not user:
        return checks

    result = run([helper, user])
    if not result.ok:
        checks.append(
            Check(
                "ssh keys from certificate",
                "WARN",
                f"{SSH_KEYS_COMMAND} failed: {result.output.strip()[:160]}",
            )
        )
        return checks

    keys = [ln for ln in result.stdout.splitlines() if ln.startswith(("ssh-", "ecdsa-"))]
    if keys:
        checks.append(
            Check(
                "ssh keys from certificate",
                "PASS",
                f"{len(keys)} key(s) derived for {user}",
            )
        )
    else:
        checks.append(
            Check(
                "ssh keys from certificate",
                "WARN",
                f"no keys derived for {user}",
                hint="Either the directory entry holds no certificate "
                "(ldap_user_certificate, userCertificate;binary on AD), or every "
                "one of them was rejected by certificate_verification or by the "
                "certmap rules. A revoked or expired certificate is dropped here "
                "exactly as it is at the login prompt.",
            )
        )
    return checks

def home_provisioning() -> tuple[str, str]:
    """``(module, file)`` that creates missing home directories, or ``("", "")``.

    Without one of these, ``fallback_homedir`` in sssd.conf only *names* a path
    -- nothing creates it.  The user then authenticates successfully and lands
    in a session that cannot write anything, which in GNOME is a black screen
    and in a shell is a login in ``/`` with no dotfiles.
    """
    for name in PAM_SESSION_FILES:
        path = PAM_DIR / name
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            if line.lstrip().startswith("#"):
                continue
            for module in HOME_PROVISIONERS:
                if module in line:
                    return module, name
    return "", ""


def home_directory_checks(lookup: "UserLookup") -> list[Check]:
    """Can this user's session actually start?

    Authentication and a usable session are different things.  On the verified
    host a Smart Card login succeeded and GNOME showed a black screen, because
    no home directory existed and nothing was configured to create one.
    """
    checks: list[Check] = []
    if not is_linux():
        return checks

    module, pam_file = home_provisioning()
    if module:
        checks.append(
            Check(
                "home provisioning",
                "PASS",
                f"{module} in /etc/pam.d/{pam_file} creates missing home directories",
            )
        )
    else:
        checks.append(
            Check(
                "home provisioning",
                "WARN",
                "no pam_mkhomedir.so or pam_oddjob_mkhomedir.so in "
                + ", ".join(f"/etc/pam.d/{f}" for f in PAM_SESSION_FILES),
                hint="fallback_homedir in sssd.conf only names the path; nothing "
                "creates it. The first login of every domain user then succeeds and "
                "lands in a session with no writable home -- a black screen under "
                "GNOME. On Ubuntu/Debian: pam-auth-update --enable mkhomedir. On "
                "RHEL: authselect enable-feature with-mkhomedir (and enable "
                "oddjobd).",
            )
        )

    if not lookup.resolved or not lookup.home:
        return checks

    home = Path(lookup.home)
    try:
        exists = home.is_dir()
    except OSError as exc:
        checks.append(
            Check("home directory", "WARN", f"cannot stat {home}: {exc}")
        )
        return checks

    if not exists:
        checks.append(
            Check(
                "home directory",
                "PASS" if module else "FAIL",
                f"{home} does not exist"
                + (
                    " -- it will be created on first login"
                    if module
                    else " and nothing will create it"
                ),
                hint=""
                if module
                else f"Either enable home provisioning above, or create it: "
                f"install -d -m 0700 -o {lookup.uid} -g {lookup.gid} '{home}'",
            )
        )
        return checks

    detail = str(home)
    status = "PASS"
    hint = ""
    try:
        stat = home.stat()
        owned = lookup.uid is not None and str(stat.st_uid) == str(lookup.uid)
        mode = stat.st_mode & 0o777
        detail = f"{home} (mode {oct(mode)}, uid {stat.st_uid})"
        if not owned:
            status = "FAIL"
            detail += f" but the account's uid is {lookup.uid}"
            hint = (
                "The user cannot write to their own home, so the session will "
                f"start and then fail. Fix with: chown -R {lookup.uid}:{lookup.gid} "
                f"'{home}'"
            )
        elif mode & 0o077:
            status = "WARN"
            hint = (
                "Other users on this host can read this home directory. "
                f"chmod 0700 '{home}' unless that is intended."
            )
    except OSError as exc:
        status = "WARN"
        detail = f"{home} exists but cannot be inspected: {exc}"

    checks.append(Check("home directory", status, detail, hint=hint))
    return checks


# ---------------------------------------------------------------------------
# PAM
# ---------------------------------------------------------------------------


@dataclass
class PamReport:
    """Read-only view of the PAM stack, plus what it implies."""

    files: dict[str, str] = field(default_factory=dict)
    uses_pam_sss: bool = False
    #: "required" (card only), "optional" (card or password), or "off".
    cert_auth_mode: str = "off"
    authselect_profile: str = ""
    authselect_features: list[str] = field(default_factory=list)
    #: ``local_auth_policy`` per domain section, as read from sssd.conf.
    local_auth_policy: dict[str, str] = field(default_factory=dict)
    checks: list[Check] = field(default_factory=list)

    @property
    def require_cert_auth(self) -> bool:
        """True when the PAM stack accepts nothing but a card."""
        return self.cert_auth_mode == "required"

    @property
    def cert_auth_enabled(self) -> bool:
        return self.cert_auth_mode in ("required", "optional")

    def to_dict(self) -> dict:
        return {
            "files_examined": sorted(self.files),
            "uses_pam_sss": self.uses_pam_sss,
            "cert_auth_mode": self.cert_auth_mode,
            "require_cert_auth": self.require_cert_auth,
            "authselect_profile": self.authselect_profile,
            "authselect_features": self.authselect_features,
            "local_auth_policy": dict(self.local_auth_policy),
            "checks": [
                {"name": c.name, "status": c.status, "detail": c.detail, "hint": c.hint}
                for c in self.checks
            ],
        }


def local_auth_policy_checks(
    config_path: str | Path = DEFAULT_CONFIG,
) -> tuple[dict[str, str], list[Check]]:
    """Report whether SSSD may authenticate a Smart Card locally.

    This is the layer that makes a perfectly configured card still ask for a
    password.  ``local_auth_policy`` defaults to ``match``, i.e. "offer what the
    backend offers", and the AD and LDAP backends offer no Smart Card
    authentication of their own -- so the card is read, the certificate is
    verified, the certmap rule maps it to a real user, and SSSD then declines:

        [pam] [pam_reply] Local auth policy allowed: smartcard [False]

    Diagnosing that previously meant raising ``debug_level`` on a production
    host, so it is a check now.
    """
    from ..model.profile import AuthenticationSpec

    policies: dict[str, str] = {}
    checks: list[Check] = []
    try:
        config = SssdConfig.load(config_path)
    except OSError as exc:
        return policies, [
            Check("local_auth_policy", "WARN", f"cannot read {config_path}: {exc}")
        ]

    names = config.domain_sections()
    if not names:
        return policies, checks

    for name in names:
        section = f"domain/{name}"
        value = config.get(section, "local_auth_policy")
        if value:
            policies[name] = value
        enabled = AuthenticationSpec.policy_enables_smartcard(value)
        if enabled:
            checks.append(
                Check(
                    f"local_auth_policy {name}",
                    "PASS",
                    f"{value} -- SSSD may authenticate the card locally",
                )
            )
            continue
        provider = (config.get(section, "id_provider") or "").strip().lower()
        affected = provider in ("ad", "ldap") or not provider
        checks.append(
            Check(
                f"local_auth_policy {name}",
                "FAIL" if affected else "WARN",
                (value or "unset, so the default 'match' applies")
                + f" -- local Smart Card authentication is off (id_provider={provider or 'unknown'})",
                hint="SSSD will read and verify the card and then still ask for a "
                "password. Add 'local_auth_policy = enable:smartcard' to the domain "
                "section, or let the tool do it with authentication.local_smartcard: "
                "true in the profile. Needs SSSD 2.9.3 or newer.",
            )
        )
    return policies, checks


def pam_report(config_path: str | Path = DEFAULT_CONFIG) -> PamReport:
    """Inspect the PAM stack. This function never writes anything."""
    report = PamReport()
    if not is_linux():
        report.checks.append(Check("pam", "SKIP", "PAM inspection requires the SSSD host"))
        return report

    for name in PAM_FILES:
        path = PAM_DIR / name
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            report.checks.append(Check(f"pam:{name}", "WARN", f"cannot read {path}: {exc}"))
            continue
        report.files[name] = text
        for line in text.splitlines():
            if line.lstrip().startswith("#"):
                continue
            if "pam_sss.so" in line:
                report.uses_pam_sss = True
                # require_cert_auth means card only; try_cert_auth means card
                # first with a password fallback. "required" wins if both
                # somehow appear, because that is the restrictive reading.
                if "require_cert_auth" in line:
                    report.cert_auth_mode = "required"
                elif "try_cert_auth" in line and report.cert_auth_mode == "off":
                    report.cert_auth_mode = "optional"

    if report.uses_pam_sss:
        report.checks.append(
            Check("pam_sss", "PASS", "pam_sss.so is present in the PAM stack")
        )
    else:
        report.checks.append(
            Check(
                "pam_sss",
                "FAIL",
                "pam_sss.so was not found in any inspected PAM file",
                hint="Smart Card authentication goes through pam_sss. On RHEL-like "
                "systems run: authselect select sssd with-smartcard",
            )
        )

    if which("authselect"):
        current = run(["authselect", "current"], timeout=20)
        if current.ok:
            text = current.stdout
            first = text.splitlines()[0] if text.splitlines() else ""
            report.authselect_profile = first.replace("Profile ID:", "").strip()
            report.authselect_features = [
                line.strip("- ").strip()
                for line in text.splitlines()[1:]
                if line.strip().startswith("-")
            ]
            has_smartcard = any(
                "smartcard" in f for f in report.authselect_features
            )
            report.checks.append(
                Check(
                    "authselect",
                    "PASS" if has_smartcard else "WARN",
                    f"{report.authselect_profile} "
                    + (
                        "with " + ", ".join(report.authselect_features)
                        if report.authselect_features
                        else "(no features enabled)"
                    ),
                    hint=""
                    if has_smartcard
                    else "authselect enable-feature with-smartcard",
                )
            )
        else:
            report.checks.append(
                Check("authselect", "WARN", current.output or "authselect current failed")
            )
    else:
        report.checks.append(
            Check(
                "authselect",
                "SKIP",
                "authselect is not installed; the PAM stack is managed some other way",
            )
        )

    # The question the operator actually has: is card login switched on in PAM?
    # Reporting only "pam_sss.so is present" cannot answer it, because the plain
    # password profile puts pam_sss there too.
    if report.cert_auth_mode == "required":
        report.checks.append(
            Check(
                "card authentication",
                "PASS",
                "pam_sss.so require_cert_auth -- Smart Card ONLY; password login is "
                "disabled for the affected services",
                hint="Keep a root session open until you have confirmed a card login.",
            )
        )
    elif report.cert_auth_mode == "optional":
        report.checks.append(
            Check(
                "card authentication",
                "PASS",
                "pam_sss.so try_cert_auth -- card first, password still accepted",
            )
        )
    else:
        report.checks.append(
            Check(
                "card authentication",
                "WARN",
                "no try_cert_auth or require_cert_auth in the PAM stack: card login "
                "is not switched on",
                hint="On Ubuntu 23.10+: pam-auth-update --enable "
                "sss-smart-card-optional. Note that pam_sss.so being present is not "
                "enough -- the plain password profile installs it too.",
            )
        )

    # PAM can be perfect and the card still refused one layer down.
    report.local_auth_policy, policy_checks = local_auth_policy_checks(config_path)
    report.checks.extend(policy_checks)
    return report
