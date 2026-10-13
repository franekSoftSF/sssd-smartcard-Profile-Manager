"""Kerberos: is a TGT actually issued for this card?

Smart Card logon on a domain member is only half done when PAM says "ok".  The
point of the exercise is a Kerberos ticket: SSSD hands the card to
``krb5_child``, which performs PKINIT against the KDC, and the user ends up
with a TGT in their credential cache.  If that last step fails the user is
logged in but cannot reach a single Kerberised service.

This module answers three questions, in increasing order of confidence:

1. Is the Kerberos client configured and is the KDC reachable?
2. Does a credential cache currently hold a TGT, and for whom?
3. Does a live PKINIT exchange with the card actually produce a TGT?

Question 3 is the real test.  It runs ``kinit -X X509_user_identity=PKCS11:...``
with the terminal attached, so the PIN is typed directly into kinit -- this
process never sees, buffers or stores it.
"""

from __future__ import annotations

import datetime as _dt
import os
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path

from ..util import Check, CommandResult, is_linux, run, run_interactive, which
from ..x509.inspect import CertificateInfo

KRB5_CONF = "/etc/krb5.conf"

#: Where SSSD writes the Kerberos snippets it manages.  They only take effect
#: if krb5.conf actually includes the directory.
SSSD_KRB5_INCLUDE_DIR = "/var/lib/sss/pubconf/krb5.include.d"
DEFAULT_KDC_PORT = 88


# ---------------------------------------------------------------------------
# Credential cache
# ---------------------------------------------------------------------------


@dataclass
class Ticket:
    """One entry in the credential cache."""

    service: str
    valid_from: str = ""
    expires: str = ""
    renew_until: str = ""
    flags: str = ""

    @property
    def is_tgt(self) -> bool:
        return self.service.startswith("krbtgt/")

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "valid_from": self.valid_from,
            "expires": self.expires,
            "renew_until": self.renew_until,
            "flags": self.flags,
            "is_tgt": self.is_tgt,
        }


@dataclass
class CredentialCache:
    """What ``klist`` reports."""

    available: bool = False
    cache_name: str = ""
    principal: str = ""
    tickets: list[Ticket] = field(default_factory=list)
    raw: str = ""
    error: str = ""

    @property
    def tgt(self) -> Ticket | None:
        for ticket in self.tickets:
            if ticket.is_tgt:
                return ticket
        return None

    @property
    def realm(self) -> str:
        if "@" in self.principal:
            return self.principal.rsplit("@", 1)[1]
        return ""

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "cache": self.cache_name,
            "principal": self.principal,
            "realm": self.realm,
            "has_tgt": self.tgt is not None,
            "tickets": [t.to_dict() for t in self.tickets],
            "error": self.error,
        }


_TICKET_RE = re.compile(
    r"^(?P<from>\S+\s+\S+)\s+(?P<to>\S+\s+\S+)\s+(?P<service>\S+)\s*$"
)


def read_ccache(cache: str | None = None) -> CredentialCache:
    """Parse ``klist -f`` for the current (or given) credential cache."""
    out = CredentialCache()
    argv = ["klist", "-f"]
    if cache:
        argv += ["-c", cache]
    result = run(argv, timeout=20)
    out.raw = result.output
    if not result.found:
        out.error = "klist not found; install krb5-workstation / krb5-user"
        return out
    if not result.ok:
        out.error = result.output.strip() or "no credential cache"
        return out

    out.available = True
    current: Ticket | None = None
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("ticket cache:"):
            out.cache_name = stripped.split(":", 1)[1].strip()
        elif stripped.lower().startswith("default principal:"):
            out.principal = stripped.split(":", 1)[1].strip()
        elif stripped.lower().startswith("renew until"):
            if current:
                current.renew_until = stripped[len("renew until") :].strip()
        elif stripped.startswith("Flags:"):
            if current:
                current.flags = stripped.split(":", 1)[1].strip()
        else:
            match = _TICKET_RE.match(line.rstrip())
            if match and "/" in match.group("service") or (
                match and "@" in match.group("service")
            ):
                current = Ticket(
                    service=match.group("service"),
                    valid_from=match.group("from"),
                    expires=match.group("to"),
                )
                out.tickets.append(current)
    return out


def default_ccache_name() -> str:
    """Where the ccache lives, as the environment and krb5.conf see it."""
    env = os.environ.get("KRB5CCNAME")
    if env:
        return env
    text = _read_krb5_conf()
    match = re.search(r"^\s*default_ccache_name\s*=\s*(\S+)", text, re.MULTILINE)
    return match.group(1) if match else "(krb5 default: FILE:/tmp/krb5cc_<uid>)"


# ---------------------------------------------------------------------------
# Client configuration and KDC reachability
# ---------------------------------------------------------------------------


def _read_krb5_conf(path: str = KRB5_CONF) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def default_realm(path: str = KRB5_CONF) -> str:
    match = re.search(r"^\s*default_realm\s*=\s*(\S+)", _read_krb5_conf(path), re.MULTILINE)
    return match.group(1) if match else ""


def included_dirs(path: str = KRB5_CONF) -> list[str]:
    """Directories krb5.conf pulls in with ``includedir``."""
    return re.findall(
        r"^\s*includedir\s+(\S+)", _read_krb5_conf(path), re.MULTILINE
    )


def sssd_snippets(directory: str = SSSD_KRB5_INCLUDE_DIR) -> list[str]:
    """Snippet files SSSD has written, if the directory is readable."""
    try:
        return sorted(p.name for p in Path(directory).iterdir() if p.is_file())
    except OSError:
        return []


def pkinit_anchors_configured(path: str = KRB5_CONF) -> list[str]:
    """``pkinit_anchors`` values from krb5.conf and every directory it includes."""
    texts = [_read_krb5_conf(path)]
    for directory in included_dirs(path):
        try:
            for child in sorted(Path(directory).iterdir()):
                if child.is_file():
                    texts.append(child.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    found: list[str] = []
    for text in texts:
        found.extend(
            re.findall(r"^\s*pkinit_anchors\s*=\s*(\S+)", text, re.MULTILINE)
        )
    return found


#: Where MIT Kerberos keeps its pre-authentication plugins.  PKINIT lives in
#: a separate package on every distribution we support, and without it kinit
#: silently falls back to password pre-authentication.
PREAUTH_PLUGIN_DIRS = (
    "/usr/lib/x86_64-linux-gnu/krb5/plugins/preauth",
    "/usr/lib/aarch64-linux-gnu/krb5/plugins/preauth",
    "/usr/lib64/krb5/plugins/preauth",
    "/usr/lib/krb5/plugins/preauth",
)

#: Package that ships ``pkinit.so``, per packaging family.
PKINIT_PACKAGE = {
    "debian": "krb5-pkinit",
    "rhel": "krb5-pkinit",
}


def pkinit_plugin_path() -> str:
    """Path to MIT's ``pkinit.so``, or "" when the plugin is not installed."""
    for directory in PREAUTH_PLUGIN_DIRS:
        candidate = Path(directory) / "pkinit.so"
        try:
            if candidate.is_file():
                return str(candidate)
        except OSError:
            continue
    return ""


def pkinit_package_hint(distro=None) -> str:
    """The install command for the PKINIT plugin on this distribution.

    Detects the distribution itself when none is passed, so every caller gets a
    command that actually exists on the host rather than a generic sentence.
    """
    if distro is None:
        try:
            from ..platform import detect_distro

            distro = detect_distro()
        except Exception:  # pragma: no cover - best effort
            distro = None
    family = getattr(distro, "family", "") if distro is not None else ""
    if family in ("rhel", "fedora", "centos"):
        return "dnf install -y krb5-pkinit"
    if family in ("debian", "ubuntu"):
        return "apt-get install -y krb5-pkinit"
    return "install the krb5-pkinit package (Debian/Ubuntu and RHEL both call it that)"


#: What a KRB5_TRACE line looks like when a preauth module produced the reply.
_TRACE_MODULE_OK = re.compile(
    r"Preauth module (?P<name>[\w-]+) \((?P<type>\d+)\) \(\w+\) returned: 0/"
)
#: The same line when the module failed -- this carries the actual reason.
_TRACE_MODULE_FAIL = re.compile(
    r"Preauth module (?P<name>[\w-]+) \((?P<type>\d+)\) \(\w+\) returned: "
    r"(?P<code>-?\d+)/(?P<message>.+)"
)
_TRACE_PLUGIN_LOAD_FAIL = re.compile(
    r"Error loading plugin module (?P<name>\w+):"
)


def interpret_trace(text: str) -> dict:
    """Read a KRB5_TRACE log and say which mechanism actually authenticated.

    A ticket in the cache proves only that *something* authenticated.  PKINIT
    uses PA-PK-AS-REQ (type 16); a password uses PA-ENC-TIMESTAMP (type 2).
    Reporting the first as proven when the second is what happened is exactly
    the mistake this function exists to prevent.
    """
    modules_ok = [m.group("name") for m in _TRACE_MODULE_OK.finditer(text)]
    load_failures = [m.group("name") for m in _TRACE_PLUGIN_LOAD_FAIL.finditer(text)]
    module_failures = [
        {
            "module": m.group("name"),
            "type": int(m.group("type")),
            "code": int(m.group("code")),
            "message": m.group("message").strip(),
        }
        for m in _TRACE_MODULE_FAIL.finditer(text)
        if m.group("code") != "0"
    ]
    # Any trace line the PKINIT code itself emitted: this is where the real
    # reason lives when PKINIT is attempted and then declines.
    pkinit_messages = [
        line.split(": ", 2)[-1].strip()
        for line in text.splitlines()
        if "PKINIT" in line or "pkinit" in line
    ]
    offered: list[str] = []
    match = re.search(r"Processing preauth types:\s*(?P<types>.+)", text)
    if match:
        offered = [t.strip() for t in match.group("types").split(",") if t.strip()]
    pkinit_failures = [f for f in module_failures if "pkinit" in f["module"].lower()]
    return {
        "modules_succeeded": modules_ok,
        "module_failures": module_failures,
        "pkinit_failures": pkinit_failures,
        "pkinit_messages": pkinit_messages,
        "plugin_load_failures": load_failures,
        "offered": offered,
        "kdc_offers_pkinit": any("PA-PK-AS-REQ" in t for t in offered),
        "used_pkinit": any("pkinit" in name.lower() for name in modules_ok),
        "used_password": any(
            "encrypted_timestamp" in name.lower() or "enc-timestamp" in name.lower()
            for name in modules_ok
        ),
        "trace_available": bool(text.strip()),
    }


def configured_kdcs(realm: str, path: str = KRB5_CONF) -> list[str]:
    """KDCs listed for *realm* in krb5.conf (SSSD hosts often rely on DNS)."""
    text = _read_krb5_conf(path)
    block = re.search(
        rf"^\s*{re.escape(realm)}\s*=\s*\{{(?P<body>.*?)^\s*\}}",
        text,
        re.MULTILINE | re.DOTALL,
    )
    if not block:
        return []
    return re.findall(r"^\s*kdc\s*=\s*(\S+)", block.group("body"), re.MULTILINE)


def discover_kdcs(realm: str) -> list[str]:
    """Look up ``_kerberos._tcp.<realm>`` with whatever resolver is available."""
    if not realm:
        return []
    name = f"_kerberos._tcp.{realm.lower()}"
    for argv in (
        ["dig", "+short", "SRV", name],
        ["host", "-t", "SRV", name],
        ["nslookup", "-type=SRV", name],
    ):
        result = run(argv, timeout=15)
        if not result.ok:
            continue
        hosts: list[str] = []
        for line in result.stdout.splitlines():
            match = re.search(r"(\S+?)\.?$", line.strip())
            fields = line.split()
            if len(fields) >= 4 and fields[-1].endswith("."):
                hosts.append(fields[-1].rstrip("."))
            elif match and argv[0] == "dig" and len(fields) == 4:
                hosts.append(fields[3].rstrip("."))
        if hosts:
            return sorted(set(hosts))
    return []


def probe_kdc(host: str, port: int = DEFAULT_KDC_PORT, timeout: float = 3.0) -> tuple[bool, str]:
    """Plain TCP reachability check against a KDC."""
    target = host
    if ":" in host and not host.startswith("["):
        target, _, port_text = host.rpartition(":")
        try:
            port = int(port_text)
        except ValueError:
            target = host
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return True, f"{target}:{port} reachable"
    except OSError as exc:
        return False, f"{target}:{port} unreachable ({exc})"


# ---------------------------------------------------------------------------
# PKINIT
# ---------------------------------------------------------------------------


def pkinit_command(
    principal: str,
    *,
    module: str,
    anchors: str | None = None,
    cache: str | None = None,
    cert_id: str | None = None,
    enterprise: bool = False,
) -> list[str]:
    """Build the ``kinit`` command that proves the KDC issues a ticket.

    ``-X X509_user_identity=PKCS11:<module>`` is MIT Kerberos's PKINIT
    pre-authentication option; ``-X X509_anchors=FILE:<pem>`` points it at the
    CA bundle that must validate the KDC's own certificate.
    """
    identity = f"PKCS11:{module}"
    if cert_id:
        identity += f":slotid=:id={cert_id}"
    argv = ["kinit"]
    if enterprise:
        # AD accepts a UPN as an enterprise principal name.
        argv.append("-E")
    if cache:
        argv += ["-c", cache]
    argv += ["-X", f"X509_user_identity={identity}"]
    if anchors:
        argv += ["-X", f"X509_anchors=FILE:{anchors}"]
    argv.append(principal)
    return argv


@dataclass
class PkinitResult:
    """Outcome of a live PKINIT attempt."""

    attempted: bool = False
    succeeded: bool = False
    command: list[str] = field(default_factory=list)
    cache: str = ""
    ticket: CredentialCache | None = None
    error: str = ""
    #: What KRB5_TRACE says actually authenticated -- see :func:`interpret_trace`.
    mechanism: dict = field(default_factory=dict)

    @property
    def proven_pkinit(self) -> bool:
        """True only when the trace shows PKINIT produced the reply.

        A ticket plus exit status 0 is *not* enough: if the PKINIT plugin is
        missing, kinit ignores ``-X X509_user_identity`` and authenticates with
        a password instead, which also yields a perfectly valid TGT.
        """
        return bool(self.succeeded and self.mechanism.get("used_pkinit"))

    @property
    def fell_back_to_password(self) -> bool:
        return bool(self.succeeded and self.mechanism.get("used_password"))

    def to_dict(self) -> dict:
        return {
            "attempted": self.attempted,
            "succeeded": self.succeeded,
            "proven_pkinit": self.proven_pkinit,
            "fell_back_to_password": self.fell_back_to_password,
            "mechanism": dict(self.mechanism),
            "command": " ".join(self.command),
            "cache": self.cache,
            "ticket": self.ticket.to_dict() if self.ticket else None,
            "error": self.error,
        }


def run_pkinit(
    principal: str,
    *,
    module: str,
    anchors: str | None = None,
    cert_id: str | None = None,
    enterprise: bool = False,
    cache: str | None = None,
) -> PkinitResult:
    """Obtain a TGT with the card, into a throwaway cache.

    A dedicated FILE: cache is used so the operator's own ticket is never
    overwritten by a test.  The PIN prompt belongs to kinit; this function
    inherits the terminal and captures nothing.
    """
    import tempfile

    own_cache = cache or os.path.join(
        tempfile.gettempdir(), f"sssd-smartcard-krb5cc-{os.getpid()}"
    )
    cache_spec = own_cache if ":" in own_cache else f"FILE:{own_cache}"
    argv = pkinit_command(
        principal,
        module=module,
        anchors=anchors,
        cache=cache_spec,
        cert_id=cert_id,
        enterprise=enterprise,
    )
    out = PkinitResult(attempted=True, command=argv, cache=cache_spec)
    if not which("kinit"):
        out.error = "kinit not found; install krb5-workstation / krb5-user"
        return out

    # Refuse to run at all without the PKINIT plugin.  kinit would ignore
    # -X X509_user_identity, prompt "Password for <principal>" and authenticate
    # with the account password -- so a card test would quietly harvest a
    # password and then report success.  Never do that.
    if not pkinit_plugin_path():
        out.attempted = False
        out.error = (
            "MIT Kerberos has no PKINIT plugin installed (pkinit.so is missing "
            f"from {', '.join(PREAUTH_PLUGIN_DIRS)}), so kinit would ignore the "
            "card, ask for the account password instead and still return a valid "
            "ticket. Not running it. Install the plugin first: "
            + pkinit_package_hint()
        )
        return out

    import tempfile as _tempfile

    trace_path = os.path.join(
        _tempfile.gettempdir(), f"sssd-smartcard-krb5trace-{os.getpid()}"
    )
    result: CommandResult = run_interactive(
        argv, timeout=300, env={"KRB5_TRACE": trace_path}
    )
    try:
        trace_text = Path(trace_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        trace_text = ""
    finally:
        try:
            os.unlink(trace_path)
        except OSError:
            pass
    out.mechanism = interpret_trace(trace_text)

    if result.returncode != 0:
        out.error = f"kinit exited with status {result.returncode}"
        return out
    out.succeeded = True
    out.ticket = read_ccache(cache_spec)
    if out.fell_back_to_password:
        out.error = (
            "a ticket was issued, but KRB5_TRACE shows it came from "
            "PA-ENC-TIMESTAMP (password pre-authentication), not from the card. "
            "The card was not used."
        )
    elif not out.mechanism.get("trace_available"):
        out.error = (
            "a ticket was issued, but KRB5_TRACE produced nothing, so which "
            "mechanism authenticated could not be confirmed."
        )
    return out


def destroy_cache(cache: str) -> CommandResult:
    return run(["kdestroy", "-c", cache], timeout=20)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------


@dataclass
class KerberosReport:
    realm: str = ""
    kdcs: list[str] = field(default_factory=list)
    ccache: CredentialCache = field(default_factory=CredentialCache)
    pkinit: PkinitResult | None = None
    #: The certificate the KDC presents, when PKINIT was asked about.
    kdc_certificate: object | None = None
    suggested_command: list[str] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(c.failed for c in self.checks)

    def to_dict(self) -> dict:
        return {
            "realm": self.realm,
            "kdcs": self.kdcs,
            "ccache": self.ccache.to_dict(),
            "pkinit": self.pkinit.to_dict() if self.pkinit else None,
            "kdc_certificate": (
                self.kdc_certificate.to_dict() if self.kdc_certificate else None
            ),
            "suggested_command": " ".join(self.suggested_command),
            "checks": [
                {"name": c.name, "status": c.status, "detail": c.detail, "hint": c.hint}
                for c in self.checks
            ],
        }


def certificate_pkinit_readiness(cert: CertificateInfo) -> list[Check]:
    """Check the card certificate for what a KDC needs to accept it."""
    checks: list[Check] = []
    from ..x509.inspect import OID_MS_SMARTCARD_LOGON
    from cryptography.x509.oid import ExtendedKeyUsageOID

    eku = cert.eku_oids
    has_client = ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string in eku
    has_sclogon = OID_MS_SMARTCARD_LOGON.dotted_string in eku
    checks.append(
        Check(
            "certificate EKU",
            "PASS" if (has_client or has_sclogon) else "FAIL",
            ", ".join(cert.eku_labels) or "(none)",
            hint=""
            if (has_client or has_sclogon)
            else "An Active Directory KDC requires the Smart Card Logon EKU "
            "(1.3.6.1.4.1.311.20.2.2) on the client certificate.",
        )
    )
    if not has_sclogon:
        checks.append(
            Check(
                "Smart Card Logon EKU",
                "WARN",
                "not present",
                hint="AD KDCs normally reject PKINIT without it, even though SSSD's "
                "local certificate check passes.",
            )
        )

    upn = cert.san.upn
    pkinit_san = cert.san.pkinit
    if upn:
        checks.append(Check("certificate principal", "PASS", f"SAN UPN {upn[0]}"))
    elif pkinit_san:
        checks.append(
            Check("certificate principal", "PASS", f"PKINIT principal {pkinit_san[0]}")
        )
    else:
        checks.append(
            Check(
                "certificate principal",
                "FAIL",
                "neither a UPN nor a PKINIT principal in the SAN",
                hint="The KDC maps the certificate to an account through one of these. "
                "Without it, PKINIT cannot identify the user.",
            )
        )

    if cert.expired:
        checks.append(
            Check("certificate validity", "FAIL", f"expired {cert.not_after:%Y-%m-%d}")
        )
    else:
        checks.append(
            Check(
                "certificate validity",
                "PASS",
                f"valid until {cert.not_after:%Y-%m-%d} ({cert.days_remaining}d)",
            )
        )
    return checks


def report(
    *,
    realm: str | None = None,
    principal: str | None = None,
    cert: CertificateInfo | None = None,
    module: str | None = None,
    anchors: str | None = None,
    cert_id: str | None = None,
    do_pkinit: bool = False,
    enterprise: bool = False,
    keep_cache: bool = False,
    sssd_config=None,
) -> KerberosReport:
    """Full Kerberos readiness report, optionally including a live PKINIT."""
    out = KerberosReport()

    if not is_linux():
        out.checks.append(
            Check("kerberos", "SKIP", "Kerberos checks require the SSSD host")
        )
        return out

    # -- client configuration ------------------------------------------
    out.realm = (realm or default_realm() or "").upper()
    if cert and not out.realm:
        for value in cert.san.upn + cert.san.pkinit:
            if "@" in value:
                out.realm = value.rsplit("@", 1)[1].upper()
                break
    out.checks.append(
        Check(
            "krb5 default_realm",
            "PASS" if out.realm else "FAIL",
            out.realm or f"not set in {KRB5_CONF}",
            hint="" if out.realm else "A domain-joined host normally has this from the "
            "join. Without a realm, no ticket can be requested.",
        )
    )

    # -- does krb5.conf actually use SSSD's snippets? -------------------
    # SSSD writes domain_realm and localauth_plugin into its own include
    # directory, but they do nothing unless krb5.conf includes it.  A host can
    # be fully joined and working without that line, because the realm comes
    # from default_realm and the KDC from DNS -- so this is quiet until you
    # need the snippets, which PKINIT configuration does.
    snippets = sssd_snippets()
    includes = included_dirs()
    uses_sssd_dir = any(
        d.rstrip("/") == SSSD_KRB5_INCLUDE_DIR.rstrip("/") for d in includes
    )
    if snippets and not uses_sssd_dir:
        out.checks.append(
            Check(
                "krb5 includedir",
                "WARN",
                f"{KRB5_CONF} does not include {SSSD_KRB5_INCLUDE_DIR}, so the "
                f"{len(snippets)} snippet(s) SSSD maintains there are inert "
                f"({', '.join(snippets)})",
                hint=f"Add 'includedir {SSSD_KRB5_INCLUDE_DIR}/' as the first line "
                "of krb5.conf. Card login does not need it -- that is local "
                "authentication -- but SSSD's realm mapping and localauth plugin do, "
                "and so does anything you configure through those snippets.",
            )
        )
    elif uses_sssd_dir:
        out.checks.append(
            Check(
                "krb5 includedir",
                "PASS",
                f"{SSSD_KRB5_INCLUDE_DIR} is included"
                + (f" ({', '.join(snippets)})" if snippets else " (empty)"),
            )
        )

    # -- PKINIT trust anchors -------------------------------------------
    # Without these the client cannot validate the KDC's certificate, so a
    # ticket is impossible no matter how good the user certificate is.
    anchor_values = pkinit_anchors_configured()
    if anchor_values:
        out.checks.append(
            Check("pkinit_anchors", "PASS", ", ".join(anchor_values))
        )
    else:
        out.checks.append(
            Check(
                "pkinit_anchors",
                "WARN" if do_pkinit else "INFO",
                f"no pkinit_anchors in {KRB5_CONF} or any included directory",
                hint="Needed only for PKINIT, which is what issues a Kerberos TGT. "
                "Smart Card login itself is local and does not use it. To enable "
                "PKINIT the client needs the CA that signed the KDC certificate, "
                "e.g. pkinit_anchors = FILE:/etc/sssd/pki/sssd_auth_ca_db.pem in "
                "[libdefaults] or the realm block -- and the KDC needs a "
                "certificate of its own, which many AD and Samba deployments do "
                "not have.",
            )
        )

    if sssd_config is not None:
        for domain in sssd_config.domain_sections():
            section = f"domain/{domain}"
            for key in ("krb5_realm", "krb5_server", "auth_provider", "id_provider"):
                value = sssd_config.get(section, key)
                if value:
                    out.checks.append(Check(f"[{section}] {key}", "INFO", value))
            enterprise_setting = sssd_config.get(section, "krb5_use_enterprise_principal")
            if enterprise_setting:
                out.checks.append(
                    Check(
                        f"[{section}] krb5_use_enterprise_principal",
                        "INFO",
                        enterprise_setting,
                        hint="With AD, enterprise principals let a UPN be used directly "
                        "as the Kerberos client name.",
                    )
                )

    # -- KDC reachability ----------------------------------------------
    if out.realm:
        out.kdcs = configured_kdcs(out.realm) or discover_kdcs(out.realm)
        if not out.kdcs:
            out.checks.append(
                Check(
                    "KDC discovery",
                    "WARN",
                    f"no kdc= entry for {out.realm} in {KRB5_CONF} and no "
                    f"_kerberos._tcp.{out.realm.lower()} SRV record resolved",
                    hint="SSSD can still locate the KDC through its own AD site "
                    "discovery, so this is not always fatal.",
                )
            )
        else:
            out.checks.append(Check("KDC discovery", "PASS", ", ".join(out.kdcs)))
            for host in out.kdcs[:3]:
                reachable, detail = probe_kdc(host)
                out.checks.append(
                    Check(
                        f"KDC {host}",
                        "PASS" if reachable else "FAIL",
                        detail,
                        hint="" if reachable else "Check firewall and DNS; PKINIT needs "
                        "TCP/88 (and often UDP/88) to the KDC.",
                    )
                )

    # -- existing ticket ------------------------------------------------
    out.ccache = read_ccache()
    ccache_label = default_ccache_name()
    if out.ccache.available and out.ccache.tgt:
        tgt = out.ccache.tgt
        out.checks.append(
            Check(
                "credential cache",
                "PASS",
                f"{out.ccache.principal} in {out.ccache.cache_name or ccache_label}",
            )
        )
        out.checks.append(
            Check(
                "TGT",
                "PASS",
                f"{tgt.service} expires {tgt.expires}"
                + (f", flags {tgt.flags}" if tgt.flags else ""),
            )
        )
    elif out.ccache.available:
        out.checks.append(
            Check(
                "TGT",
                "WARN",
                f"cache {out.ccache.cache_name} holds no krbtgt ticket",
                hint="The session authenticated, but no ticket-granting ticket was "
                "issued -- Kerberised services will fail.",
            )
        )
    else:
        out.checks.append(
            Check(
                "credential cache",
                "INFO",
                out.ccache.error or "no ticket in this shell",
                hint=f"Expected location: {ccache_label}. Run this as the logged-in "
                "user, in their session, to see their ticket.",
            )
        )

    # -- certificate suitability ---------------------------------------
    if cert is not None:
        out.checks.extend(certificate_pkinit_readiness(cert))

    # -- live PKINIT ----------------------------------------------------
    target_principal = principal
    if not target_principal and cert is not None:
        candidates = cert.san.pkinit + cert.san.upn
        target_principal = candidates[0] if candidates else None

    # The KDC's half of PKINIT.  Only worth the TLS round trip when PKINIT is
    # actually being asked about, since it reaches out over the network.
    if do_pkinit and out.kdcs:
        from .kdccert import fetch_kdc_certificate, kdc_certificate_checks

        out.kdc_certificate = fetch_kdc_certificate(out.kdcs[0])
        out.checks.extend(kdc_certificate_checks(out.kdc_certificate))

    plugin = pkinit_plugin_path()
    out.checks.append(
        Check(
            "PKINIT plugin",
            "PASS" if plugin else ("FAIL" if do_pkinit else "WARN"),
            plugin
            or "pkinit.so is not installed; MIT Kerberos cannot do PKINIT at all",
            hint=""
            if plugin
            else "Without it kinit ignores -X X509_user_identity, prompts for the "
            "account PASSWORD instead of the card PIN, and still returns a valid "
            "ticket -- which looks like success. Install it: "
            + pkinit_package_hint(),
        )
    )

    if target_principal:
        chosen_module = module
        if chosen_module is None:
            try:
                from ..pkcs11.detect import pick_module

                chosen_module = pick_module(None)
            except Exception:
                chosen_module = ""
        use_enterprise = enterprise or (
            bool(cert and cert.san.upn and not cert.san.pkinit)
        )
        out.suggested_command = pkinit_command(
            target_principal,
            module=chosen_module,
            anchors=anchors,
            enterprise=use_enterprise,
        )
        if do_pkinit:
            out.pkinit = run_pkinit(
                target_principal,
                module=chosen_module,
                anchors=anchors,
                cert_id=cert_id,
                enterprise=use_enterprise,
            )
            kdc_offers = out.pkinit.mechanism.get("kdc_offers_pkinit")
            if out.pkinit.fell_back_to_password:
                # A valid TGT, obtained the wrong way.  Reporting this as a
                # PKINIT pass would be a false positive of the worst kind: the
                # card was never used and a password was typed instead.
                out.checks.append(
                    Check(
                        "PKINIT",
                        "FAIL",
                        out.pkinit.error,
                        hint="The ticket is real but the card did not produce it. "
                        + (
                            "The KDC does offer PA-PK-AS-REQ, so the gap is on this "
                            "client: "
                            if kdc_offers
                            else "Check that the KDC offers PA-PK-AS-REQ at all: "
                        )
                        + pkinit_package_hint()
                        + ". Destroy the ticket you just obtained with kdestroy.",
                    )
                )
            elif out.pkinit.proven_pkinit and out.pkinit.ticket and out.pkinit.ticket.tgt:
                tgt = out.pkinit.ticket.tgt
                out.checks.append(
                    Check(
                        "PKINIT",
                        "PASS",
                        f"the card obtained {tgt.service} for "
                        f"{out.pkinit.ticket.principal}, expires {tgt.expires} "
                        "(KRB5_TRACE confirms PA-PK-AS-REQ)",
                    )
                )
            elif out.pkinit.succeeded and out.pkinit.ticket and out.pkinit.ticket.tgt:
                tgt = out.pkinit.ticket.tgt
                out.checks.append(
                    Check(
                        "PKINIT",
                        "WARN",
                        f"a TGT was issued ({tgt.service}) but KRB5_TRACE did not "
                        "confirm that PKINIT produced it",
                        hint=out.pkinit.error
                        or "Re-run with KRB5_TRACE=/dev/stderr and check which "
                        "preauth module returned 0.",
                    )
                )
            elif out.pkinit.succeeded:
                out.checks.append(
                    Check(
                        "PKINIT",
                        "WARN",
                        "kinit succeeded but no TGT was found in the test cache",
                    )
                )
            else:
                # The trace knows why.  Report that instead of a list of
                # maybes -- guessing at causes when the reason was captured is
                # how a diagnosis gets buried.
                detail = out.pkinit.error or "kinit failed"
                reasons = [
                    f"{f['module']} returned {f['code']}: {f['message']}"
                    for f in out.pkinit.mechanism.get("pkinit_failures", [])
                ]
                if reasons:
                    detail += " -- PKINIT said: " + "; ".join(reasons)
                elif out.pkinit.mechanism.get("module_failures"):
                    detail += " -- preauth modules reported: " + "; ".join(
                        f"{f['module']} {f['code']}/{f['message']}"
                        for f in out.pkinit.mechanism["module_failures"]
                    )
                if out.pkinit.attempted and not out.pkinit.mechanism.get(
                    "trace_available"
                ):
                    hint = (
                        "No KRB5_TRACE output was produced, so the reason could not "
                        "be read. Re-run by hand with KRB5_TRACE=/dev/stderr in front "
                        "of the command above."
                    )
                elif reasons or out.pkinit.mechanism.get("module_failures"):
                    hint = (
                        "That message is the reason, read straight from KRB5_TRACE. "
                        "If it mentions the KDC certificate, the CA in "
                        "pkinit_anchors does not validate it; if it mentions the "
                        "client certificate or principal, the KDC rejected the card's "
                        "certificate or its UPN."
                    )
                elif not out.pkinit.attempted:
                    hint = ""
                else:
                    hint = (
                        "Common causes: the KDC certificate is not validated by "
                        "X509_anchors, the client certificate lacks the Smart Card "
                        "Logon EKU, the account has no matching UPN, or the domain "
                        "controller has no KDC certificate at all."
                    )
                out.checks.append(Check("PKINIT", "FAIL", detail, hint=hint))
                for message in out.pkinit.mechanism.get("pkinit_messages", [])[:6]:
                    out.checks.append(Check("PKINIT trace", "INFO", message))
            if out.pkinit.attempted and not keep_cache:
                destroy_cache(out.pkinit.cache)
        else:
            out.checks.append(
                Check(
                    "PKINIT",
                    "SKIP",
                    "not attempted (pass --pkinit to obtain a real ticket)",
                    hint="Command: " + " ".join(out.suggested_command),
                )
            )
    else:
        out.checks.append(
            Check(
                "PKINIT",
                "SKIP",
                "no principal to request a ticket for",
                hint="Pass --principal user@REALM, or a certificate with --from-card.",
            )
        )

    return out
