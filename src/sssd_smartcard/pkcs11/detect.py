"""Smart Card / PKCS#11 discovery.

Everything here goes through the standard command line tools (``pcsc_scan``,
``opensc-tool``, ``p11-kit``, ``pkcs11-tool``) rather than binding a PKCS#11
module in-process.  That keeps the dependency surface small and, more
importantly, makes it obvious that the tool only ever asks for *certificates*:
every ``pkcs11-tool`` invocation below passes ``--type cert``.  Private key
objects are never read, exported or referenced, and no PIN is ever passed.
"""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..errors import PlatformUnsupported, ToolMissing
from ..util import Check, is_linux, run, service_or_socket_active, which
from ..x509.inspect import CertificateInfo, load_certificate

#: Where distributions put the OpenSC PKCS#11 module.
MODULE_CANDIDATES = (
    "/usr/lib64/pkcs11/opensc-pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib/pkcs11/opensc-pkcs11.so",
    "/usr/lib64/opensc-pkcs11.so",
    "/usr/lib/opensc-pkcs11.so",
    "/usr/local/lib/opensc-pkcs11.so",
)

#: p11-kit's proxy module, which fans out to every configured module.
P11_KIT_PROXY = (
    "/usr/lib64/pkcs11/p11-kit-proxy.so",
    "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-proxy.so",
    "/usr/lib/p11-kit-proxy.so",
)


@dataclass
class Reader:
    name: str
    card_present: bool = False
    detail: str = ""


@dataclass
class TokenSlot:
    slot_id: str = ""
    slot_description: str = ""
    token_label: str = ""
    manufacturer: str = ""
    model: str = ""
    serial: str = ""
    uri: str = ""

    def to_dict(self) -> dict:
        return {
            "slot_id": self.slot_id,
            "slot": self.slot_description,
            "token": self.token_label,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "serial": self.serial,
            "uri": self.uri,
        }


@dataclass
class CardCertificate:
    label: str
    object_id: str
    certificate: CertificateInfo | None = None
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "id": self.object_id,
            "error": self.error,
            "certificate": self.certificate.to_dict() if self.certificate else None,
        }


@dataclass
class CardScan:
    """The complete result of ``card detect``."""

    module: str | None = None
    modules_found: list[str] = field(default_factory=list)
    readers: list[Reader] = field(default_factory=list)
    slots: list[TokenSlot] = field(default_factory=list)
    certificates: list[CardCertificate] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "modules_found": self.modules_found,
            "readers": [
                {"name": r.name, "card_present": r.card_present, "detail": r.detail}
                for r in self.readers
            ],
            "slots": [s.to_dict() for s in self.slots],
            "certificates": [c.to_dict() for c in self.certificates],
            "checks": [
                {"name": c.name, "status": c.status, "detail": c.detail, "hint": c.hint}
                for c in self.checks
            ],
        }


# ---------------------------------------------------------------------------
# Module discovery
# ---------------------------------------------------------------------------


def find_modules() -> list[str]:
    """Every PKCS#11 module we can see, proxy first."""
    found: list[str] = []
    for path in P11_KIT_PROXY + MODULE_CANDIDATES:
        if os.path.exists(path) and path not in found:
            found.append(path)
    result = run(["p11-kit", "list-modules"], timeout=15)
    if result.ok:
        for match in re.finditer(r"^\s*path:\s*(\S+)", result.stdout, re.MULTILINE):
            path = match.group(1)
            if path not in found and os.path.exists(path):
                found.append(path)
    return found


def pick_module(explicit: str | None = None) -> str:
    """Choose the module to talk to."""
    if explicit:
        if not os.path.exists(explicit):
            raise ToolMissing(f"PKCS#11 module not found: {explicit}")
        return explicit
    env = os.environ.get("SSSD_SMARTCARD_PKCS11_MODULE")
    if env:
        return pick_module(env)
    modules = find_modules()
    if not modules:
        raise ToolMissing(
            "no PKCS#11 module found. Install opensc (and p11-kit), or pass "
            "--module /path/to/module.so"
        )
    return modules[0]


# ---------------------------------------------------------------------------
# Readers
# ---------------------------------------------------------------------------


def list_readers() -> tuple[list[Reader], list[Check]]:
    """Enumerate PC/SC readers and say whether a card is inserted."""
    readers: list[Reader] = []
    checks: list[Check] = []

    if not is_linux():
        checks.append(
            Check(
                "pcsc",
                "SKIP",
                "reader detection needs PC/SC, which this tool only drives on Linux",
            )
        )
        return readers, checks

    available, detail = service_or_socket_active("pcscd.service", "pcscd.socket")
    if available is None:
        checks.append(Check("pcscd", "SKIP", detail))
    else:
        checks.append(
            Check(
                "pcscd",
                "PASS" if available else "WARN",
                detail,
                hint="" if available else "systemctl enable --now pcscd.socket",
            )
        )

    result = run(["opensc-tool", "--list-readers"], timeout=20)
    if result.found and result.stdout.strip():
        for line in result.stdout.splitlines():
            line = line.rstrip()
            if not line or line.lower().startswith(("nr", "#", "no readers")):
                continue
            match = re.match(r"^\s*(\d+)\s+(\S*)\s+(.*)$", line)
            if not match:
                continue
            flags, name = match.group(2), match.group(3).strip()
            present = "card" in flags.lower() or "yes" in flags.lower()
            readers.append(Reader(name, present, line.strip()))
    if not readers:
        result = run(["pcsc_scan", "-r"], timeout=20)
        if result.found:
            for line in result.stdout.splitlines():
                match = re.match(r"^\s*\d+:\s*(.+)$", line)
                if match:
                    readers.append(Reader(match.group(1).strip()))

    if not readers:
        checks.append(
            Check(
                "readers",
                "FAIL" if which("opensc-tool") or which("pcsc_scan") else "SKIP",
                "no PC/SC reader detected",
                hint=no_reader_hint(short=True),
            )
        )
    else:
        checks.append(Check("readers", "PASS", f"{len(readers)} reader(s) detected"))
    return readers, checks


def unprivileged_on_linux() -> bool:
    """True when we are not root on a system where PC/SC needs authorisation."""
    return is_linux() and hasattr(os, "geteuid") and os.geteuid() != 0


#: Diagnosis for "pcscd is running, the reader is plugged in, and yet nothing
#: is visible". Observed on Ubuntu 24.04: pcsc-lite authorises clients through
#: polkit, and /usr/share/polkit-1/actions/org.debian.pcsc-lite.policy defaults
#: the access_pcsc action to allow_any=no, allow_inactive=no, allow_active=yes.
#: Only a session attached to a local seat counts as active, and an SSH session
#: has no seat -- so an unprivileged remote user is refused, and pcscd logs
#: "is NOT authorized for action: access_pcsc".
PRIVILEGE_HINT = (
    "You are not root. pcsc-lite authorises clients through the polkit action "
    "org.debian.pcsc-lite.access_pcsc, which by default only allows a session on "
    "a local seat -- an SSH session has no seat and is refused, even though "
    "pcscd is running and the reader is plugged in. Re-run with sudo, or run it "
    "from the machine's console. Check with: "
    "journalctl -u pcscd | grep access_pcsc"
)

HARDWARE_HINT = (
    "Check that the reader is attached and that pcscd sees it: "
    "systemctl status pcscd; opensc-tool --list-readers. In a VM, the reader "
    "has to be passed through to the guest."
)

#: The full explanation is printed once, on the "privileges" check. Repeating it
#: under every downstream failure buries the output.
SHORT_PRIVILEGE_HINT = (
    "Almost certainly the privileges warning above, not the hardware -- re-run "
    "with sudo."
)


def no_reader_hint(*, short: bool = False) -> str:
    if not unprivileged_on_linux():
        return HARDWARE_HINT
    return SHORT_PRIVILEGE_HINT if short else PRIVILEGE_HINT


# ---------------------------------------------------------------------------
# Tokens and certificates
# ---------------------------------------------------------------------------

_SLOT_RE = re.compile(r"^Slot\s+(\S+)\s*\(0x[0-9a-fA-F]+\)\s*:?\s*(.*)$")


def list_slots(module: str) -> list[TokenSlot]:
    """Parse ``pkcs11-tool --list-token-slots``."""
    result = run(["pkcs11-tool", "--module", module, "--list-token-slots"], timeout=30)
    if not result.found:
        raise ToolMissing(
            "pkcs11-tool not found; install opensc (Fedora/RHEL: opensc, "
            "Debian/Ubuntu: opensc-pkcs11)"
        )
    slots: list[TokenSlot] = []
    current: TokenSlot | None = None
    for line in result.stdout.splitlines():
        stripped = line.strip()
        match = _SLOT_RE.match(stripped)
        if match:
            current = TokenSlot(slot_id=match.group(1), slot_description=match.group(2))
            slots.append(current)
            continue
        if current is None or ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "token label":
            current.token_label = value
        elif key == "token manufacturer":
            current.manufacturer = value
        elif key == "token model":
            current.model = value
        elif key in ("token serial", "serial num", "token serial number"):
            current.serial = value
        elif key == "uri":
            current.uri = value
    return slots


_OBJECT_RE = re.compile(r"^\s*(label|ID):\s*(.*)$", re.IGNORECASE)


def list_certificates(module: str, *, slot: str | None = None) -> list[CardCertificate]:
    """List certificate objects on the token.

    Only ``--type cert`` is ever requested, so a private key is never touched.
    """
    argv = ["pkcs11-tool", "--module", module, "--list-objects", "--type", "cert"]
    if slot:
        argv += ["--slot", slot]
    result = run(argv, timeout=60)
    if not result.found:
        raise ToolMissing("pkcs11-tool not found; install opensc")
    certificates: list[CardCertificate] = []
    label = object_id = ""
    for line in result.stdout.splitlines():
        if line.strip().lower().startswith("certificate object"):
            if object_id or label:
                certificates.append(CardCertificate(label, object_id))
            label = object_id = ""
            continue
        match = _OBJECT_RE.match(line)
        if match:
            if match.group(1).lower() == "label":
                label = match.group(2).strip()
            else:
                object_id = match.group(2).strip()
    if object_id or label:
        certificates.append(CardCertificate(label, object_id))
    return certificates


def read_certificate(
    module: str, object_id: str, *, slot: str | None = None
) -> CertificateInfo:
    """Read one certificate object off the card, by ID."""
    with tempfile.TemporaryDirectory(prefix="sssd-smartcard-") as tmp:
        out = Path(tmp) / "cert.der"
        argv = [
            "pkcs11-tool",
            "--module",
            module,
            "--read-object",
            "--type",
            "cert",
            "--id",
            object_id,
            "--output-file",
            str(out),
        ]
        if slot:
            argv += ["--slot", slot]
        result = run(argv, timeout=60)
        if not result.ok or not out.exists():
            raise ToolMissing(
                f"could not read certificate id={object_id} from the card: "
                + (result.output or "no output")
            )
        data = out.read_bytes()
    return load_certificate(data, source=f"pkcs11:id={object_id}")


def scan(
    *, module: str | None = None, slot: str | None = None, read_certs: bool = True
) -> CardScan:
    """Run the whole detect chain: reader, token, slot, certificates."""
    if not is_linux():
        raise PlatformUnsupported(
            "Smart Card detection drives PC/SC and PKCS#11 tooling that this program "
            "only supports on the SSSD host (Linux). Use `cert inspect --file` to work "
            "on an exported certificate instead."
        )
    result = CardScan()
    # Say this before anything can fail, so the operator is not left reading a
    # hardware error when the real answer is "run it with sudo".
    if unprivileged_on_linux():
        result.checks.append(
            Check(
                "privileges",
                "WARN",
                f"running as uid {os.geteuid()}, not root",
                hint=PRIVILEGE_HINT,
            )
        )
    result.modules_found = find_modules()
    result.readers, reader_checks = list_readers()
    result.checks.extend(reader_checks)
    result.module = pick_module(module)
    result.checks.append(Check("pkcs11-module", "PASS", result.module))

    result.slots = list_slots(result.module)
    if not result.slots:
        result.checks.append(
            Check(
                "token",
                "FAIL",
                "no PKCS#11 token found",
                hint=SHORT_PRIVILEGE_HINT
                if unprivileged_on_linux()
                else "Insert a card and check that pcscd sees it: "
                "opensc-tool --list-readers",
            )
        )
        return result
    result.checks.append(Check("token", "PASS", f"{len(result.slots)} token slot(s)"))

    entries = list_certificates(result.module, slot=slot)
    if not entries:
        result.checks.append(
            Check(
                "certificates",
                "FAIL",
                "no certificate objects on the token",
                hint=SHORT_PRIVILEGE_HINT
                if unprivileged_on_linux()
                else "The card may be blank, or the PKCS#11 module may need a PIN "
                "to list objects. This tool never supplies a PIN.",
            )
        )
        return result

    for entry in entries:
        if read_certs and entry.object_id:
            try:
                entry.certificate = read_certificate(
                    result.module, entry.object_id, slot=slot
                )
            except ToolMissing as exc:
                entry.error = str(exc)
        result.certificates.append(entry)
    result.checks.append(
        Check("certificates", "PASS", f"{len(result.certificates)} certificate(s) found")
    )
    return result


def pick_authentication_certificate(scan_result: CardScan) -> CardCertificate | None:
    """Choose the certificate best suited to logon.

    Preference order: a UPN in the SAN, then clientAuth EKU, then the first
    certificate that parsed at all.
    """
    from ..x509.inspect import OID_MS_SMARTCARD_LOGON
    from cryptography.x509.oid import ExtendedKeyUsageOID

    usable = [c for c in scan_result.certificates if c.certificate]
    if not usable:
        return None
    for entry in usable:
        if entry.certificate.san.upn:
            return entry
    for entry in usable:
        eku = entry.certificate.eku_oids
        if OID_MS_SMARTCARD_LOGON.dotted_string in eku:
            return entry
    for entry in usable:
        if ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string in entry.certificate.eku_oids:
            return entry
    return usable[0]
