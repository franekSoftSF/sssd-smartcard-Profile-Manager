"""SSSD version detection and the feature matrix the renderer gates on.

Every entry carries the source it was taken from.  Where we could not confirm
a version from upstream documentation the entry says so rather than guessing --
an unverified gate that silently blocks a working option is worse than no gate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import total_ordering

from ..util import run


@total_ordering
@dataclass(frozen=True)
class Version:
    """A dotted SSSD version, comparable and printable."""

    parts: tuple[int, ...]
    raw: str = ""

    @classmethod
    def parse(cls, text: str) -> "Version":
        match = re.search(r"(\d+(?:\.\d+)*)", text or "")
        if not match:
            raise ValueError(f"cannot read a version out of {text!r}")
        return cls(tuple(int(p) for p in match.group(1).split(".")), text.strip())

    def _pad(self, other: "Version") -> tuple[tuple[int, ...], tuple[int, ...]]:
        size = max(len(self.parts), len(other.parts))
        return (
            self.parts + (0,) * (size - len(self.parts)),
            other.parts + (0,) * (size - len(other.parts)),
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        a, b = self._pad(other)
        return a == b

    def __lt__(self, other: "Version") -> bool:
        a, b = self._pad(other)
        return a < b

    def __hash__(self) -> int:
        return hash(self.parts)

    def __str__(self) -> str:
        return ".".join(str(p) for p in self.parts)


#: What the tool assumes when it cannot see the target host.  2.9 is what
#: current enterprise distributions ship, so generated config stays usable.
DEFAULT_VERSION = Version.parse("2.9.0")

SOURCE_RELNOTES = "https://sssd.io/release-notes/"
SOURCE_CERTMAP_MAN = "sss-certmap(5)"
SOURCE_SSSD_CONF_MAN = "sssd.conf(5)"


@dataclass(frozen=True)
class Feature:
    """One capability the generator may depend on."""

    key: str
    description: str
    since: Version | None
    source: str
    note: str = ""

    def available_in(self, version: Version) -> bool:
        return self.since is None or version >= self.since


def _v(text: str) -> Version:
    return Version.parse(text)


FEATURES: dict[str, Feature] = {
    f.key: f
    for f in (
        Feature(
            "certmap.section",
            "[certmap/DOMAIN/RULE] sections for the AD and LDAP providers",
            _v("2.0.0"),
            SOURCE_CERTMAP_MAN,
            "Generic certificate mapping outside IPA arrived with the 2.0 series.",
        ),
        Feature(
            "map.ldapu1",
            "LDAPU1: mapping rule prefix",
            _v("2.0.0"),
            SOURCE_CERTMAP_MAN,
        ),
        Feature(
            "map.ldapu1_extended",
            "{serial_number}, {subject_key_id}, {sid}, {cert!DIGEST}, "
            "{subject_dn_component}, {issuer_dn_component}",
            _v("2.8.2"),
            SOURCE_RELNOTES + "sssd-2.8.2.html",
            "Needed for AD strong certificate mapping (KB5014754) rules.",
        ),
        Feature(
            "pam.p11_uri",
            "p11_uri -- restrict which PKCS#11 device may be used",
            _v("2.1.0"),
            SOURCE_RELNOTES + "sssd-2.1.0.html",
        ),
        Feature(
            "verify.crl_file",
            "certificate_verification=crl_file=/path",
            _v("2.1.0"),
            SOURCE_RELNOTES + "sssd-2.1.0.html",
        ),
        Feature(
            "verify.ocsp_dgst",
            "certificate_verification=ocsp_dgst=sha256",
            _v("2.2.1"),
            SOURCE_RELNOTES + "sssd-2.2.1.html",
        ),
        Feature(
            "verify.soft_ocsp",
            "certificate_verification=soft_ocsp",
            _v("2.2.3"),
            SOURCE_RELNOTES + "sssd-2.2.3.html",
        ),
        Feature(
            "verify.soft_crl",
            "certificate_verification=soft_crl",
            _v("2.2.3"),
            SOURCE_RELNOTES + "sssd-2.2.3.html",
        ),
        Feature(
            "verify.partial_chain",
            "certificate_verification=partial_chain",
            None,
            SOURCE_SSSD_CONF_MAN,
            "Documented without an introduction version; treated as always present.",
        ),
        Feature(
            "verify.no_ocsp",
            "certificate_verification=no_ocsp / no_verification",
            None,
            SOURCE_SSSD_CONF_MAN,
            "Documented without an introduction version; treated as always present.",
        ),
        Feature(
            "pam.cert_auth",
            "pam_cert_auth, pam_cert_db_path, p11_child_timeout",
            None,
            SOURCE_SSSD_CONF_MAN,
            "Documented without an introduction version; treated as always present.",
        ),
        Feature(
            "pam.cert_verification",
            "pam_cert_verification -- per-PAM override of certificate_verification",
            None,
            SOURCE_SSSD_CONF_MAN,
            "Documented without an introduction version; treated as always present.",
        ),
        Feature(
            "auth.local_auth_policy",
            "local_auth_policy -- which authentication methods may be checked locally",
            _v("2.9.2"),
            SOURCE_RELNOTES + "sssd-2.9.2.html",
        ),
        Feature(
            "auth.local_smartcard",
            "local_auth_policy = enable:smartcard -- local Smart Card authentication",
            _v("2.9.3"),
            SOURCE_RELNOTES + "sssd-2.9.3.html",
            "Without this the AD provider reads the card and then refuses it: the PAM "
            "responder logs 'Local auth policy allowed: smartcard [False]' and falls "
            "back to a password prompt.",
        ),
    )
}


def feature(key: str) -> Feature:
    try:
        return FEATURES[key]
    except KeyError:  # pragma: no cover - programming error
        raise KeyError(f"unknown feature {key!r}") from None


def supported(key: str, version: Version) -> bool:
    return feature(key).available_in(version)


@dataclass
class DetectedSSSD:
    """What we could learn about the SSSD installed on this host."""

    version: Version | None = None
    binary: str | None = None
    detected: bool = False
    detail: str = ""
    tools: dict[str, bool] = field(default_factory=dict)

    @property
    def effective_version(self) -> Version:
        return self.version or DEFAULT_VERSION


_SSSD_BINARIES = ("sssd", "/usr/sbin/sssd", "/usr/libexec/sssd/sssd")


def detect_sssd() -> DetectedSSSD:
    """Look for SSSD and read its version, without requiring root."""
    info = DetectedSSSD()
    for candidate in _SSSD_BINARIES:
        result = run([candidate, "--version"], timeout=10)
        if not result.found:
            continue
        info.binary = candidate
        text = result.output
        try:
            info.version = Version.parse(text)
            info.detected = True
            info.detail = text.splitlines()[0] if text else ""
        except ValueError:
            info.detail = f"{candidate} --version produced no parsable version: {text!r}"
        break
    else:
        info.detail = "sssd binary not found on PATH"

    for tool in ("sssctl", "sss_cache", "pkcs11-tool", "p11-kit", "pcsc_scan", "openssl"):
        info.tools[tool] = run([tool, "--version"], timeout=10).found
    return info


def sssctl_supports(subcommand: str) -> bool:
    """Ask sssctl whether it knows *subcommand* (versions differ a lot)."""
    result = run(["sssctl", subcommand, "--help"], timeout=10)
    if not result.found:
        return False
    text = result.output.lower()
    return "unknown command" not in text and "invalid" not in text
