"""Distribution detection and the per-distribution facts that follow from it.

This module exists because the single most common way to get Smart Card logon
wrong is to follow Red Hat's instructions on Ubuntu.  ``authselect`` does not
exist on Ubuntu, and ``pam-auth-update`` does not exist on RHEL, so any tool
that prints one command for everybody is wrong half the time.

Everything here is sourced:

* Ubuntu packages and PAM profiles --
  https://ubuntu.com/server/docs/how-to/security/smart-card-authentication/
* RHEL PAM configuration --
  https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/managing_smart_card_authentication/configuring-smart-cards-using-authselect_managing-smart-card-authentication
* adsys (Ubuntu only) -- https://documentation.ubuntu.com/adsys/
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

OS_RELEASE = "/etc/os-release"

FAMILY_DEBIAN = "debian"
FAMILY_RHEL = "rhel"
FAMILY_SUSE = "suse"
FAMILY_UNKNOWN = "unknown"

_FAMILY_BY_ID = {
    "ubuntu": FAMILY_DEBIAN,
    "debian": FAMILY_DEBIAN,
    "linuxmint": FAMILY_DEBIAN,
    "pop": FAMILY_DEBIAN,
    "elementary": FAMILY_DEBIAN,
    "rhel": FAMILY_RHEL,
    "centos": FAMILY_RHEL,
    "fedora": FAMILY_RHEL,
    "rocky": FAMILY_RHEL,
    "almalinux": FAMILY_RHEL,
    "ol": FAMILY_RHEL,
    "opensuse": FAMILY_SUSE,
    "opensuse-leap": FAMILY_SUSE,
    "opensuse-tumbleweed": FAMILY_SUSE,
    "sles": FAMILY_SUSE,
}

#: ``pam-auth-update`` gained the sss-smart-card-* profiles in Ubuntu 23.10 ...
PAM_AUTH_UPDATE_SINCE = (23, 10)

#: ... and in Debian 13 (trixie, sssd 2.10); Debian 12 (sssd 2.8) has none.
#: Measured in a debian:13 container: /usr/share/pam-configs/ holds
#: sss-smart-card-optional and sss-smart-card-required after libpam-sss.
PAM_AUTH_UPDATE_SINCE_DEBIAN = (13,)

#: Where each family keeps SSSD's PKCS#11 helper.
P11_CHILD_PATHS = {
    FAMILY_DEBIAN: ("/usr/libexec/sssd/p11_child", "/usr/lib/x86_64-linux-gnu/sssd/p11_child"),
    FAMILY_RHEL: ("/usr/libexec/sssd/p11_child",),
    FAMILY_SUSE: ("/usr/lib/sssd/p11_child", "/usr/libexec/sssd/p11_child"),
}

#: SoftHSM's PKCS#11 module, used by the test lab to emulate a card.
SOFTHSM_MODULES = (
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib64/pkcs11/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib64/softhsm/libsofthsm2.so",
)


@dataclass
class PackageSet:
    """Packages grouped by the job they do, so a step can install just its own."""

    core: tuple[str, ...] = ()
    join: tuple[str, ...] = ()
    smartcard: tuple[str, ...] = ()
    kerberos: tuple[str, ...] = ()
    gpo: tuple[str, ...] = ()
    autoenroll: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()

    def group(self, name: str) -> tuple[str, ...]:
        return getattr(self, name, ())


@dataclass
class PamPlan:
    """How to turn Smart Card authentication on in this distribution's PAM."""

    kind: str  # authselect | pam-auth-update | manual | unknown
    optional: list[str] = field(default_factory=list)
    required: list[str] = field(default_factory=list)
    inspect: list[str] = field(default_factory=list)
    detail: str = ""
    manual_lines: dict[str, str] = field(default_factory=dict)

    def commands(self, *, require_smartcard: bool) -> list[str]:
        return self.required if require_smartcard else self.optional


@dataclass
class DistroInfo:
    """What /etc/os-release says, plus everything derived from it."""

    id: str = ""
    id_like: tuple[str, ...] = ()
    version_id: str = ""
    pretty_name: str = ""
    family: str = FAMILY_UNKNOWN

    @property
    def version_tuple(self) -> tuple[int, ...]:
        parts: list[int] = []
        for chunk in self.version_id.split("."):
            if chunk.isdigit():
                parts.append(int(chunk))
            else:
                break
        return tuple(parts)

    @property
    def is_ubuntu(self) -> bool:
        return self.id == "ubuntu"

    @property
    def has_smartcard_pam_profiles(self) -> bool:
        """Whether libpam-sss ships the sss-smart-card-* pam-auth-update profiles."""
        if self.is_ubuntu:
            return self.version_tuple >= PAM_AUTH_UPDATE_SINCE
        if self.id == "debian":
            return self.version_tuple >= PAM_AUTH_UPDATE_SINCE_DEBIAN
        return False

    @property
    def package_manager(self) -> str:
        if self.family == FAMILY_DEBIAN:
            return "apt-get"
        if self.family == FAMILY_RHEL:
            return "dnf" if shutil.which("dnf") else "yum"
        if self.family == FAMILY_SUSE:
            return "zypper"
        return ""

    @property
    def supports_adsys(self) -> bool:
        """adsys is packaged by Canonical for Ubuntu only."""
        return self.is_ubuntu

    @property
    def p11_child(self) -> str | None:
        for path in P11_CHILD_PATHS.get(self.family, ()):
            if os.path.exists(path):
                return path
        for paths in P11_CHILD_PATHS.values():
            for path in paths:
                if os.path.exists(path):
                    return path
        return None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "id_like": list(self.id_like),
            "version_id": self.version_id,
            "pretty_name": self.pretty_name,
            "family": self.family,
            "package_manager": self.package_manager,
            "supports_adsys": self.supports_adsys,
            "pam": {
                "kind": self.pam_plan().kind,
                "detail": self.pam_plan().detail,
            },
        }

    # -- packages --------------------------------------------------------
    def packages(self) -> PackageSet:
        if self.family == FAMILY_DEBIAN:
            return PackageSet(
                # Documented set for Ubuntu Smart Card authentication, plus the
                # NSS/PAM modules and sssd-ad, which Ubuntu splits out.
                core=("sssd", "sssd-ad", "sssd-tools", "libpam-sss", "libnss-sss"),
                join=("realmd", "adcli", "samba-common", "samba-common-bin", "packagekit"),
                smartcard=("opensc", "opensc-pkcs11", "pcscd", "pcsc-tools", "p11-kit"),
                kerberos=("krb5-user",),
                gpo=("adsys",) if self.supports_adsys else (),
                autoenroll=("certmonger", "cepces"),
                diagnostics=("pamtester", "openssl", "gnutls-bin", "ldap-utils"),
            )
        if self.family == FAMILY_RHEL:
            return PackageSet(
                core=("sssd", "sssd-ad", "sssd-tools", "authselect", "oddjob", "oddjob-mkhomedir"),
                join=("realmd", "adcli", "samba-common-tools"),
                smartcard=("opensc", "pcsc-lite", "pcsc-lite-ccid", "p11-kit"),
                kerberos=("krb5-workstation",),
                gpo=(),  # GPO access control is built into the AD provider
                autoenroll=("certmonger", "cepces"),
                diagnostics=("pamtester", "openssl", "openldap-clients"),
            )
        if self.family == FAMILY_SUSE:
            return PackageSet(
                core=("sssd", "sssd-ad", "sssd-tools", "pam_sss"),
                join=("realmd", "adcli", "samba-client"),
                smartcard=("opensc", "pcsc-lite", "pcsc-ccid", "p11-kit"),
                kerberos=("krb5-client",),
                diagnostics=("openssl",),
            )
        return PackageSet()

    # -- PAM -------------------------------------------------------------
    def pam_plan(self) -> PamPlan:
        if self.family == FAMILY_RHEL:
            return PamPlan(
                kind="authselect",
                optional=["authselect enable-feature with-smartcard"],
                required=[
                    "authselect enable-feature with-smartcard",
                    "authselect enable-feature with-smartcard-required",
                ],
                inspect=["authselect current"],
                detail=(
                    "authselect manages the PAM stack. with-smartcard makes the card "
                    "usable; with-smartcard-required adds pam_sss.so require_cert_auth, "
                    "which disables password login for the affected services."
                ),
            )

        if self.family == FAMILY_DEBIAN:
            if self.has_smartcard_pam_profiles:
                return PamPlan(
                    kind="pam-auth-update",
                    optional=[
                        "pam-auth-update --disable sss-smart-card-required "
                        "--enable sss-smart-card-optional"
                    ],
                    required=[
                        "pam-auth-update --disable sss-smart-card-optional "
                        "--enable sss-smart-card-required"
                    ],
                    inspect=["pam-auth-update --list"],
                    detail=(
                        f"{self.pretty_name or (self.id + ' ' + self.version_id)} ships "
                        "the sss-smart-card-optional and sss-smart-card-required "
                        "pam-auth-update profiles. Debian and Ubuntu have no authselect "
                        "-- do not use it here."
                    ),
                )
            return PamPlan(
                kind="manual",
                inspect=["grep -n pam_sss /etc/pam.d/common-auth"],
                detail=(
                    "This release has no sss-smart-card-* pam-auth-update profile, so the "
                    "pam_sss line has to be added to /etc/pam.d/common-auth by hand. "
                    "This tool never edits PAM: a wrong line here locks you out."
                ),
                manual_lines={
                    "optional": "auth [success=ok default=ignore] pam_sss.so "
                    "allow_missing_name try_cert_auth",
                    "required": "auth [success=done default=die] pam_sss.so "
                    "allow_missing_name require_cert_auth",
                },
            )

        return PamPlan(
            kind="unknown",
            detail=(
                "Unrecognised distribution. Enable pam_sss.so with try_cert_auth "
                "(optional) or require_cert_auth (Smart Card only) using whatever "
                "mechanism manages your PAM stack."
            ),
            manual_lines={
                "optional": "auth [success=ok default=ignore] pam_sss.so "
                "allow_missing_name try_cert_auth",
                "required": "auth [success=done default=die] pam_sss.so "
                "allow_missing_name require_cert_auth",
            },
        )


def parse_os_release(text: str) -> DistroInfo:
    """Parse /etc/os-release content into a :class:`DistroInfo`."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    distro_id = values.get("ID", "").lower()
    id_like = tuple(v for v in values.get("ID_LIKE", "").lower().split() if v)
    family = _FAMILY_BY_ID.get(distro_id, FAMILY_UNKNOWN)
    if family == FAMILY_UNKNOWN:
        for candidate in id_like:
            if candidate in _FAMILY_BY_ID:
                family = _FAMILY_BY_ID[candidate]
                break
    return DistroInfo(
        id=distro_id,
        id_like=id_like,
        version_id=values.get("VERSION_ID", ""),
        pretty_name=values.get("PRETTY_NAME", ""),
        family=family,
    )


def detect_distro(path: str = OS_RELEASE) -> DistroInfo:
    """Read /etc/os-release, or return an unknown distribution off-host."""
    try:
        return parse_os_release(Path(path).read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return DistroInfo()


def softhsm_module() -> str | None:
    for path in SOFTHSM_MODULES:
        if os.path.exists(path):
            return path
    return None
