"""Distribution detection, the PAM plan it implies, and the GPO settings.

The regression these tests guard against is the one that breaks real
deployments: printing Red Hat's ``authselect`` command on Ubuntu, where it does
not exist.
"""

from __future__ import annotations

import pytest

from sssd_smartcard.certmap.compat import Version
from sssd_smartcard.certmap.renderer import render
from sssd_smartcard.errors import ProfileError
from sssd_smartcard.model.profile import GpoSpec, SmartCardProfile
from sssd_smartcard.model.store import load_profile_text
from sssd_smartcard.platform import (
    FAMILY_DEBIAN,
    FAMILY_RHEL,
    FAMILY_UNKNOWN,
    DistroInfo,
    parse_os_release,
)

V29 = Version.parse("2.9.0")

UBUNTU_2404 = """\
PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
ID_LIKE=debian
"""

UBUNTU_2204 = """\
PRETTY_NAME="Ubuntu 22.04.5 LTS"
ID=ubuntu
ID_LIKE=debian
VERSION_ID="22.04"
"""

DEBIAN_12 = """\
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
ID=debian
VERSION_ID="12"
"""

ROCKY_9 = """\
NAME="Rocky Linux"
VERSION_ID="9.4"
ID="rocky"
ID_LIKE="rhel centos fedora"
"""


class TestDistroDetection:
    def test_ubuntu(self):
        distro = parse_os_release(UBUNTU_2404)
        assert distro.id == "ubuntu"
        assert distro.family == FAMILY_DEBIAN
        assert distro.version_tuple == (24, 4)
        assert distro.package_manager == "apt-get"
        assert distro.supports_adsys

    def test_rocky_is_recognised_through_id_like(self):
        distro = parse_os_release(ROCKY_9)
        assert distro.family == FAMILY_RHEL
        assert not distro.supports_adsys

    def test_debian_is_debian_family_but_not_ubuntu(self):
        distro = parse_os_release(DEBIAN_12)
        assert distro.family == FAMILY_DEBIAN
        assert not distro.supports_adsys

    def test_unknown_distribution_degrades_instead_of_crashing(self):
        distro = parse_os_release("ID=plan9\n")
        assert distro.family == FAMILY_UNKNOWN
        assert distro.package_manager == ""

    def test_missing_os_release_yields_unknown(self, tmp_path):
        from sssd_smartcard.platform import detect_distro

        assert detect_distro(str(tmp_path / "nope")).family == FAMILY_UNKNOWN


class TestPamPlan:
    def test_rhel_uses_authselect(self):
        plan = parse_os_release(ROCKY_9).pam_plan()
        assert plan.kind == "authselect"
        assert plan.commands(require_smartcard=False) == [
            "authselect enable-feature with-smartcard"
        ]
        assert "with-smartcard-required" in " ".join(
            plan.commands(require_smartcard=True)
        )

    def test_ubuntu_2404_uses_pam_auth_update_not_authselect(self):
        plan = parse_os_release(UBUNTU_2404).pam_plan()
        assert plan.kind == "pam-auth-update"
        joined = " ".join(plan.commands(require_smartcard=False))
        assert "pam-auth-update" in joined
        assert "sss-smart-card-optional" in joined
        assert "authselect" not in joined

    def test_ubuntu_required_profile(self):
        plan = parse_os_release(UBUNTU_2404).pam_plan()
        joined = " ".join(plan.commands(require_smartcard=True))
        assert "--enable sss-smart-card-required" in joined
        assert "--disable sss-smart-card-optional" in joined

    def test_ubuntu_2204_has_no_profiles_so_falls_back_to_manual(self):
        plan = parse_os_release(UBUNTU_2204).pam_plan()
        assert plan.kind == "manual"
        assert "try_cert_auth" in plan.manual_lines["optional"]
        assert "require_cert_auth" in plan.manual_lines["required"]

    def test_debian_is_manual(self):
        assert parse_os_release(DEBIAN_12).pam_plan().kind == "manual"

    def test_manual_lines_carry_allow_missing_name(self):
        plan = parse_os_release(DEBIAN_12).pam_plan()
        for line in plan.manual_lines.values():
            assert "allow_missing_name" in line
            assert "pam_sss.so" in line


class TestPackages:
    def test_ubuntu_gets_libpam_sss_not_authselect(self):
        packages = parse_os_release(UBUNTU_2404).packages()
        assert "libpam-sss" in packages.core
        assert "authselect" not in packages.core
        assert "opensc-pkcs11" in packages.smartcard
        assert "krb5-user" in packages.kerberos
        assert "adsys" in packages.gpo

    def test_rhel_gets_authselect_and_no_adsys(self):
        packages = parse_os_release(ROCKY_9).packages()
        assert "authselect" in packages.core
        assert packages.gpo == ()
        assert "krb5-workstation" in packages.kerberos

    def test_autoenrolment_needs_certmonger_and_cepces_everywhere(self):
        for text in (UBUNTU_2404, ROCKY_9):
            packages = parse_os_release(text).packages()
            assert "certmonger" in packages.autoenroll
            assert "cepces" in packages.autoenroll


class TestDistroAwareManualSteps:
    def _profile(self, **kwargs) -> SmartCardProfile:
        return SmartCardProfile(name="T", domain="domain-b.local", **kwargs)

    def test_ubuntu_never_gets_told_to_run_authselect(self):
        result = render(
            self._profile(), version=V29, distro=parse_os_release(UBUNTU_2404)
        )
        commands = " ".join(s.command for s in result.manual_steps)
        assert "authselect" not in commands
        assert "pam-auth-update" in commands

    def test_rhel_gets_authselect(self):
        result = render(self._profile(), version=V29, distro=parse_os_release(ROCKY_9))
        commands = " ".join(s.command for s in result.manual_steps)
        assert "authselect enable-feature with-smartcard" in commands

    def test_old_ubuntu_gets_the_exact_pam_line_and_no_command(self):
        result = render(
            self._profile(), version=V29, distro=parse_os_release(UBUNTU_2204)
        )
        step = next(s for s in result.manual_steps if "pam_sss" in s.title)
        assert step.command == ""
        assert "try_cert_auth" in step.detail

    def test_unknown_distro_offers_both_recipes(self):
        result = render(self._profile(), version=V29, distro=DistroInfo())
        detail = " ".join(s.detail for s in result.manual_steps)
        assert "authselect" in detail and "pam-auth-update" in detail


class TestSocketActivatedServices:
    """pcscd is socket-activated, so an inactive service is not a fault.

    Reported from a real Ubuntu 24.04 host: doctor warned "pcscd.service is
    inactive" and told the operator to enable pcscd.socket, which was already
    active. Checking the service alone false-alarms on every default install.
    """

    def _fake_systemctl(self, states: dict[str, str]):
        from sssd_smartcard.util import CommandResult

        def runner(argv, **kwargs):
            unit = argv[-1]
            if unit not in states:
                return CommandResult(list(argv), 3, "inactive\n", "")
            return CommandResult(
                list(argv), 0 if states[unit] == "active" else 3, states[unit] + "\n", ""
            )

        return runner

    def test_active_service_is_available(self, monkeypatch):
        from sssd_smartcard import util

        monkeypatch.setattr(
            util, "run", self._fake_systemctl({"pcscd.service": "active"})
        )
        available, detail = util.service_or_socket_active("pcscd.service", "pcscd.socket")
        assert available is True
        assert "active" in detail

    def test_inactive_service_with_active_socket_is_available(self, monkeypatch):
        from sssd_smartcard import util

        monkeypatch.setattr(
            util,
            "run",
            self._fake_systemctl(
                {"pcscd.service": "inactive", "pcscd.socket": "active"}
            ),
        )
        available, detail = util.service_or_socket_active("pcscd.service", "pcscd.socket")
        assert available is True
        assert "socket-activated" in detail

    def test_both_inactive_is_not_available(self, monkeypatch):
        from sssd_smartcard import util

        monkeypatch.setattr(
            util,
            "run",
            self._fake_systemctl(
                {"pcscd.service": "inactive", "pcscd.socket": "inactive"}
            ),
        )
        available, _ = util.service_or_socket_active("pcscd.service", "pcscd.socket")
        assert available is False

    def test_no_systemd_yields_unknown(self, monkeypatch):
        from sssd_smartcard import util
        from sssd_smartcard.util import CommandResult

        monkeypatch.setattr(
            util,
            "run",
            lambda argv, **kw: CommandResult(list(argv), 127, "", "no systemctl", found=False),
        )
        available, detail = util.service_or_socket_active("pcscd.service", "pcscd.socket")
        assert available is None
        assert "systemctl" in detail

    def test_service_only_check_still_works(self, monkeypatch):
        from sssd_smartcard import util

        monkeypatch.setattr(
            util, "run", self._fake_systemctl({"sssd.service": "inactive"})
        )
        available, detail = util.service_or_socket_active("sssd.service")
        assert available is False
        assert "sssd.service is inactive" == detail


class TestPcscPrivilegeDiagnosis:
    """"No reader detected" must not blame the hardware when it is polkit.

    Reported from a real Ubuntu 24.04 host with a YubiKey passed through to the
    VM: pcscd was running and `sudo opensc-tool --list-readers` saw the reader,
    but an unprivileged SSH user saw nothing and the tool advised installing
    pcsc-lite and checking that pcscd runs -- both already true. pcscd logs
    "is NOT authorized for action: access_pcsc": pcsc-lite gates access through
    polkit, whose default allows only a session on a local seat.
    """

    def test_unprivileged_hint_talks_about_polkit_not_hardware(self, monkeypatch):
        from sssd_smartcard.pkcs11 import detect

        monkeypatch.setattr(detect, "is_linux", lambda: True)
        monkeypatch.setattr(detect.os, "geteuid", lambda: 1000, raising=False)
        hint = detect.no_reader_hint()
        assert "polkit" in hint
        assert "access_pcsc" in hint
        assert "sudo" in hint
        # The old, misleading advice must be gone.
        assert "Install pcsc-lite" not in hint

    def test_root_hint_talks_about_hardware(self, monkeypatch):
        from sssd_smartcard.pkcs11 import detect

        monkeypatch.setattr(detect, "is_linux", lambda: True)
        monkeypatch.setattr(detect.os, "geteuid", lambda: 0, raising=False)
        hint = detect.no_reader_hint()
        assert "polkit" not in hint
        assert "passed through" in hint

    def test_off_host_is_never_treated_as_a_privilege_problem(self, monkeypatch):
        from sssd_smartcard.pkcs11 import detect

        monkeypatch.setattr(detect, "is_linux", lambda: False)
        assert detect.unprivileged_on_linux() is False

    def test_root_on_linux_is_privileged(self, monkeypatch):
        from sssd_smartcard.pkcs11 import detect

        monkeypatch.setattr(detect, "is_linux", lambda: True)
        monkeypatch.setattr(detect.os, "geteuid", lambda: 0, raising=False)
        assert detect.unprivileged_on_linux() is False


class TestPamCertAuthDetection:
    """"pam_sss.so is present" cannot answer "is card login on?".

    The plain password profile installs pam_sss too, so presence proves nothing.
    What matters is try_cert_auth (card or password) or require_cert_auth
    (card only). Observed on a real host after
    `pam-auth-update --enable sss-smart-card-optional`.
    """

    OPTIONAL = (
        "auth [success=3 default=ignore] pam_sss.so allow_missing_name try_cert_auth\n"
        "auth [success=2 default=ignore] pam_unix.so nullok try_first_pass\n"
        "auth [success=1 default=ignore] pam_sss.so use_first_pass\n"
        "auth requisite pam_deny.so\n"
    )
    REQUIRED = (
        "auth [success=done default=die] pam_sss.so allow_missing_name require_cert_auth\n"
        "auth requisite pam_deny.so\n"
    )
    PASSWORD_ONLY = (
        "auth [success=2 default=ignore] pam_unix.so nullok\n"
        "auth [success=1 default=ignore] pam_sss.so use_first_pass\n"
    )

    def _mode(self, text: str) -> str:
        mode = "off"
        for line in text.splitlines():
            if line.lstrip().startswith("#") or "pam_sss.so" not in line:
                continue
            if "require_cert_auth" in line:
                mode = "required"
            elif "try_cert_auth" in line and mode == "off":
                mode = "optional"
        return mode

    def test_try_cert_auth_is_optional(self):
        assert self._mode(self.OPTIONAL) == "optional"

    def test_require_cert_auth_is_required(self):
        assert self._mode(self.REQUIRED) == "required"

    def test_plain_sss_password_profile_is_not_card_auth(self):
        assert self._mode(self.PASSWORD_ONLY) == "off"

    def test_required_wins_over_optional(self):
        assert self._mode(self.OPTIONAL + self.REQUIRED) == "required"

    def test_commented_out_lines_do_not_count(self):
        assert self._mode("# auth pam_sss.so try_cert_auth\n") == "off"

    def test_report_exposes_the_derived_booleans(self):
        from sssd_smartcard.sssdconf.runtime import PamReport

        report = PamReport(cert_auth_mode="optional")
        assert report.cert_auth_enabled and not report.require_cert_auth
        report = PamReport(cert_auth_mode="required")
        assert report.cert_auth_enabled and report.require_cert_auth
        report = PamReport()
        assert not report.cert_auth_enabled and not report.require_cert_auth


class TestGpoModel:
    def test_defaults_are_inert(self):
        gpo = GpoSpec.from_dict(None)
        assert not gpo.manage and not gpo.adsys and not gpo.cert_autoenroll

    def test_map_interactive_uses_the_documented_plus_minus_syntax(self):
        gpo = GpoSpec.from_dict(
            {
                "manage": True,
                "map_interactive_add": ["gdm-smartcard", "sudo"],
                "map_interactive_remove": ["lxdm"],
            }
        )
        assert gpo.map_interactive == ["+gdm-smartcard", "+sudo", "-lxdm"]

    def test_a_service_cannot_be_added_and_removed_at_once(self):
        with pytest.raises(ProfileError):
            GpoSpec.from_dict(
                {"map_interactive_add": ["sudo"], "map_interactive_remove": ["sudo"]}
            )

    def test_bad_access_control_value_is_rejected(self):
        with pytest.raises(ProfileError):
            GpoSpec.from_dict({"access_control": "sometimes"})

    def test_cert_autoenroll_requires_adsys(self):
        with pytest.raises(ProfileError) as excinfo:
            GpoSpec.from_dict({"cert_autoenroll": True})
        assert "adsys" in str(excinfo.value)

    def test_round_trips_through_yaml(self):
        profile = load_profile_text(
            "apiVersion: sssd-smartcard/v1\nname: X\ndomain: d.local\n"
            "gpo:\n  manage: true\n  access_control: permissive\n  adsys: true\n"
            "  cert_autoenroll: true\n  map_interactive_add: [gdm-smartcard]\n"
        )
        assert profile.gpo.manage and profile.gpo.adsys and profile.gpo.cert_autoenroll
        reloaded = load_profile_text(
            __import__("yaml").safe_dump(profile.to_dict())
        )
        assert reloaded.gpo.map_interactive_add == ["gdm-smartcard"]


class TestGpoRendering:
    def _render(self, gpo: dict, distro=None):
        profile = SmartCardProfile(
            name="T", domain="domain-b.local", gpo=GpoSpec.from_dict(gpo)
        )
        return render(
            profile,
            version=V29,
            distro=distro or parse_os_release(UBUNTU_2404),
        )

    def test_unmanaged_gpo_warns_about_the_enforcing_default(self):
        result = self._render({})
        assert "ad_gpo_access_control" not in result.to_ini()
        assert any("enforcing" in n for n in result.notes)

    def test_permissive_is_written_into_the_domain_section(self):
        ini = self._render({"manage": True, "access_control": "permissive"}).to_ini()
        assert "[domain/domain-b.local]" in ini
        assert "ad_gpo_access_control = permissive" in ini

    def test_enforcing_carries_a_lockout_warning(self):
        result = self._render({"manage": True, "access_control": "enforcing"})
        assert any("InteractiveLogonRight" in w for w in result.warnings)

    def test_implicit_deny_carries_a_warning(self):
        result = self._render({"manage": True, "implicit_deny": True})
        assert "ad_gpo_implicit_deny = True" in result.to_ini()
        assert any("denies everyone" in w for w in result.warnings)

    def test_map_interactive_is_rendered(self):
        ini = self._render(
            {"manage": True, "map_interactive_add": ["gdm-smartcard"]}
        ).to_ini()
        assert "ad_gpo_map_interactive = +gdm-smartcard" in ini

    def test_adsys_step_appears_on_ubuntu(self):
        result = self._render({"adsys": True})
        assert any("adsysctl update" in s.command for s in result.manual_steps)

    def test_adsys_on_rhel_is_a_warning_not_a_step(self):
        result = self._render({"adsys": True}, distro=parse_os_release(ROCKY_9))
        assert any("Ubuntu" in w for w in result.warnings)
        assert not any("adsysctl" in s.command for s in result.manual_steps)

    def test_cert_autoenrolment_step_names_certmonger_and_cepces(self):
        result = self._render({"adsys": True, "cert_autoenroll": True})
        step = next(s for s in result.manual_steps if "auto-enrolment" in s.title)
        assert "certmonger" in step.command and "cepces" in step.command
