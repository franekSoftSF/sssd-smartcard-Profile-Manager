"""The apply plan has to name the home-directory step, not just `doctor`.

`doctor` already warns when nothing provisions a home.  The plan printed by
`config apply` did not, and that is the document an operator works from:
dry-run, read "Still to do by hand", do those things, test the login.  On the
lab host the list held one item -- the Smart Card PAM profile -- so an operator
following it exactly would enable the card, log in, and get the black screen
that test_home_directory.py exists because of.  Authenticating is not logging
in.

The step is only emitted when the live PAM session stack can be read and has
no provisioner in it, so a host that provisions homes another way (autofs, a
pre-created share) is never told to change anything.
"""

from __future__ import annotations

import pytest

from sssd_smartcard.certmap.compat import Version
from sssd_smartcard.certmap.renderer import render
from sssd_smartcard.model.profile import SmartCardProfile
from sssd_smartcard.platform import FAMILY_DEBIAN, FAMILY_RHEL, DistroInfo
from sssd_smartcard.sssdconf import runtime
from sssd_smartcard import util

V_OK = Version.parse("2.9.4")

BASE = {
    "apiVersion": "sssd-smartcard/v1",
    "name": "AD-PIV-UPN",
    "domain": "ad.example.com",
    "provider": "ad",
    "certificate": {"issuer": "CN=CA,DC=ad,DC=example,DC=com", "eku": ["clientAuth"]},
    "mapping": {"type": "san-upn"},
}

UBUNTU = DistroInfo(
    id="ubuntu", version_id="24.04", pretty_name="Ubuntu 24.04", family=FAMILY_DEBIAN
)
RHEL = DistroInfo(id="rhel", version_id="9.4", family=FAMILY_RHEL)
ODD = DistroInfo(id="arch", version_id="", family="unknown")


@pytest.fixture
def on_linux(monkeypatch):
    """Render as if on Linux, with the home provisioner absent."""
    monkeypatch.setattr(util, "is_linux", lambda: True)
    monkeypatch.setattr(runtime, "home_provisioning", lambda: ("", ""))


def home_step(out):
    for step in out.manual_steps:
        if "home director" in step.title.lower():
            return step
    return None


class TestTheStepAppearsWhenItIsNeeded:
    def test_ubuntu_gets_the_pam_auth_update_command(self, on_linux):
        step = home_step(render(SmartCardProfile.from_dict(BASE), version=V_OK,
                                distro=UBUNTU))
        assert step is not None
        assert step.command == "pam-auth-update --enable mkhomedir"

    def test_rhel_gets_authselect_and_oddjobd(self, on_linux):
        step = home_step(render(SmartCardProfile.from_dict(BASE), version=V_OK,
                                distro=RHEL))
        assert step is not None
        assert "with-mkhomedir" in step.command
        # The feature does nothing without the daemon that answers it.
        assert "oddjobd" in step.command

    def test_an_unknown_distro_says_so_instead_of_a_wrong_command(self, on_linux):
        step = home_step(render(SmartCardProfile.from_dict(BASE), version=V_OK,
                                distro=ODD))
        assert step is not None
        assert step.command == ""
        assert "by hand" in step.detail

    def test_the_detail_names_the_symptom_not_just_the_option(self, on_linux):
        step = home_step(render(SmartCardProfile.from_dict(BASE), version=V_OK,
                                distro=UBUNTU))
        # An operator who reads "fallback_homedir only names the path" can tell
        # this apart from the login failing for an authentication reason.
        assert "fallback_homedir" in step.detail
        assert "black screen" in step.detail


class TestItStaysQuietOtherwise:
    def test_a_host_that_already_provisions_homes_is_left_alone(self, monkeypatch):
        monkeypatch.setattr(util, "is_linux", lambda: True)
        monkeypatch.setattr(
            runtime, "home_provisioning", lambda: ("pam_mkhomedir.so", "common-session")
        )
        out = render(SmartCardProfile.from_dict(BASE), version=V_OK, distro=UBUNTU)
        assert home_step(out) is None

    def test_rendering_off_the_target_host_does_not_guess(self, monkeypatch):
        """No /etc/pam.d to read, so the live state is unknown -- say nothing.

        `doctor` on the target covers it; inventing the step here would tell
        every operator to change a stack this run never looked at.
        """
        monkeypatch.setattr(util, "is_linux", lambda: False)
        out = render(SmartCardProfile.from_dict(BASE), version=V_OK, distro=UBUNTU)
        assert home_step(out) is None

    def test_the_smart_card_pam_step_is_still_there(self, on_linux):
        """The new step is additional, not a replacement."""
        out = render(SmartCardProfile.from_dict(BASE), version=V_OK, distro=UBUNTU)
        titles = [s.title for s in out.manual_steps]
        assert any("PAM stack" in t for t in titles)
        assert any("home director" in t.lower() for t in titles)
