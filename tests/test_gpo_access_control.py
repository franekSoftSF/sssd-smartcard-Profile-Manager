"""access_provider = ad denies the login *after* the card has authenticated.

Measured on the lab host. The card was read, the PIN accepted, the certmap rule
resolved the account, and pam_sss logged `authentication success` -- and the
login was still refused:

    pam_sss(gdm-smartcard:auth):    authentication success; user=...
    pam_sss(gdm-smartcard:account): Access denied for user ...: 4 (System error)

The account phase failed, not the auth phase. `access_provider = ad` -- which
`realm join` writes, not this tool -- makes SSSD evaluate the Windows logon
rights through GPO, and `ad_gpo_access_control` defaults to **enforcing**. One
unreadable Group Policy Container was enough:

    ad_gpo_process_gpo_done: Unable to get GPO list from server ...: [14](Bad address)
    ad_gpo_access_done: GPO-based access control failed.

GDM reported all of it as "smart card authentication didn't work", which sends
the operator to the card. The profile model has carried a docstring warning
about this default since it was written; it just never reached an operator,
because gpo.manage defaults to false and nothing said anything.
"""

from __future__ import annotations

import pytest

from sssd_smartcard.certmap.compat import Version
from sssd_smartcard.model.profile import SmartCardProfile
from sssd_smartcard.sssdconf.apply import build_plan

V_OK = Version.parse("2.9.4")

BASE = {
    "apiVersion": "sssd-smartcard/v1",
    "name": "AD-PIV-UPN",
    "domain": "ad.example.com",
    "provider": "ad",
    "certificate": {"issuer": "CN=CA,DC=ad,DC=example,DC=com", "eku": ["clientAuth"]},
    "mapping": {"type": "san-upn"},
}

JOINED = """[sssd]
domains = ad.example.com
config_file_version = 2
services = nss, pam

[domain/ad.example.com]
id_provider = ad
ad_domain = ad.example.com
use_fully_qualified_names = True
"""


def write(tmp_path, body: str):
    path = tmp_path / "sssd.conf"
    path.write_text(body, encoding="utf-8")
    return path


def profile(**gpo):
    data = dict(BASE)
    if gpo:
        data["gpo"] = gpo
    return SmartCardProfile.from_dict(data)


def gpo_check(plan):
    for check in plan.checks:
        if check.name == "GPO access control":
            return check
    return None


class TestTheWarning:
    def test_access_provider_ad_without_the_option_warns(self, tmp_path):
        path = write(tmp_path, JOINED + "access_provider = ad\n")
        check = gpo_check(build_plan(profile(), config_path=path, version=V_OK))
        assert check is not None
        assert check.status == "WARN"
        assert "enforcing" in check.detail

    def test_the_hint_names_the_phase_and_how_to_test_it(self, tmp_path):
        """An operator who reads 'account phase' stops suspecting the card."""
        path = write(tmp_path, JOINED + "access_provider = ad\n")
        check = gpo_check(build_plan(profile(), config_path=path, version=V_OK))
        assert "account phase" in check.hint
        # authenticate alone passed while the real login failed.
        assert "acct_mgmt" in check.hint
        assert "permissive" in check.hint


class TestItStaysQuiet:
    def test_an_explicit_setting_is_not_second_guessed(self, tmp_path):
        path = write(
            tmp_path,
            JOINED + "access_provider = ad\nad_gpo_access_control = permissive\n",
        )
        assert gpo_check(build_plan(profile(), config_path=path, version=V_OK)) is None

    def test_the_profile_setting_its_own_value_silences_it(self, tmp_path):
        """The profile writes ad_gpo_access_control, so there is nothing to warn
        about -- the check must read the config as it will be, not as it was."""
        path = write(tmp_path, JOINED + "access_provider = ad\n")
        plan = build_plan(
            profile(manage=True, access_control="permissive"),
            config_path=path,
            version=V_OK,
        )
        assert "ad_gpo_access_control = permissive" in plan.after
        assert gpo_check(plan) is None

    def test_another_access_provider_is_not_affected(self, tmp_path):
        path = write(tmp_path, JOINED + "access_provider = permit\n")
        assert gpo_check(build_plan(profile(), config_path=path, version=V_OK)) is None

    def test_no_access_provider_at_all_is_not_affected(self, tmp_path):
        """Unset means 'permit' in sssd.conf(5), not 'ad'."""
        path = write(tmp_path, JOINED)
        assert gpo_check(build_plan(profile(), config_path=path, version=V_OK)) is None
