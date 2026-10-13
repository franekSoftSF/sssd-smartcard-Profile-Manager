"""local_auth_policy -- the option that decides PIN prompt versus password prompt.

Measured on SSSD 2.9.4 with a real YubiKey PIV certificate.  Everything else was
already right -- the certmap rule loaded, p11_child read and verified the card,
``sssctl cert-map`` resolved the account, PAM carried ``try_cert_auth`` -- and
login still asked for a password.  Raising ``debug_level`` showed why:

    [pam] [pam_reply] (0x0400): [CID#1] Local auth policy allowed:
                                        smartcard [False], passkey [True]

``local_auth_policy`` defaults to ``match``, meaning "offer whatever the backend
offers", and the AD backend has no Smart Card authentication of its own.  So
SSSD declined the card it had just verified.  Nothing in the certmap tooling can
show this, which is why it is both rendered and checked now.

Sources: sssd.conf(5) local_auth_policy; introduced in SSSD 2.9.2 and extended
to local Smart Card authentication in 2.9.3.
"""

from __future__ import annotations

import pytest

from sssd_smartcard.certmap.compat import Version
from sssd_smartcard.certmap.renderer import render
from sssd_smartcard.errors import ProfileError, UnsupportedFeature
from sssd_smartcard.model.profile import AuthenticationSpec, SmartCardProfile
from sssd_smartcard.sssdconf.apply import build_plan
from sssd_smartcard.sssdconf.runtime import local_auth_policy_checks

V_OK = Version.parse("2.9.4")
V_OLD = Version.parse("2.9.0")

BASE = {
    "apiVersion": "sssd-smartcard/v1",
    "name": "AD-PIV-UPN",
    "domain": "domain-b.local",
    "provider": "ad",
    "certificate": {"issuer": "CN=CA,DC=domain-a,DC=local", "eku": ["clientAuth"]},
    "mapping": {"type": "san-upn", "domains": ["domain-a.local"]},
}


def profile(**auth) -> SmartCardProfile:
    data = dict(BASE)
    if auth:
        data["authentication"] = auth
    return SmartCardProfile.from_dict(data)


def policy_of(out, domain: str = "domain-b.local") -> str | None:
    for change in out.changes:
        if change.section == f"domain/{domain}" and change.key == "local_auth_policy":
            return change.value
    return None


class TestRendering:
    def test_ad_gets_local_smartcard_enabled_by_default(self):
        out = render(profile(), version=V_OK)
        assert policy_of(out) == "enable:smartcard"

    def test_ldap_gets_it_too(self):
        data = dict(BASE, provider="ldap")
        out = render(SmartCardProfile.from_dict(data), version=V_OK)
        assert policy_of(out) == "enable:smartcard"

    def test_ipa_is_left_alone(self):
        """IPA authenticates the card through the backend, so do not override it."""
        data = dict(BASE, provider="ipa")
        out = render(SmartCardProfile.from_dict(data), version=V_OK)
        assert policy_of(out) is None

    def test_it_lands_in_the_domain_section_not_pam(self):
        out = render(profile(), version=V_OK)
        sections = {c.section for c in out.changes if c.key == "local_auth_policy"}
        assert sections == {"domain/domain-b.local"}

    def test_the_note_explains_the_pin_prompt_and_the_missing_tgt(self):
        out = render(profile(), version=V_OK)
        note = " ".join(out.notes)
        assert "PIN" in note
        assert "TGT" in note

    def test_opting_out_warns_that_the_card_will_be_refused(self):
        out = render(profile(mode="optional", local_smartcard=False), version=V_OK)
        assert policy_of(out) is None
        assert any("still ask for a password" in w for w in out.warnings)

    def test_an_explicit_policy_is_passed_through_verbatim(self):
        out = render(
            profile(local_auth_policy="enable:smartcard, enable:passkey"), version=V_OK
        )
        assert policy_of(out) == "enable:smartcard, enable:passkey"

    def test_an_explicit_policy_without_smartcard_claims_nothing_about_pins(self):
        out = render(profile(local_auth_policy="enable:passkey"), version=V_OK)
        assert policy_of(out) == "enable:passkey"
        assert not any("PIN" in n for n in out.notes)


class TestVersionGate:
    def test_an_explicit_request_on_an_old_sssd_is_refused(self):
        with pytest.raises(UnsupportedFeature) as excinfo:
            render(profile(local_smartcard=True), version=V_OLD)
        assert "2.9.3" in str(excinfo.value)

    def test_allow_degraded_turns_the_refusal_into_a_warning(self):
        out = render(profile(local_smartcard=True), version=V_OLD, allow_degraded=True)
        assert policy_of(out) is None
        assert any("2.9.3" in w for w in out.warnings)

    def test_the_provider_default_degrades_without_refusing_to_render(self):
        """An unversioned run must still produce a usable configuration."""
        out = render(profile(), version=V_OLD)
        assert policy_of(out) is None
        assert any("PKINIT" in w for w in out.warnings)
        assert any(c.key == "matchrule" for c in out.changes)


class TestPolicyValues:
    @pytest.mark.parametrize(
        "value,expected",
        [
            (None, False),
            ("match", False),
            ("only", False),
            ("enable:passkey", False),
            ("enable:smartcard", True),
            ("ENABLE:SMARTCARD", True),
            ("enable:passkey, enable:smartcard", True),
            ("enable:smartcard, disable:smartcard", False),
        ],
    )
    def test_policy_enables_smartcard(self, value, expected):
        assert AuthenticationSpec.policy_enables_smartcard(value) is expected

    def test_an_undocumented_value_is_refused_not_written_out(self):
        with pytest.raises(ProfileError) as excinfo:
            profile(local_auth_policy="enable:fingerprint")
        assert "not a documented value" in str(excinfo.value)

    def test_an_undocumented_verb_is_refused(self):
        with pytest.raises(ProfileError):
            profile(local_auth_policy="allow:smartcard")

    def test_whitespace_is_normalised(self):
        spec = profile(local_auth_policy="  enable:smartcard ,  only ").authentication
        assert spec.local_auth_policy == "enable:smartcard, only"

    def test_it_round_trips_through_the_profile_dict(self):
        original = profile(local_smartcard=True, local_auth_policy="enable:smartcard")
        again = SmartCardProfile.from_dict(original.to_dict())
        assert again.authentication.local_smartcard is True
        assert again.authentication.local_auth_policy == "enable:smartcard"

    def test_an_unset_value_is_not_serialised(self):
        assert "local_smartcard" not in profile().authentication.to_dict()


EXISTING = (
    "[sssd]\n"
    "config_file_version = 2\n"
    "domains = domain-b.local\n"
    "services = nss, pam\n"
    "\n"
    "[domain/domain-b.local]\n"
    "id_provider = ad\n"
    "ad_domain = domain-b.local\n"
)


def write_config(tmp_path, text: str):
    path = tmp_path / "sssd.conf"
    path.write_text(text, encoding="utf-8")
    return path


class TestMergingAnExistingPolicy:
    def test_an_existing_passkey_policy_is_extended_not_replaced(self, tmp_path):
        path = write_config(tmp_path, EXISTING + "local_auth_policy = enable:passkey\n")
        plan = build_plan(profile(), config_path=path, version=V_OK)
        assert "local_auth_policy = enable:passkey, enable:smartcard" in plan.after
        assert any("added rather than replacing" in w for w in plan.warnings)

    def test_an_identical_policy_is_left_alone(self, tmp_path):
        path = write_config(
            tmp_path, EXISTING + "local_auth_policy = enable:smartcard\n"
        )
        plan = build_plan(profile(), config_path=path, version=V_OK)
        assert not any("local_auth_policy" in w for w in plan.warnings)
        assert "enable:smartcard, enable:smartcard" not in plan.after

    def test_only_is_never_merged_silently(self, tmp_path):
        path = write_config(tmp_path, EXISTING + "local_auth_policy = only\n")
        plan = build_plan(profile(), config_path=path, version=V_OK)
        assert any("not merged automatically" in w for w in plan.warnings)
        assert "local_auth_policy = only" in plan.after

    def test_a_fresh_config_just_gets_the_value(self, tmp_path):
        path = write_config(tmp_path, EXISTING)
        plan = build_plan(profile(), config_path=path, version=V_OK)
        assert "local_auth_policy = enable:smartcard" in plan.after


class TestDiagnostics:
    def test_an_unset_policy_on_an_ad_domain_is_a_failure(self, tmp_path):
        path = write_config(tmp_path, EXISTING)
        policies, checks = local_auth_policy_checks(path)
        assert policies == {}
        assert [c.status for c in checks] == ["FAIL"]
        assert "enable:smartcard" in checks[0].hint

    def test_an_enabled_policy_passes(self, tmp_path):
        path = write_config(
            tmp_path, EXISTING + "local_auth_policy = enable:smartcard\n"
        )
        policies, checks = local_auth_policy_checks(path)
        assert policies == {"domain-b.local": "enable:smartcard"}
        assert [c.status for c in checks] == ["PASS"]

    def test_the_check_names_the_option_so_it_is_greppable(self, tmp_path):
        path = write_config(tmp_path, EXISTING)
        _, checks = local_auth_policy_checks(path)
        assert checks[0].name == "local_auth_policy domain-b.local"

    def test_a_missing_config_is_not_a_crash(self, tmp_path):
        policies, checks = local_auth_policy_checks(tmp_path / "nope.conf")
        assert policies == {}
        assert all(c.status in ("WARN", "PASS") for c in checks)
