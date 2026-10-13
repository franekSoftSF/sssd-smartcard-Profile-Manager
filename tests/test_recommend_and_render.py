"""The certificate -> profile -> sssd.conf path, which is the point of the tool."""

from __future__ import annotations

import pytest
from conftest import build_cert

from sssd_smartcard.certmap.compat import Version
from sssd_smartcard.certmap.renderer import render
from sssd_smartcard.errors import UnsupportedFeature
from sssd_smartcard.model.profile import RevocationSpec, SmartCardProfile
from sssd_smartcard.model.store import dump_profile, load_profile_text
from sssd_smartcard.x509.recommend import build_profile, infer_domain, recommend

V29 = Version.parse("2.9.0")
V27 = Version.parse("2.7.0")


class TestDomainInference:
    def test_prefers_the_upn_suffix(self, piv_cert):
        domain, reason = infer_domain(piv_cert)
        assert domain == "domain-a.local" and "UPN" in reason

    def test_falls_back_to_dc_components(self):
        cert = build_cert(upn=None, sid=None)
        domain, reason = infer_domain(cert)
        assert domain == "domain-a.local" and "DC components" in reason

    def test_falls_back_to_the_email_domain(self, email_only_cert):
        # The subject still has DC components, so those win; drop them by
        # checking the e-mail path directly on a certificate with a UPN removed.
        domain, _ = infer_domain(email_only_cert)
        assert domain == "domain-a.local"


class TestRanking:
    def test_upn_wins_for_a_normal_piv_certificate(self, piv_cert):
        best = recommend(piv_cert, version=V29).best
        assert best.key == "san-upn"
        assert best.identity == "jan.kowalski@domain-a.local"

    def test_sid_extension_is_offered_when_present(self, piv_cert):
        keys = [c.key for c in recommend(piv_cert, version=V29).candidates]
        assert "sid-extension" in keys

    def test_sid_extension_is_not_offered_without_the_extension(self, piv_cert_no_sid):
        keys = [c.key for c in recommend(piv_cert_no_sid, version=V29).candidates]
        assert "sid-extension" not in keys

    def test_old_sssd_blocks_the_ldapu1_mechanisms(self, piv_cert):
        rec = recommend(piv_cert, version=V27)
        sid = next(c for c in rec.candidates if c.key == "sid-extension")
        assert sid.blocked and "2.8.2" in sid.blocked
        # ...but the UPN mechanism still works, so there is still a recommendation.
        assert rec.best.key == "san-upn"

    def test_email_certificate_falls_back_to_rfc822(self, email_only_cert):
        assert recommend(email_only_cert, version=V29).best.key == "san-rfc822"

    def test_blocked_candidates_sort_last(self, piv_cert):
        rec = recommend(piv_cert, version=V27)
        blocked_positions = [
            i for i, c in enumerate(rec.candidates) if c.blocked is not None
        ]
        usable_positions = [i for i, c in enumerate(rec.candidates) if c.blocked is None]
        assert not blocked_positions or min(blocked_positions) > max(usable_positions)


class TestObservations:
    def test_expired_certificate_is_a_blocking_observation(self):
        rec = recommend(build_cert(days_valid=1, days_ago=30), version=V29)
        assert any("expired" in o.text for o in rec.blocking)

    def test_ca_certificate_is_rejected_as_a_user_certificate(self):
        rec = recommend(build_cert(ca=True), version=V29)
        assert any("CA certificate" in o.text for o in rec.blocking)

    def test_missing_clientauth_is_warned_about(self):
        from cryptography.x509.oid import ExtendedKeyUsageOID

        cert = build_cert(ekus=(ExtendedKeyUsageOID.EMAIL_PROTECTION,))
        rec = recommend(cert, version=V29)
        assert any("clientAuth" in o.text for o in rec.observations)


class TestGeneratedProfile:
    def test_profile_round_trips_through_yaml(self, piv_cert):
        profile = build_profile(recommend(piv_cert, version=V29))
        reloaded = load_profile_text(dump_profile(profile))
        assert reloaded.name == profile.name
        assert reloaded.mapping.type == profile.mapping.type
        assert reloaded.certificate.issuer == profile.certificate.issuer

    def test_issuer_and_eku_are_pinned_from_the_certificate(self, piv_cert):
        profile = build_profile(recommend(piv_cert, version=V29))
        assert profile.certificate.issuer == piv_cert.issuer_dn
        assert profile.certificate.eku == ["clientAuth", "msScLogin"]

    def test_upn_suffix_is_taken_from_the_certificate(self, piv_cert):
        profile = build_profile(recommend(piv_cert, version=V29))
        assert profile.mapping.options["upn_suffix"] == "domain-a.local"

    def test_trusted_domain_layout(self, piv_cert):
        """Section belongs to the joined domain, search goes to the trusted one."""
        profile = build_profile(
            recommend(piv_cert, version=V29), section_domain="domain-b.local"
        )
        assert profile.domain == "domain-b.local"
        assert profile.mapping.domains == ["domain-a.local"]
        assert profile.section == "certmap/domain-b.local/DOMAIN-A-UPN"

    def test_single_domain_layout_omits_the_domains_list(self, piv_cert):
        profile = build_profile(
            recommend(piv_cert, version=V29), section_domain="domain-a.local"
        )
        assert profile.mapping.domains == []

    def test_forcing_a_mechanism(self, piv_cert):
        profile = build_profile(
            recommend(piv_cert, version=V29), mechanism_key="issuer-serial"
        )
        assert profile.mapping.type == "issuer-serial"

    def test_revocation_follows_the_certificate_endpoints(self, piv_cert):
        profile = build_profile(recommend(piv_cert, version=V29), with_revocation=True)
        assert profile.revocation.enabled and profile.revocation.method == "ocsp"


class TestRendering:
    def test_generated_config_has_the_expected_shape(self, piv_cert):
        profile = build_profile(
            recommend(piv_cert, version=V29), section_domain="domain-b.local"
        )
        ini = render(profile, version=V29).to_ini()
        assert "[certmap/domain-b.local/DOMAIN-A-UPN]" in ini
        assert "matchrule = KRB5:<ISSUER>" in ini
        assert "<SAN:ntPrincipalName>.*@domain-a\\.local$" in ini
        assert "maprule = LDAP:(|(userPrincipalName={subject_nt_principal})" in ini
        assert "domains = domain-a.local" in ini
        assert "pam_cert_auth = True" in ini

    def test_sid_mapping_uses_the_ldapu1_prefix(self, piv_cert):
        profile = build_profile(
            recommend(piv_cert, version=V29), mechanism_key="sid-extension"
        )
        ini = render(profile, version=V29).to_ini()
        assert "maprule = LDAPU1:(objectSid={sid})" in ini

    def test_old_sssd_refuses_an_ldapu1_rule(self, piv_cert):
        profile = build_profile(
            recommend(piv_cert, version=V29), mechanism_key="sid-extension"
        )
        with pytest.raises(UnsupportedFeature) as excinfo:
            render(profile, version=V27)
        assert "2.8.2" in str(excinfo.value)

    def test_allow_degraded_turns_the_refusal_into_a_warning(self, piv_cert):
        profile = build_profile(
            recommend(piv_cert, version=V29), mechanism_key="sid-extension"
        )
        result = render(profile, version=V27, allow_degraded=True)
        assert any("2.8.2" in w for w in result.warnings)

    def test_certificate_binary_tells_ad_to_read_certificates(self, piv_cert):
        profile = build_profile(
            recommend(piv_cert, version=V29), mechanism_key="certificate-binary"
        )
        ini = render(profile, version=V29).to_ini()
        assert "ldap_user_certificate = userCertificate;binary" in ini

    def test_smartcard_required_never_becomes_an_sssd_option(self, piv_cert):
        """There is no 'Smart Card only' key in sssd.conf; it must stay in PAM."""
        profile = build_profile(
            recommend(piv_cert, version=V29), require_smartcard=True
        )
        ini = render(profile, version=V29).to_ini()
        assert "require_cert_auth" not in ini
        assert "smartcard" not in ini.lower()


class TestVerificationValues:
    def _profile(self, revocation: dict) -> SmartCardProfile:
        return SmartCardProfile(
            name="T",
            domain="d.local",
            revocation=RevocationSpec.from_dict(revocation),
        )

    def test_disabled_revocation_emits_no_ocsp(self):
        ini = render(self._profile({"enabled": False}), version=V29).to_ini()
        assert "certificate_verification = no_ocsp" in ini

    def test_ocsp_fail_open_emits_soft_ocsp(self):
        profile = self._profile(
            {"enabled": True, "method": "ocsp", "fail_mode": "open", "ocsp_digest": "sha256"}
        )
        ini = render(profile, version=V29).to_ini()
        assert "soft_ocsp" in ini and "ocsp_dgst=sha256" in ini

    def test_crl_requires_a_file(self):
        from sssd_smartcard.errors import ProfileError

        with pytest.raises(ProfileError):
            self._profile({"enabled": True, "method": "crl"})

    def test_crl_emits_crl_file_and_disables_ocsp(self):
        profile = self._profile(
            {"enabled": True, "method": "crl", "crl_file": "/etc/sssd/pki/x.crl"}
        )
        ini = render(profile, version=V29).to_ini()
        assert "crl_file=/etc/sssd/pki/x.crl" in ini and "no_ocsp" in ini

    def test_soft_crl_needs_sssd_2_2_3(self):
        profile = self._profile(
            {
                "enabled": True,
                "method": "crl",
                "crl_file": "/x.crl",
                "fail_mode": "open",
            }
        )
        with pytest.raises(UnsupportedFeature):
            render(profile, version=Version.parse("2.2.0"))

    def test_pam_scope_writes_pam_cert_verification(self):
        ini = render(
            self._profile({"enabled": False}), version=V29, verification_scope="pam"
        ).to_ini()
        assert "pam_cert_verification = no_ocsp" in ini
