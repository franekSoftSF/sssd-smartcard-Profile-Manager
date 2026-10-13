"""Mapping Tester: local matching and template expansion."""

from __future__ import annotations

from conftest import SID, UPN, build_cert

from sssd_smartcard.certmap.evaluator import evaluate_match, render_map
from sssd_smartcard.certmap.rules import MapRule, MatchRule


def match(text: str, cert) -> bool:
    return evaluate_match(MatchRule.parse(text), cert).matched


class TestMatching:
    def test_issuer_matches(self, piv_cert):
        assert match(r"KRB5:<ISSUER>^CN=Enterprise Issuing CA,DC=domain-a,DC=local$", piv_cert)

    def test_issuer_anchoring_rejects_a_lookalike_ca(self, piv_cert):
        assert not match(r"KRB5:<ISSUER>^CN=Enterprise Issuing CA Two$", piv_cert)

    def test_eku_requires_every_listed_value(self, piv_cert):
        assert match("KRB5:<EKU>clientAuth,msScLogin", piv_cert)
        assert not match("KRB5:<EKU>clientAuth,codeSigning", piv_cert)

    def test_eku_accepts_an_oid(self, piv_cert):
        assert match("KRB5:<EKU>1.3.6.1.4.1.311.20.2.2", piv_cert)

    def test_key_usage(self, piv_cert):
        assert match("KRB5:<KU>digitalSignature,keyEncipherment", piv_cert)
        assert not match("KRB5:<KU>keyCertSign", piv_cert)

    def test_san_upn_suffix(self, piv_cert):
        assert match(r"KRB5:<SAN:ntPrincipalName>.*@domain-a\.local$", piv_cert)
        assert not match(r"KRB5:<SAN:ntPrincipalName>.*@other\.local$", piv_cert)

    def test_missing_san_fails_with_an_explanation(self, email_only_cert):
        result = evaluate_match(
            MatchRule.parse("KRB5:<SAN:ntPrincipalName>.*"), email_only_cert
        )
        assert not result.matched
        assert "no SAN:ntPrincipalName value" in result.failed_terms[0].detail

    def test_conjunction_needs_every_term(self, piv_cert):
        assert not match(
            r"KRB5:<ISSUER>^CN=Enterprise Issuing CA,DC=domain-a,DC=local$"
            r" && <EKU>codeSigning",
            piv_cert,
        )

    def test_disjunction_needs_only_one_branch(self, email_only_cert):
        assert match(
            r"KRB5:<SAN:ntPrincipalName>.* || <SAN:rfc822Name>.*@example\.com",
            email_only_cert,
        )

    def test_an_empty_rule_matches_everything(self, piv_cert):
        assert evaluate_match(MatchRule([]), piv_cert).matched

    def test_base64_keywords_are_left_to_sssctl(self, piv_cert):
        result = evaluate_match(MatchRule.parse("KRB5:<SAN:otherName>MTIz"), piv_cert)
        assert not result.matched
        assert "sssctl" in result.failed_terms[0].detail


class TestTemplateExpansion:
    def test_upn_and_short_name(self, piv_cert):
        result = render_map(
            MapRule(
                "(|(userPrincipalName={subject_nt_principal})"
                "(sAMAccountName={subject_nt_principal.short_name}))"
            ),
            piv_cert,
        )
        assert result.complete
        assert result.filter == (
            f"(|(userPrincipalName={UPN})(sAMAccountName=jan.kowalski))"
        )

    def test_sid(self, piv_cert):
        result = render_map(MapRule("(objectSid={sid})", prefix="LDAPU1"), piv_cert)
        assert result.filter == f"(objectSid={SID})"

    def test_sid_rid_selector(self, piv_cert):
        result = render_map(MapRule("(rid={sid.rid})", prefix="LDAPU1"), piv_cert)
        assert result.filter == "(rid=1104)"

    def test_ad_altsecurityidentities_issuer_serial(self, piv_cert):
        result = render_map(
            MapRule(
                "(altSecurityIdentities=X509:<I>{issuer_dn!ad_x500}"
                "<SR>{serial_number!hex_ur})",
                prefix="LDAPU1",
            ),
            piv_cert,
        )
        assert result.filter == (
            "(altSecurityIdentities=X509:<I>DC=local,DC=domain-a,"
            "CN=Enterprise Issuing CA<SR>8B7A6F5E1D2C3B4A)"
        )

    def test_subject_key_id_upper_hex(self, piv_cert):
        result = render_map(
            MapRule("(ski={subject_key_id!hex_u})", prefix="LDAPU1"), piv_cert
        )
        assert result.filter == f"(ski={piv_cert.subject_key_id.hex().upper()})"

    def test_serial_as_decimal(self, piv_cert):
        result = render_map(
            MapRule("(s={serial_number!dec})", prefix="LDAPU1"), piv_cert
        )
        assert result.filter == f"(s={piv_cert.serial_int})"

    def test_certificate_digest(self, piv_cert):
        result = render_map(
            MapRule("(d={cert!sha256})", prefix="LDAPU1"), piv_cert
        )
        assert result.filter == f"(d={piv_cert.digest_hex('sha256')})"

    def test_certificate_binary_is_an_escaped_hex_sequence(self, piv_cert):
        result = render_map(MapRule("(c={cert!bin})"), piv_cert)
        assert result.filter.startswith("(c=\\30\\82")

    def test_subject_dn_component_by_attribute(self, piv_cert):
        result = render_map(
            MapRule("(cn={subject_dn_component.CN})", prefix="LDAPU1"), piv_cert
        )
        assert result.filter == "(cn=Jan Kowalski)"

    def test_missing_values_are_reported_not_silently_dropped(self, email_only_cert):
        result = render_map(MapRule("(u={subject_nt_principal})"), email_only_cert)
        assert not result.complete
        assert result.missing == ["{subject_nt_principal}"]
        assert result.filter == "(u={subject_nt_principal})"

    def test_pkinit_principal(self, pkinit_cert):
        result = render_map(MapRule("(p={subject_pkinit_principal})"), pkinit_cert)
        assert result.filter == "(p=jan.kowalski@DOMAIN-A.LOCAL)"

    def test_rfc822_short_name(self, email_only_cert):
        result = render_map(
            MapRule("(uid={subject_rfc822_name.short_name})"), email_only_cert
        )
        assert result.filter == "(uid=jan.kowalski)"


class TestEndToEnd:
    def test_profile_rule_matches_its_own_certificate(self, piv_cert):
        from sssd_smartcard.certmap.compat import Version
        from sssd_smartcard.certmap.mappings import build_rule
        from sssd_smartcard.x509.recommend import build_profile, recommend

        version = Version.parse("2.9.0")
        profile = build_profile(recommend(piv_cert, version=version))
        rule = build_rule(profile, version=version)
        assert evaluate_match(rule.matchrule, piv_cert).matched
        assert render_map(rule.maprule, piv_cert).complete

    def test_generated_rule_rejects_a_certificate_from_another_ca(self, piv_cert):
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        from sssd_smartcard.certmap.compat import Version
        from sssd_smartcard.certmap.mappings import build_rule
        from sssd_smartcard.x509.recommend import build_profile, recommend

        version = Version.parse("2.9.0")
        profile = build_profile(recommend(piv_cert, version=version))
        rule = build_rule(profile, version=version)

        import conftest

        original = conftest.ISSUER_DN_PARTS[:]
        try:
            conftest.ISSUER_DN_PARTS[:] = [
                x509.NameAttribute(NameOID.COMMON_NAME, "Rogue CA")
            ]
            rogue = build_cert()
        finally:
            conftest.ISSUER_DN_PARTS[:] = original
        assert not evaluate_match(rule.matchrule, rogue).matched
