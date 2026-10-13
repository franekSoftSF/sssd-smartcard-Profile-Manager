"""Certificate Inspector: parsing the fields SSSD templates depend on."""

from __future__ import annotations

import pytest
from conftest import SID, UPN, build_cert

from sssd_smartcard.errors import CertificateError
from sssd_smartcard.x509.inspect import (
    eku_certmap_token,
    load_certificate,
    normalise_eku,
)
from sssd_smartcard.x509.names import format_dn


class TestSubjectAlternativeName:
    def test_decodes_the_microsoft_upn_othername(self, piv_cert):
        assert piv_cert.san.upn == [UPN]

    def test_decodes_a_krb5_pkinit_principal(self, pkinit_cert):
        assert pkinit_cert.san.pkinit == ["jan.kowalski@DOMAIN-A.LOCAL"]

    def test_principals_covers_both_upn_and_pkinit(self, piv_cert):
        assert UPN in piv_cert.principals

    def test_rfc822_is_read(self, email_only_cert):
        assert email_only_cert.san.rfc822 == ["jan.kowalski@example.com"]

    def test_empty_san_is_reported_as_empty(self):
        cert = build_cert(upn=None, sid=None)
        assert cert.san.empty


class TestSidExtension:
    def test_decodes_the_ad_security_extension(self, piv_cert):
        assert piv_cert.sid == SID

    def test_absent_extension_yields_none(self, piv_cert_no_sid):
        assert piv_cert_no_sid.sid is None


class TestDistinguishedNames:
    def test_ldap_order_is_most_specific_first(self, piv_cert):
        assert piv_cert.subject_dn.startswith("CN=Jan Kowalski")
        assert piv_cert.subject_dn.endswith("DC=local")

    def test_x500_order_is_reversed(self, piv_cert):
        assert piv_cert.subject_dn_as("ad_x500").startswith("DC=local")
        assert piv_cert.subject_dn_as("ad_x500").endswith("CN=Jan Kowalski")

    def test_issuer_ad_x500_matches_what_ad_stores(self, piv_cert):
        assert (
            piv_cert.issuer_dn_as("ad_x500")
            == "DC=local,DC=domain-a,CN=Enterprise Issuing CA"
        )

    def test_unknown_style_is_rejected(self, piv_cert):
        with pytest.raises(ValueError):
            format_dn(piv_cert.cert.subject, "klingon")

    def test_dc_components_give_the_domain(self, piv_cert):
        assert piv_cert.dc_domain == "domain-a.local"


class TestSerialNumber:
    def test_plain_hex(self, piv_cert):
        assert piv_cert.serial_hex() == "4a3b2c1d5e6f7a8b"

    def test_ad_altsecurityidentities_form_is_upper_and_reversed(self, piv_cert):
        # AD stores the serial byte-reversed and upper case: {serial_number!hex_ur}
        assert piv_cert.serial_hex(upper=True, reverse=True) == "8B7A6F5E1D2C3B4A"

    def test_colon_separated(self, piv_cert):
        assert piv_cert.serial_hex(colon=True, upper=True) == "4A:3B:2C:1D:5E:6F:7A:8B"


class TestExtendedKeyUsage:
    def test_smartcard_logon_spellings_all_normalise_to_the_oid(self):
        oid = "1.3.6.1.4.1.311.20.2.2"
        for spelling in ("smartCardLogon", "smartcardlogin", "msScLogin", oid):
            assert normalise_eku(spelling) == oid

    def test_sssd_keyword_is_used_where_documented(self):
        assert eku_certmap_token("1.3.6.1.4.1.311.20.2.2") == "msScLogin"
        assert eku_certmap_token("1.3.6.1.5.5.7.3.2") == "clientAuth"

    def test_undocumented_oids_stay_oids(self):
        # We never invent a keyword; an OID is always valid in a matching rule.
        assert eku_certmap_token("1.3.6.1.4.1.99999.1") == "1.3.6.1.4.1.99999.1"

    def test_unknown_name_is_rejected(self):
        with pytest.raises(CertificateError):
            normalise_eku("definitelyNotAnEku")


class TestValidityAndMetadata:
    def test_expiry_is_detected(self):
        cert = build_cert(days_valid=1, days_ago=10)
        assert cert.expired

    def test_a_current_certificate_is_not_expired(self, piv_cert):
        assert not piv_cert.expired and piv_cert.days_remaining > 300

    def test_ca_flag(self, piv_cert):
        assert not piv_cert.is_ca
        assert build_cert(ca=True).is_ca

    def test_revocation_endpoints_are_surfaced(self, piv_cert):
        assert piv_cert.ocsp_urls == ["http://pki.domain-a.local/ocsp"]
        assert piv_cert.crl_urls == ["http://pki.domain-a.local/crl/issuing.crl"]

    def test_to_dict_is_json_friendly(self, piv_cert):
        import json

        json.dumps(piv_cert.to_dict())

    def test_public_key_is_named_without_a_leading_underscore(self, piv_cert):
        """cryptography's class is _RSAPublicKey; output must not say "_RSA"."""
        assert piv_cert.public_key_algorithm == "RSA 2048 bit"
        assert not piv_cert.public_key_algorithm.startswith("_")


class TestLoading:
    def test_pem_der_and_base64_all_parse_to_the_same_certificate(self, piv_cert):
        from base64 import b64encode

        pem = load_certificate(piv_cert.pem.encode())
        der = load_certificate(piv_cert.der_bytes)
        b64 = load_certificate(b64encode(piv_cert.der_bytes))
        fingerprints = {c.fingerprint("sha256") for c in (pem, der, b64)}
        assert fingerprints == {piv_cert.fingerprint("sha256")}

    def test_garbage_raises_a_clear_error(self):
        with pytest.raises(CertificateError):
            load_certificate(b"not a certificate at all")

    def test_empty_input_raises(self):
        with pytest.raises(CertificateError):
            load_certificate(b"   ")
