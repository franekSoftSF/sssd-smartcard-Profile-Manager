"""The KDC's half of PKINIT: does its certificate let MIT Kerberos do this?

Measured against the real domain controller. `dc01` presents a certificate
from Microsoft's older *Domain Controller* template:

    EKU: TLS Web Client Authentication, TLS Web Server Authentication
    SAN: othername: 1.3.6.1.4.1.311.25.1, DNS:DC01.ad.example.com

RFC 4556 wants `id-pkinit-KPKdc` (1.3.6.1.5.2.3.5) and an `id-pkinit-san`
otherName (1.3.6.1.5.2.2). Windows accepts the certificate above for backwards
compatibility; MIT Kerberos does not, because `pkinit_eku_checking` defaults to
`kpKDC`. The visible symptom was a PIN prompt followed by a password prompt --
PKINIT engaged, rejected the KDC, and kinit fell back.

Setting `pkinit_eku_checking = kpServerAuth` and `pkinit_kdc_hostname` fixed it,
verified: `KRB5_TRACE confirms PA-PK-AS-REQ`.

Sources: RFC 4556 section 3.2.4; krb5.conf(5) `pkinit_eku_checking` (default
`kpKDC`), `pkinit_kdc_hostname` (its presence accepts a dNSName SAN "rather
than requiring the id-pkinit-san").
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sssd_smartcard.krb5 import kdccert


@dataclass
class FakeSan:
    dns: list[str] = field(default_factory=list)
    pkinit: list[str] = field(default_factory=list)
    upn: list[str] = field(default_factory=list)


@dataclass
class FakeCert:
    # These names must match CertificateInfo exactly.  An earlier version of
    # this file used `subject`/`issuer`, which CertificateInfo does not have:
    # every test passed and the real code raised AttributeError on the live DC.
    subject_dn: str = "CN=DC01.ad.example.com"
    issuer_dn: str = "CN=Example Issuing CA"
    eku_oids: list[str] = field(default_factory=list)
    eku_labels: list[str] = field(default_factory=list)
    san: FakeSan = field(default_factory=FakeSan)


def dc_template() -> kdccert.KdcCertificate:
    """What dc01 actually presents."""
    cert = FakeCert(
        eku_oids=[kdccert.OID_SERVER_AUTH, "1.3.6.1.5.5.7.3.2"],
        eku_labels=["serverAuth", "clientAuth"],
        san=FakeSan(dns=["DC01.ad.example.com"]),
    )
    return kdccert.KdcCertificate(
        host="dc01.ad.example.com", fetched=True, chain=[cert]
    )


def kerberos_template() -> kdccert.KdcCertificate:
    """What a Kerberos Authentication template issues."""
    cert = FakeCert(
        eku_oids=[kdccert.OID_PKINIT_KP_KDC, kdccert.OID_SERVER_AUTH],
        eku_labels=["id-pkinit-KPKdc", "serverAuth"],
        san=FakeSan(
            dns=["DC01.ad.example.com"],
            pkinit=["krbtgt/AD.EXAMPLE.COM@AD.EXAMPLE.COM"],
        ),
    )
    return kdccert.KdcCertificate(
        host="dc01.ad.example.com", fetched=True, chain=[cert]
    )


class TestTheRealDomainControllerCertificate:
    def test_it_is_not_rfc4556_compliant(self):
        assert dc_template().rfc4556_compliant is False

    def test_it_lacks_the_kdc_eku(self):
        assert dc_template().has_kdc_eku is False

    def test_it_lacks_the_pkinit_san(self):
        assert dc_template().has_pkinit_san is False

    def test_it_does_have_server_auth_and_a_dns_name(self):
        cert = dc_template()
        assert cert.has_server_auth is True
        assert cert.dns_names == ["DC01.ad.example.com"]

    def test_the_required_options_are_exactly_the_two_that_fixed_it(self):
        assert dc_template().required_options() == {
            "pkinit_eku_checking": "kpServerAuth",
            "pkinit_kdc_hostname": "DC01.ad.example.com",
        }


class TestACompliantCertificate:
    def test_it_is_recognised_as_compliant(self):
        assert kerberos_template().rfc4556_compliant is True

    def test_it_needs_no_client_side_options(self):
        assert kerberos_template().required_options() == {}

    def test_the_check_passes_without_advice(self):
        checks = kdccert.kdc_certificate_checks(kerberos_template())
        statuses = {c.status for c in checks}
        assert statuses == {"PASS"}
        assert not any("needs" in c.name for c in checks)


class TestChecks:
    def test_the_dc_template_is_a_warning_with_the_exact_options(self):
        checks = kdccert.kdc_certificate_checks(dc_template())
        suitability = [c for c in checks if "suitability" in c.name][0]
        assert suitability.status == "WARN"
        assert "pkinit_eku_checking = kpServerAuth" in suitability.hint
        assert "pkinit_kdc_hostname = DC01.ad.example.com" in suitability.hint

    def test_the_hint_explains_why_windows_works_and_mit_does_not(self):
        checks = kdccert.kdc_certificate_checks(dc_template())
        hint = " ".join(c.hint for c in checks)
        assert "kpKDC" in hint
        assert "Windows" in hint

    def test_each_needed_option_is_also_its_own_info_line(self):
        checks = kdccert.kdc_certificate_checks(dc_template())
        needed = {c.name: c.detail for c in checks if c.name.startswith("needs ")}
        assert needed == {
            "needs pkinit_eku_checking": "kpServerAuth",
            "needs pkinit_kdc_hostname": "DC01.ad.example.com",
        }

    def test_a_certificate_with_neither_eku_nor_dns_name_is_a_hard_fail(self):
        """Nothing on the client can relax this far; the DC must be reissued."""
        cert = FakeCert(eku_oids=["1.3.6.1.5.5.7.3.3"], eku_labels=["codeSigning"])
        bare = kdccert.KdcCertificate(host="dc", fetched=True, chain=[cert])
        assert bare.required_options() == {}
        suitability = [
            c for c in kdccert.kdc_certificate_checks(bare) if "suitability" in c.name
        ][0]
        assert suitability.status == "FAIL"
        assert "Kerberos Authentication template" in suitability.hint

    def test_an_unreachable_dc_warns_and_does_not_pretend_to_know(self):
        cert = kdccert.KdcCertificate(host="dc", fetched=False, error="connection refused")
        checks = kdccert.kdc_certificate_checks(cert)
        assert [c.status for c in checks] == ["WARN"]
        assert "connection refused" in checks[0].detail
        assert "openssl s_client" in checks[0].hint


class TestFetching:
    def test_a_response_without_a_certificate_is_an_error(self, monkeypatch):
        from sssd_smartcard.util import CommandResult

        monkeypatch.setattr(kdccert, "which", lambda name: "/usr/bin/openssl")
        monkeypatch.setattr(
            kdccert,
            "run",
            lambda argv, **kw: CommandResult(list(argv), 1, "", "connect: refused"),
        )
        cert = kdccert.fetch_kdc_certificate("dc.example.com")
        assert cert.fetched is False
        assert "no certificate received" in cert.error

    def test_a_missing_openssl_is_reported_not_crashed(self, monkeypatch):
        monkeypatch.setattr(kdccert, "which", lambda name: None)
        cert = kdccert.fetch_kdc_certificate("dc.example.com")
        assert cert.fetched is False
        assert "openssl" in cert.error

    def test_it_never_sends_anything_but_the_handshake(self, monkeypatch):
        """Read-only: empty stdin, no credentials, no write operations."""
        from sssd_smartcard.util import CommandResult

        seen = {}
        monkeypatch.setattr(kdccert, "which", lambda name: "/usr/bin/openssl")

        def fake_run(argv, **kw):
            seen["argv"] = list(argv)
            seen["input_text"] = kw.get("input_text")
            return CommandResult(list(argv), 0, "", "")

        monkeypatch.setattr(kdccert, "run", fake_run)
        kdccert.fetch_kdc_certificate("dc.example.com")
        assert seen["input_text"] == ""
        assert seen["argv"][:2] == ["openssl", "s_client"]
        assert "dc.example.com:636" in seen["argv"]


class TestTheFakesMatchTheRealClass:
    """A fake with the wrong attribute names tests nothing.

    This file originally gave FakeCert `subject`/`issuer`; CertificateInfo has
    `subject_dn`/`issuer_dn`. Sixteen tests passed and the code raised
    AttributeError the first time it met a real certificate. This guards the
    contract so the fakes cannot drift away from it again.
    """

    def test_every_fake_cert_field_exists_on_certificateinfo(self):
        from dataclasses import fields

        from sssd_smartcard.x509.inspect import CertificateInfo

        for name in (f.name for f in fields(FakeCert)):
            assert hasattr(CertificateInfo, name), (
                f"FakeCert.{name} does not exist on CertificateInfo, so any test "
                "relying on it proves nothing about the real code"
            )

    def test_every_fake_san_field_exists_on_saninfo(self):
        from dataclasses import fields

        from sssd_smartcard.x509.inspect import SanInfo

        real = {f.name for f in fields(SanInfo)}
        for name in (f.name for f in fields(FakeSan)):
            assert name in real, f"FakeSan.{name} is not a field of SanInfo"

    def test_the_attributes_kdccert_reads_are_all_real(self):
        """Names the module reaches for, checked against the real classes."""
        from sssd_smartcard.x509.inspect import CertificateInfo, SanInfo

        for name in ("subject_dn", "issuer_dn", "eku_oids", "eku_labels", "san"):
            assert hasattr(CertificateInfo, name), name
        for name in ("dns", "pkinit"):
            assert name in {f.name for f in SanInfo.__dataclass_fields__.values()}
