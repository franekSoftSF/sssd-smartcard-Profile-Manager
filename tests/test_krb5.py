"""Kerberos: ccache parsing, PKINIT command construction, certificate readiness."""

from __future__ import annotations

from conftest import build_cert

from sssd_smartcard.krb5 import check as krb5

KLIST_OUTPUT = """\
Ticket cache: KEYRING:persistent:1000:1000
Default principal: jan.kowalski@DOMAIN-A.LOCAL

Valid starting       Expires              Service principal
09/24/26 08:12:03    09/24/26 18:12:03    krbtgt/DOMAIN-A.LOCAL@DOMAIN-A.LOCAL
	renew until 10/01/26 08:12:00
	Flags: FRIA
09/24/26 08:12:10    09/24/26 18:12:03    cifs/fs1.domain-a.local@DOMAIN-A.LOCAL
"""


class TestCcacheParsing:
    def _parse(self, text: str) -> krb5.CredentialCache:
        """Drive the parser the way read_ccache does, without running klist."""
        out = krb5.CredentialCache(available=True)
        current = None
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("ticket cache:"):
                out.cache_name = stripped.split(":", 1)[1].strip()
            elif stripped.lower().startswith("default principal:"):
                out.principal = stripped.split(":", 1)[1].strip()
            elif stripped.lower().startswith("renew until"):
                if current:
                    current.renew_until = stripped[len("renew until") :].strip()
            elif stripped.startswith("Flags:"):
                if current:
                    current.flags = stripped.split(":", 1)[1].strip()
            else:
                match = krb5._TICKET_RE.match(line.rstrip())
                if match and ("/" in match.group("service") or "@" in match.group("service")):
                    current = krb5.Ticket(
                        service=match.group("service"),
                        valid_from=match.group("from"),
                        expires=match.group("to"),
                    )
                    out.tickets.append(current)
        return out

    def test_principal_and_cache(self):
        cache = self._parse(KLIST_OUTPUT)
        assert cache.principal == "jan.kowalski@DOMAIN-A.LOCAL"
        assert cache.cache_name == "KEYRING:persistent:1000:1000"
        assert cache.realm == "DOMAIN-A.LOCAL"

    def test_the_tgt_is_identified_among_service_tickets(self):
        cache = self._parse(KLIST_OUTPUT)
        assert len(cache.tickets) == 2
        assert cache.tgt is not None
        assert cache.tgt.service == "krbtgt/DOMAIN-A.LOCAL@DOMAIN-A.LOCAL"
        assert cache.tgt.renew_until.startswith("10/01/26")
        assert cache.tgt.flags == "FRIA"

    def test_a_cache_without_a_tgt_reports_none(self):
        text = KLIST_OUTPUT.replace("krbtgt/DOMAIN-A.LOCAL@DOMAIN-A.LOCAL", "cifs/x@R")
        assert self._parse(text).tgt is None


class TestPkinitCommand:
    def test_builds_the_documented_kinit_invocation(self):
        argv = krb5.pkinit_command(
            "jan.kowalski@DOMAIN-A.LOCAL",
            module="/usr/lib64/pkcs11/opensc-pkcs11.so",
        )
        assert argv[0] == "kinit"
        assert "X509_user_identity=PKCS11:/usr/lib64/pkcs11/opensc-pkcs11.so" in argv
        assert argv[-1] == "jan.kowalski@DOMAIN-A.LOCAL"

    def test_anchors_are_passed_as_a_file_uri(self):
        argv = krb5.pkinit_command(
            "u@R", module="/m.so", anchors="/etc/sssd/pki/sssd_auth_ca_db.pem"
        )
        assert "X509_anchors=FILE:/etc/sssd/pki/sssd_auth_ca_db.pem" in argv

    def test_enterprise_principal_flag(self):
        assert "-E" in krb5.pkinit_command("u@R", module="/m.so", enterprise=True)
        assert "-E" not in krb5.pkinit_command("u@R", module="/m.so")

    def test_a_dedicated_cache_keeps_the_operators_ticket_safe(self):
        argv = krb5.pkinit_command("u@R", module="/m.so", cache="FILE:/tmp/test-cc")
        assert argv[argv.index("-c") + 1] == "FILE:/tmp/test-cc"

    def test_no_pin_ever_appears_on_the_command_line(self):
        argv = krb5.pkinit_command("u@R", module="/m.so", cert_id="01")
        joined = " ".join(argv).lower()
        assert "pin" not in joined


class TestCertificateReadiness:
    def _status(self, checks, name):
        return next(c.status for c in checks if c.name == name)

    def test_a_piv_certificate_is_ready(self, piv_cert):
        checks = krb5.certificate_pkinit_readiness(piv_cert)
        assert self._status(checks, "certificate EKU") == "PASS"
        assert self._status(checks, "certificate principal") == "PASS"
        assert self._status(checks, "certificate validity") == "PASS"

    def test_missing_smartcard_logon_eku_is_warned_about(self):
        from cryptography.x509.oid import ExtendedKeyUsageOID

        cert = build_cert(ekus=(ExtendedKeyUsageOID.CLIENT_AUTH,))
        checks = krb5.certificate_pkinit_readiness(cert)
        assert self._status(checks, "Smart Card Logon EKU") == "WARN"

    def test_no_principal_in_the_san_fails(self):
        cert = build_cert(upn=None, sid=None)
        checks = krb5.certificate_pkinit_readiness(cert)
        assert self._status(checks, "certificate principal") == "FAIL"

    def test_an_expired_certificate_fails(self):
        cert = build_cert(days_valid=1, days_ago=30)
        checks = krb5.certificate_pkinit_readiness(cert)
        assert self._status(checks, "certificate validity") == "FAIL"


class TestReportOffHost:
    def test_report_skips_cleanly_when_not_on_the_sssd_host(self, monkeypatch):
        monkeypatch.setattr(krb5, "is_linux", lambda: False)
        report = krb5.report()
        assert [c.status for c in report.checks] == ["SKIP"]
        assert report.ok
