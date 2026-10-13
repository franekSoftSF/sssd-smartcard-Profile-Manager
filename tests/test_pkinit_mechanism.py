"""A ticket is not proof that the card produced it.

On the verified lab host `krb5 test --from-card --pkinit` reported

    [PASS] PKINIT  the KDC issued krbtgt/AD.EXAMPLE.COM@... for ...

and it was wrong. The MIT PKINIT plugin was not installed, so kinit ignored
`-X X509_user_identity=PKCS11:...`, prompted `Password for <principal>` instead
of a PIN, authenticated with the account password, and returned a perfectly
valid TGT. KRB5_TRACE showed exactly what happened:

    Error loading plugin module pkinit: 2/unable to load plugin
        [.../krb5/plugins/preauth/pkinit.so]: cannot open shared object file
    Processing preauth types: PA-PK-AS-REQ (16), PA-PK-AS-REP_OLD (15),
                              PA-ETYPE-INFO2 (19), PA-ENC-TIMESTAMP (2)
    Preauth module encrypted_timestamp (2) (real) returned: 0/Success

The KDC *did* offer PKINIT; the client could not use it. So the verdict must
come from the trace, never from "exit status 0 and a ticket in the cache" --
the same mistake as reading "no match" out of an error message that merely
contains the word "matching".
"""

from __future__ import annotations

from sssd_smartcard.krb5 import check as krb5

TRACE_PASSWORD_FALLBACK = (
    "[25060] 1791754451.560767: Error loading plugin module pkinit: 2/unable to "
    "load plugin [/usr/lib/x86_64-linux-gnu/krb5/plugins/preauth/pkinit.so]: "
    "cannot open shared object file: No such file or directory\n"
    "[25060] 1791754451.560780: Preauthenticating using KDC method data\n"
    "[25060] 1791754451.560781: Processing preauth types: PA-PK-AS-REQ (16), "
    "PA-PK-AS-REP_OLD (15), PA-ETYPE-INFO2 (19), PA-ENC-TIMESTAMP (2)\n"
    "[25060] 1791754451.560782: Selected etype info: etype aes256-cts\n"
    "[25060] 1791754451.560783: Preauth module encrypted_timestamp (2) (real) "
    "returned: 0/Success\n"
)

TRACE_REAL_PKINIT = (
    "[300] 1791754999.1: Processing preauth types: PA-PK-AS-REQ (16), "
    "PA-ETYPE-INFO2 (19), PA-ENC-TIMESTAMP (2)\n"
    "[300] 1791754999.2: PKINIT client computed kdc-req-body checksum\n"
    "[300] 1791754999.3: Preauth module pkinit (16) (real) returned: 0/Success\n"
)

TRACE_WRONG_PASSWORD = (
    "[1] 1.1: Processing preauth types: PA-PK-AS-REQ (16), PA-ENC-TIMESTAMP (2)\n"
    "[1] 1.2: Preauth module encrypted_timestamp (2) (real) returned: "
    "-1765328254/Cannot read password\n"
)


class TestInterpretTrace:
    def test_a_password_fallback_is_recognised(self):
        info = krb5.interpret_trace(TRACE_PASSWORD_FALLBACK)
        assert info["used_password"] is True
        assert info["used_pkinit"] is False
        assert info["plugin_load_failures"] == ["pkinit"]

    def test_the_kdc_offering_pkinit_is_recorded_separately(self):
        """The KDC was willing; the client could not. Those are different facts."""
        info = krb5.interpret_trace(TRACE_PASSWORD_FALLBACK)
        assert info["kdc_offers_pkinit"] is True
        assert info["used_pkinit"] is False

    def test_real_pkinit_is_recognised(self):
        info = krb5.interpret_trace(TRACE_REAL_PKINIT)
        assert info["used_pkinit"] is True
        assert info["used_password"] is False
        assert info["plugin_load_failures"] == []

    def test_a_failed_module_is_not_counted_as_success(self):
        info = krb5.interpret_trace(TRACE_WRONG_PASSWORD)
        assert info["modules_succeeded"] == []
        assert info["used_password"] is False
        assert info["used_pkinit"] is False

    def test_an_empty_trace_is_flagged_as_unavailable(self):
        info = krb5.interpret_trace("")
        assert info["trace_available"] is False
        assert info["used_pkinit"] is False

    def test_offered_types_are_listed(self):
        info = krb5.interpret_trace(TRACE_REAL_PKINIT)
        assert any("PA-PK-AS-REQ" in t for t in info["offered"])


class TestPkinitResultVerdict:
    def _result(self, trace: str, *, succeeded: bool = True):
        out = krb5.PkinitResult(attempted=True, succeeded=succeeded)
        out.mechanism = krb5.interpret_trace(trace)
        return out

    def test_a_password_issued_ticket_is_not_proven_pkinit(self):
        result = self._result(TRACE_PASSWORD_FALLBACK)
        assert result.succeeded is True
        assert result.proven_pkinit is False
        assert result.fell_back_to_password is True

    def test_a_card_issued_ticket_is_proven(self):
        result = self._result(TRACE_REAL_PKINIT)
        assert result.proven_pkinit is True
        assert result.fell_back_to_password is False

    def test_a_failed_kinit_proves_nothing(self):
        result = self._result(TRACE_REAL_PKINIT, succeeded=False)
        assert result.proven_pkinit is False

    def test_no_trace_means_not_proven(self):
        result = self._result("")
        assert result.proven_pkinit is False
        assert result.fell_back_to_password is False

    def test_the_dict_exposes_the_distinction(self):
        data = self._result(TRACE_PASSWORD_FALLBACK).to_dict()
        assert data["succeeded"] is True
        assert data["proven_pkinit"] is False
        assert data["fell_back_to_password"] is True


class TestRefusingToHarvestAPassword:
    """Without the plugin, kinit must not be run at all."""

    def test_run_pkinit_refuses_when_the_plugin_is_missing(self, monkeypatch):
        called = []
        monkeypatch.setattr(krb5, "pkinit_plugin_path", lambda: "")
        monkeypatch.setattr(krb5, "which", lambda name: "/usr/bin/kinit")
        monkeypatch.setattr(
            krb5,
            "run_interactive",
            lambda *a, **kw: called.append(a) or krb5.CommandResult([], 0, "", ""),
        )
        result = krb5.run_pkinit("testuser@example.com", module="/x/opensc.so")
        assert called == [], "kinit must not run without the PKINIT plugin"
        assert result.attempted is False
        assert result.succeeded is False
        assert "krb5-pkinit" in result.error

    def test_the_refusal_explains_the_password_prompt(self, monkeypatch):
        monkeypatch.setattr(krb5, "pkinit_plugin_path", lambda: "")
        monkeypatch.setattr(krb5, "which", lambda name: "/usr/bin/kinit")
        result = krb5.run_pkinit("testuser@example.com", module="/x/opensc.so")
        assert "password" in result.error.lower()


class TestPluginDiscovery:
    def test_a_missing_plugin_returns_empty(self, monkeypatch, tmp_path):
        monkeypatch.setattr(krb5, "PREAUTH_PLUGIN_DIRS", (str(tmp_path),))
        assert krb5.pkinit_plugin_path() == ""

    def test_a_present_plugin_is_found(self, monkeypatch, tmp_path):
        (tmp_path / "pkinit.so").write_bytes(b"\x7fELF")
        monkeypatch.setattr(krb5, "PREAUTH_PLUGIN_DIRS", (str(tmp_path),))
        assert krb5.pkinit_plugin_path() == str(tmp_path / "pkinit.so")

    def test_the_hint_names_the_package(self):
        assert "krb5-pkinit" in krb5.pkinit_package_hint()


TRACE_PKINIT_REJECTED = (
    "[9] 1.1: Processing preauth types: PA-PK-AS-REQ (16), PA-ENC-TIMESTAMP (2)\n"
    "[9] 1.2: PKINIT client received freshness token from KDC\n"
    "[9] 1.3: PKINIT client could not verify KDC certificate\n"
    "[9] 1.4: Preauth module pkinit (16) (real) returned: "
    "-1765328305/Cannot verify received certificate\n"
    "[9] 1.5: Preauth module encrypted_timestamp (2) (real) returned: "
    "-1765328254/Password incorrect\n"
)


class TestFailureReasonsAreReadFromTheTrace:
    """A PIN prompt followed by a password prompt means PKINIT tried and lost.

    The reason is in the trace; reporting "kinit exited with status 1" plus a
    list of possible causes throws it away.
    """

    def test_the_pkinit_module_failure_is_captured(self):
        info = krb5.interpret_trace(TRACE_PKINIT_REJECTED)
        assert info["pkinit_failures"], "the pkinit module failure must be recorded"
        failure = info["pkinit_failures"][0]
        assert failure["module"] == "pkinit"
        assert failure["code"] == -1765328305
        assert "Cannot verify received certificate" in failure["message"]

    def test_pkinit_trace_lines_are_kept_for_display(self):
        info = krb5.interpret_trace(TRACE_PKINIT_REJECTED)
        assert any("could not verify KDC certificate" in m for m in info["pkinit_messages"])

    def test_a_password_failure_is_also_recorded(self):
        info = krb5.interpret_trace(TRACE_PKINIT_REJECTED)
        modules = {f["module"] for f in info["module_failures"]}
        assert modules == {"pkinit", "encrypted_timestamp"}

    def test_nothing_succeeded_so_nothing_is_proven(self):
        info = krb5.interpret_trace(TRACE_PKINIT_REJECTED)
        assert info["used_pkinit"] is False
        assert info["used_password"] is False

    def test_the_kdc_still_offered_pkinit(self):
        info = krb5.interpret_trace(TRACE_PKINIT_REJECTED)
        assert info["kdc_offers_pkinit"] is True

    def test_a_successful_run_records_no_failures(self):
        info = krb5.interpret_trace(TRACE_REAL_PKINIT)
        assert info["pkinit_failures"] == []
        assert info["module_failures"] == []
