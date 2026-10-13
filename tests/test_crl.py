"""CRL handling, with the rules measured against SSSD 2.9.4.

The point of all of this: without revocation checking, a revoked card still
logs in. Where there is no OCSP responder, a CRL is the only mechanism, and
SSSD reads it from one local PEM file that nothing refreshes by itself.

Four behaviours were measured with ``p11_child --verification
--verify=crl_file=...`` on a real two-tier PKI, and none of them is in
``sssd.conf(5)``:

===================================================  ======  =========================
``--verify``                                         result  reason
===================================================  ======  =========================
(no CRL)                                             pass    baseline
``crl_file=<issuing CA CRL>``                        FAIL    ``[3][unable to get certificate CRL]``
``crl_file=<root CA CRL>``                           FAIL    ``[3][unable to get certificate CRL]``
``crl_file=<both, concatenated>``                    pass
``crl_file=<both, reversed order>``                  pass    order is irrelevant
``soft_crl,crl_file=<issuing only>``                 FAIL    forgives expiry, not absence
``ocsp_dgst=sha256,crl_file=<issuing only>``         FAIL    OCSP does not relax it
``partial_chain,crl_file=<both>``                    FAIL    incompatible with crl_file
===================================================  ======  =========================

So: one current CRL per CA in the chain, concatenated into one file;
``partial_chain`` must never be emitted alongside ``crl_file``; and
``ocsp+crl`` cannot mean "OCSP at the issuing CA, CRL only at the root".

A fifth fact is about *finding* the CRLs. A certificate's
``crlDistributionPoints`` names the CRL that would revoke **that
certificate** -- published by its issuer. So the issuing CA's CRL is
advertised by the card's certificate, and the root's by the issuing CA's
certificate. Reading each CA's own CDP finds the root's CRL twice and the
issuing CA's never, which is exactly what the first implementation did.
"""

from __future__ import annotations

import datetime as _dt

import pytest

from sssd_smartcard.ca import crl as crlmod
from sssd_smartcard.certmap.compat import Version
from sssd_smartcard.certmap.renderer import render
from sssd_smartcard.model.profile import SmartCardProfile

V = Version.parse("2.9.4")


def profile(**revocation) -> SmartCardProfile:
    data = {
        "apiVersion": "sssd-smartcard/v1",
        "name": "AD-PIV-UPN",
        "domain": "domain-b.local",
        "provider": "ad",
        "certificate": {"issuer": "CN=CA,DC=domain-a,DC=local", "eku": ["clientAuth"]},
        "mapping": {"type": "san-upn"},
    }
    if revocation:
        data["revocation"] = revocation
    return SmartCardProfile.from_dict(data)


def verification_of(out) -> str:
    for change in out.changes:
        if change.key in ("certificate_verification", "pam_cert_verification"):
            return change.value
    return ""


CRL_SPEC = {
    "enabled": True,
    "method": "crl",
    "crl_file": "/etc/sssd/pki/revocation.crl.pem",
}


class TestRenderedVerification:
    def test_crl_method_emits_crl_file_and_disables_ocsp(self):
        """Their PKI has no OCSP AIA, so OCSP must be off or nothing verifies."""
        out = render(profile(**CRL_SPEC), version=V)
        values = verification_of(out)
        assert "crl_file=/etc/sssd/pki/revocation.crl.pem" in values
        assert "no_ocsp" in values

    def test_the_whole_chain_requirement_is_warned_about(self):
        out = render(profile(**CRL_SPEC), version=V)
        assert any("EVERY CA in the chain" in w for w in out.warnings)

    def test_fail_mode_open_emits_soft_crl(self):
        out = render(profile(**CRL_SPEC, fail_mode="open"), version=V)
        assert "soft_crl" in verification_of(out)

    def test_soft_crl_is_described_as_no_safety_net_for_a_missing_crl(self):
        out = render(profile(**CRL_SPEC, fail_mode="open"), version=V)
        assert any("never a missing one" in w for w in out.warnings)

    def test_method_crl_without_a_file_is_refused_at_the_profile(self):
        """Caught when the profile loads, which is earlier than the renderer."""
        from sssd_smartcard.errors import ProfileError

        with pytest.raises(ProfileError) as excinfo:
            profile(enabled=True, method="crl")
        assert "requires crl_file" in str(excinfo.value)


class TestPartialChainIsIncompatible:
    """Measured: a complete CRL set that passes alone fails with partial_chain."""

    def _render_with_partial_chain(self, **revocation):
        data = {
            "apiVersion": "sssd-smartcard/v1",
            "name": "X",
            "domain": "domain-b.local",
            "provider": "ad",
            "certificate": {"issuer": "CN=CA,DC=a,DC=local"},
            "mapping": {"type": "san-upn"},
            "validation": {"partial_chain": True},
        }
        if revocation:
            data["revocation"] = revocation
        return render(SmartCardProfile.from_dict(data), version=V)

    def test_partial_chain_is_dropped_when_crl_checking_is_on(self):
        out = self._render_with_partial_chain(**CRL_SPEC)
        values = verification_of(out)
        assert "partial_chain" not in values
        assert "crl_file" in values

    def test_dropping_it_is_explained_not_silent(self):
        out = self._render_with_partial_chain(**CRL_SPEC)
        assert any("partial_chain was dropped" in w for w in out.warnings)

    def test_partial_chain_survives_when_there_is_no_crl(self):
        out = self._render_with_partial_chain()
        assert "partial_chain" in verification_of(out)


class TestMixedOcspAndCrl:
    """'OCSP at the subca, CRL only at the root' is not expressible."""

    def test_ocsp_plus_crl_notes_that_ocsp_does_not_relax_the_crl_rule(self):
        out = render(
            profile(enabled=True, method="ocsp+crl", crl_file="/x/crl.pem"), version=V
        )
        note = " ".join(out.notes)
        assert "does NOT relax the CRL requirement" in note
        assert "every CA in the chain" in note

    def test_both_mechanisms_are_still_emitted(self):
        out = render(
            profile(
                enabled=True,
                method="ocsp+crl",
                crl_file="/x/crl.pem",
                ocsp_digest="sha256",
            ),
            version=V,
        )
        values = verification_of(out)
        assert "crl_file=/x/crl.pem" in values
        assert "ocsp_dgst=sha256" in values
        assert "no_ocsp" not in values


class TestCrlParsing:
    def test_a_file_with_two_concatenated_pem_crls_parses_as_two(self):
        """The shape SSSD requires has to round-trip."""
        data = (
            b"-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n"
            b"-----BEGIN X509 CRL-----\nBBBB\n-----END X509 CRL-----\n"
        )
        assert len(crlmod._PEM_CRL_RE.findall(data)) == 2

    def test_junk_is_rejected_with_a_message_about_der(self):
        from sssd_smartcard.errors import CertificateError

        with pytest.raises(CertificateError) as excinfo:
            crlmod.load_crls(b"not a crl at all", source="x.crl")
        assert "DER" in str(excinfo.value)

    def test_an_ldap_distribution_point_is_refused_clearly(self):
        from sssd_smartcard.errors import CertificateError

        with pytest.raises(CertificateError) as excinfo:
            crlmod.fetch_crl("ldap:///CN=CA,CN=AIA?certificateRevocationList")
        assert "LDAP" in str(excinfo.value)

    def test_a_non_http_scheme_is_refused(self):
        from sssd_smartcard.errors import CertificateError

        with pytest.raises(CertificateError):
            crlmod.fetch_crl("file:///etc/passwd")


class TestRememberedSources:
    """The timer runs with no card, so the URLs must be recorded."""

    def test_round_trip(self, tmp_path):
        path = tmp_path / "crl-sources.json"
        crlmod.save_sources({"cn=issuing": "http://pki/issuing.crl"}, path)
        assert crlmod.load_sources(path) == {"cn=issuing": "http://pki/issuing.crl"}

    def test_saving_merges_rather_than_replacing(self, tmp_path):
        path = tmp_path / "crl-sources.json"
        crlmod.save_sources({"cn=a": "http://pki/a.crl"}, path)
        crlmod.save_sources({"cn=b": "http://pki/b.crl"}, path)
        assert crlmod.load_sources(path) == {
            "cn=a": "http://pki/a.crl",
            "cn=b": "http://pki/b.crl",
        }

    def test_a_missing_file_is_empty_not_an_error(self, tmp_path):
        assert crlmod.load_sources(tmp_path / "absent.json") == {}

    def test_corrupt_json_is_empty_not_an_error(self, tmp_path):
        path = tmp_path / "crl-sources.json"
        path.write_text("{not json", encoding="utf-8")
        assert crlmod.load_sources(path) == {}

    def test_an_unwritable_path_does_not_raise(self, tmp_path):
        """Failing to remember must not fail the refresh that worked."""
        crlmod.save_sources({"cn=a": "http://x"}, tmp_path / "no" / "such" / "d" / "f")


class FakeCrl:
    """Enough of a CRL for the freshness logic."""

    def __init__(self, issuer: str, days: float | None, revoked: int = 0):
        self._issuer = issuer
        self._days = days
        self._revoked = revoked

    @property
    def issuer(self) -> str:
        return self._issuer

    @property
    def next_update(self):
        if self._days is None:
            return None
        return _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=self._days)

    @property
    def days_left(self):
        return self._days

    @property
    def expired(self) -> bool:
        return self._days is not None and self._days <= 0

    @property
    def revoked_count(self) -> int:
        return self._revoked


class TestCoverageAndFreshnessChecks:
    def test_a_missing_ca_crl_is_a_hard_fail_naming_the_lockout(self):
        plan = crlmod.CrlPlan(
            crls=[FakeCrl("CN=Issuing", 7, revoked=5)], missing=["CN=Root"]
        )
        checks = crlmod.crl_plan_checks(plan)
        coverage = [c for c in checks if c.name == "CRL coverage"][0]
        assert coverage.status == "FAIL"
        assert "NOBODY can log in" in coverage.hint

    def test_a_complete_set_passes(self):
        plan = crlmod.CrlPlan(
            cas=[object(), object()],
            crls=[FakeCrl("CN=Issuing", 7), FakeCrl("CN=Root", 300)],
        )
        coverage = [
            c for c in crlmod.crl_plan_checks(plan) if c.name == "CRL coverage"
        ][0]
        assert coverage.status == "PASS"

    def test_an_expired_crl_fails(self):
        plan = crlmod.CrlPlan(crls=[FakeCrl("CN=Issuing", -1)])
        check = [c for c in crlmod.crl_plan_checks(plan) if c.name.startswith("CRL CN")][0]
        assert check.status == "FAIL"
        assert "EXPIRED" in check.detail
        assert "fails closed" in check.hint

    def test_a_crl_expiring_soon_warns(self):
        plan = crlmod.CrlPlan(crls=[FakeCrl("CN=Issuing", 1)])
        check = [c for c in crlmod.crl_plan_checks(plan) if c.name.startswith("CRL CN")][0]
        assert check.status == "WARN"

    def test_a_fresh_crl_passes(self):
        plan = crlmod.CrlPlan(crls=[FakeCrl("CN=Issuing", 7)])
        check = [c for c in crlmod.crl_plan_checks(plan) if c.name.startswith("CRL CN")][0]
        assert check.status == "PASS"

    def test_plan_completeness_requires_crls_and_no_gaps(self):
        assert not crlmod.CrlPlan().complete
        assert not crlmod.CrlPlan(crls=[FakeCrl("a", 5)], missing=["b"]).complete
        assert crlmod.CrlPlan(crls=[FakeCrl("a", 5)]).complete

    def test_soonest_expiry_picks_the_nearest(self):
        plan = crlmod.CrlPlan(
            crls=[FakeCrl("root", 300), FakeCrl("issuing", 7), FakeCrl("none", None)]
        )
        assert plan.soonest_expiry.issuer == "issuing"


class TestTimerUnits:
    def test_both_units_are_produced(self):
        units = crlmod.timer_units(bundle="/etc/sssd/pki/ca.pem")
        assert set(units) == {crlmod.SERVICE_UNIT, crlmod.TIMER_UNIT}

    def test_the_service_runs_the_update_command_with_the_right_paths(self):
        units = crlmod.timer_units(
            bundle="/etc/sssd/pki/ca.pem", crl_file="/etc/sssd/pki/r.pem"
        )
        service = units[crlmod.SERVICE_UNIT]
        assert "ca crl update" in service
        assert "--bundle /etc/sssd/pki/ca.pem" in service
        assert "--crl-file /etc/sssd/pki/r.pem" in service

    def test_the_service_may_write_the_crl_directory(self):
        units = crlmod.timer_units(
            bundle="/x/ca.pem", crl_file="/etc/sssd/pki/r.pem"
        )
        assert "ReadWritePaths=/etc/sssd/pki" in units[crlmod.SERVICE_UNIT]

    def test_the_timer_catches_up_after_downtime(self):
        """An expired CRL fails closed, so a missed run cannot simply be skipped."""
        units = crlmod.timer_units(bundle="/x/ca.pem")
        assert "Persistent=true" in units[crlmod.TIMER_UNIT]

    def test_the_schedule_is_configurable(self):
        units = crlmod.timer_units(bundle="/x/ca.pem", on_calendar="hourly")
        assert "OnCalendar=hourly" in units[crlmod.TIMER_UNIT]
