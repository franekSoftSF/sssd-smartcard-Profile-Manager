"""Discovering a PKI from one certificate, and fetching what it names.

Verified against a live two-tier PKI: starting from the card's certificate,
following AIA `caIssuers` produced the issuing CA and then the self-signed
root, and both SHA-256 fingerprints matched the trust bundle that had already
been verified against AD's NTAuth store by a different route. That agreement
is the evidence this module works; these tests pin the behaviour around it.

Two distinctions the tests exist to protect:

* **Downloaded is not trusted.** The chain is a proposal. Anyone who can answer
  the AIA URL could otherwise install themselves as a CA whose certificates log
  in, so the fingerprints are reported for out-of-band comparison and the
  report says plainly that nothing was verified.
* **Advertised is not working.** An AIA OCSP URL only means the CA put a URL in
  the certificate. SSSD fails closed on OCSP, so enabling it against a silent
  responder stops every login — which makes "a responder answered" a different
  finding from "a responder is named", and the recommendation turns on it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from sssd_smartcard.ca import discover as disc


@dataclass
class FakeCert:
    """Only the attributes discover.py reads."""

    subject_dn: str
    issuer_dn: str
    ca_issuer_urls: list[str] = field(default_factory=list)
    crl_urls: list[str] = field(default_factory=list)
    ocsp_urls: list[str] = field(default_factory=list)
    pem: str = "-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n"
    _fp: str = "AA:BB"

    def fingerprint(self, algorithm: str = "sha256", **kw) -> str:
        return self._fp


LEAF = "CN=Test,DC=ad,DC=example"
SUB = "CN=Issuing CA,DC=ad,DC=example"
ROOT = "CN=Root CA"

AIA_SUB = "http://pki.example/PKI/Issuing%20CA.crt"
AIA_ROOT = "http://pki.example/PKI/Root%20CA.crt"
CDP_SUB = "http://pki.example/PKI/Issuing%20CA.crl"
OCSP_URL = "http://ocsp.example/ocsp"


def leaf(**kw) -> FakeCert:
    return FakeCert(
        subject_dn=LEAF,
        issuer_dn=SUB,
        ca_issuer_urls=[AIA_SUB],
        crl_urls=[CDP_SUB],
        _fp="LEAF",
        **kw,
    )


def sub() -> FakeCert:
    return FakeCert(
        subject_dn=SUB, issuer_dn=ROOT, ca_issuer_urls=[AIA_ROOT], _fp="SUB"
    )


def root() -> FakeCert:
    # A root is self-signed: subject equals issuer, which is what stops the walk.
    return FakeCert(subject_dn=ROOT, issuer_dn=ROOT, _fp="ROOT")


@pytest.fixture
def fetcher(monkeypatch):
    """Serve certificates by URL; record what was requested."""
    served: dict[str, FakeCert] = {AIA_SUB: sub(), AIA_ROOT: root()}
    calls: list[str] = []

    def fake_http_get(url, *, timeout=20, post=None, content_type=None):
        calls.append(url)
        if url in served:
            return b"DER", ""
        return b"", f"{url}: 404"

    def fake_load_any(data, source):
        return [served[source]] if source in served else []

    monkeypatch.setattr(disc, "http_get", fake_http_get)
    monkeypatch.setattr(disc, "_load_any", fake_load_any)
    return calls, served


class TestChainWalking:
    def test_the_whole_chain_is_fetched_to_the_root(self, fetcher):
        report = disc.discover(leaf(), probe_responders=False)
        assert [c.subject_dn for c in report.chain] == [SUB, ROOT]
        assert report.complete_chain is True

    def test_each_fetch_is_recorded_so_the_source_is_auditable(self, fetcher):
        report = disc.discover(leaf(), probe_responders=False)
        assert any(AIA_SUB in n for n in report.notes)
        assert any(AIA_ROOT in n for n in report.notes)

    def test_a_chain_stopping_at_an_intermediate_is_flagged(self, monkeypatch):
        monkeypatch.setattr(
            disc, "http_get", lambda url, **kw: (b"DER", "") if url == AIA_SUB else (b"", "404")
        )
        monkeypatch.setattr(
            disc, "_load_any", lambda d, source: [sub()] if source == AIA_SUB else []
        )
        report = disc.discover(leaf(), probe_responders=False)
        assert [c.subject_dn for c in report.chain] == [SUB]
        assert report.complete_chain is False
        assert any("self-signed root" in n for n in report.notes)

    def test_a_certificate_with_no_aia_reports_why(self, monkeypatch):
        monkeypatch.setattr(disc, "http_get", lambda url, **kw: (b"", "unused"))
        bare = FakeCert(subject_dn=LEAF, issuer_dn=SUB)
        report = disc.discover(bare, probe_responders=False)
        assert report.chain == []
        assert any("no HTTP caIssuers" in e for e in report.errors)

    def test_an_aia_loop_is_stopped(self, monkeypatch):
        """A certificate pointing at itself must not loop forever."""
        looping = FakeCert(
            subject_dn=SUB, issuer_dn=ROOT, ca_issuer_urls=[AIA_ROOT], _fp="SUB"
        )
        monkeypatch.setattr(disc, "http_get", lambda url, **kw: (b"DER", ""))
        monkeypatch.setattr(disc, "_load_any", lambda d, source: [looping])
        report = disc.discover(leaf(), probe_responders=False)
        assert any("loops back" in e for e in report.errors)
        assert len(report.chain) < disc.MAX_CHAIN_DEPTH

    def test_a_self_signed_leaf_needs_no_walk(self, monkeypatch):
        monkeypatch.setattr(disc, "http_get", lambda url, **kw: (b"", "should not be called"))
        report = disc.discover(root(), probe_responders=False)
        assert report.chain == []


class TestPkiUrlFallback:
    def test_a_base_url_is_tried_when_the_aia_is_absent(self, monkeypatch):
        requested: list[str] = []

        def fake_get(url, **kw):
            requested.append(url)
            return b"", "404"

        monkeypatch.setattr(disc, "http_get", fake_get)
        bare = FakeCert(subject_dn=LEAF, issuer_dn=SUB)
        disc.discover(bare, pki_url="http://pki.example/PKI/", probe_responders=False)
        # The issuer's CN is the conventional filename on an AD CS web host.
        assert any("Issuing%20CA.crt" in u for u in requested)
        assert any(u.endswith(".p7b") for u in requested)

    def test_the_base_url_is_not_used_when_the_aia_works(self, fetcher):
        calls, _ = fetcher
        disc.discover(leaf(), pki_url="http://other.example/", probe_responders=False)
        assert calls[0] == AIA_SUB


class TestCrlCollection:
    def test_crl_urls_come_from_the_leaf_and_every_ca(self, monkeypatch):
        sub_with_cdp = FakeCert(
            subject_dn=SUB,
            issuer_dn=ROOT,
            ca_issuer_urls=[AIA_ROOT],
            crl_urls=["http://pki.example/PKI/Root%20CA.crl"],
            _fp="SUB",
        )
        served = {AIA_SUB: sub_with_cdp, AIA_ROOT: root()}
        monkeypatch.setattr(
            disc, "http_get", lambda url, **kw: (b"DER", "") if url in served else (b"", "404")
        )
        monkeypatch.setattr(
            disc, "_load_any", lambda d, source: [served[source]] if source in served else []
        )
        report = disc.discover(leaf(), probe_responders=False)
        assert CDP_SUB in report.crl_urls
        assert "http://pki.example/PKI/Root%20CA.crl" in report.crl_urls

    def test_an_ldap_only_distribution_point_is_explained(self, monkeypatch):
        monkeypatch.setattr(disc, "http_get", lambda url, **kw: (b"", "404"))
        ldap_leaf = FakeCert(
            subject_dn=LEAF,
            issuer_dn=SUB,
            crl_urls=["ldap:///CN=Issuing%20CA?certificateRevocationList"],
        )
        report = disc.discover(ldap_leaf, probe_responders=False)
        assert report.crl_urls == []
        assert any("LDAP URLs" in n for n in report.notes)


class TestOcspProbing:
    def test_a_working_responder_drives_the_recommendation(self, fetcher, monkeypatch):
        monkeypatch.setattr(
            disc,
            "probe_ocsp",
            lambda c, i, url, **kw: disc.OcspProbe(
                url=url, attempted=True, answered=True, status="good"
            ),
        )
        report = disc.discover(leaf(ocsp_urls=[OCSP_URL]))
        assert report.ocsp_works is True
        assert report.revocation_method == "ocsp"

    def test_an_advertised_but_silent_responder_falls_back_to_crl(
        self, fetcher, monkeypatch
    ):
        """SSSD fails closed on OCSP, so this distinction decides the config."""
        monkeypatch.setattr(
            disc,
            "probe_ocsp",
            lambda c, i, url, **kw: disc.OcspProbe(
                url=url, attempted=True, answered=False, error="timed out"
            ),
        )
        report = disc.discover(leaf(ocsp_urls=[OCSP_URL]))
        assert report.ocsp_advertised is True
        assert report.ocsp_works is False
        assert report.revocation_method == "crl"
        checks = disc.discovery_checks(report)
        reason = [c for c in checks if c.name == "recommended revocation"][0].detail
        assert "did not answer" in reason

    def test_no_responder_advertised_says_so_rather_than_blaming_one(
        self, fetcher
    ):
        report = disc.discover(leaf(), probe_responders=True)
        assert report.ocsp == []
        checks = disc.discovery_checks(report)
        reason = [c for c in checks if c.name == "recommended revocation"][0].detail
        assert "advertises no OCSP responder" in reason

    def test_an_unknown_status_is_not_counted_as_working(self):
        probe = disc.OcspProbe(
            url=OCSP_URL, attempted=True, answered=True, status="unknown"
        )
        assert probe.working is False

    def test_a_revoked_verdict_still_counts_as_a_working_responder(self):
        probe = disc.OcspProbe(
            url=OCSP_URL, attempted=True, answered=True, status="revoked"
        )
        assert probe.working is True

    def test_probing_is_skipped_without_the_issuer(self, monkeypatch):
        monkeypatch.setattr(disc, "http_get", lambda url, **kw: (b"", "404"))
        bare = FakeCert(subject_dn=LEAF, issuer_dn=SUB, ocsp_urls=[OCSP_URL])
        report = disc.discover(bare)
        assert len(report.ocsp) == 1
        assert report.ocsp[0].attempted is False
        assert "issuer certificate" in report.ocsp[0].error


class TestChecks:
    def test_the_trust_caveat_is_always_present_when_a_chain_was_fetched(self, fetcher):
        report = disc.discover(leaf(), probe_responders=False)
        trust = [c for c in disc.discovery_checks(report) if c.name == "CA trust"][0]
        assert trust.status == "WARN"
        assert "not trusting it" in trust.hint

    def test_fingerprints_are_reported_for_comparison(self, fetcher):
        report = disc.discover(leaf(), probe_responders=False)
        details = " ".join(c.detail for c in disc.discovery_checks(report))
        assert "SHA-256 SUB" in details
        assert "SHA-256 ROOT" in details

    def test_no_revocation_at_all_is_stated_plainly(self, monkeypatch):
        monkeypatch.setattr(disc, "http_get", lambda url, **kw: (b"", "404"))
        bare = FakeCert(subject_dn=LEAF, issuer_dn=SUB)
        report = disc.discover(bare, probe_responders=False)
        assert report.revocation_method == "none"
        verdict = [
            c for c in disc.discovery_checks(report) if c.name == "recommended revocation"
        ][0]
        assert verdict.status == "WARN"
        assert "still log in" in verdict.detail

    def test_a_failed_chain_fetch_is_a_hard_failure(self, monkeypatch):
        monkeypatch.setattr(disc, "http_get", lambda url, **kw: (b"", "404"))
        bare = FakeCert(subject_dn=LEAF, issuer_dn=SUB)
        report = disc.discover(bare, probe_responders=False)
        chain = [c for c in disc.discovery_checks(report) if c.name == "CA chain"][0]
        assert chain.status == "FAIL"


class TestBundle:
    def test_the_bundle_is_the_fetched_chain_as_pem(self, fetcher):
        report = disc.discover(leaf(), probe_responders=False)
        pem = report.bundle_pem()
        assert pem.count(b"BEGIN CERTIFICATE") == 2

    def test_an_empty_chain_yields_an_empty_bundle(self):
        assert disc.DiscoveryReport().bundle_pem() == b""
