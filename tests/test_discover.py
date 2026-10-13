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


# --- browsing a PKI by address, with no certificate -------------------------
#
# The live run caught a NameError in PkiListing.complete_chain that the whole
# suite had missed, because nothing exercised it. These cover that path.

INDEX_HTML = """<html><head><title>pki.example - /PKI/</title></head><body>
<pre><A HREF="/">[To Parent Directory]</A><br>
<A HREF="/PKI/Example%20Issuing%20CA.crl">Example Issuing CA.crl</A><br>
<A HREF="/PKI/Example%20Issuing%20CA.crt">Example Issuing CA.crt</A><br>
<A HREF="/PKI/Example%20Root%20CA.crt">Example Root CA.crt</A><br>
<A HREF="/PKI/web.config">web.config</A><br>
<A HREF="http://elsewhere.example/evil.crt">offsite</A><br>
</pre></body></html>"""


class TestPkiListingChain:
    def test_a_published_root_and_intermediate_is_a_complete_chain(self):
        listing = disc.PkiListing(certificates=[sub(), root()])
        assert listing.complete_chain is True

    def test_an_intermediate_without_its_issuer_is_not(self):
        listing = disc.PkiListing(certificates=[sub()])
        assert listing.complete_chain is False

    def test_a_root_alone_counts_as_complete(self):
        """Nothing is dangling: there are no intermediates to resolve."""
        assert disc.PkiListing(certificates=[root()]).complete_chain is True

    def test_an_empty_listing_is_not_complete(self):
        assert disc.PkiListing().complete_chain is False

    def test_dn_comparison_tolerates_spacing_and_case(self):
        spaced = FakeCert(subject_dn=SUB, issuer_dn="cn=root ca", _fp="SUB")
        listing = disc.PkiListing(certificates=[spaced, root()])
        assert listing.complete_chain is True

    def test_roots_and_intermediates_are_separated(self):
        listing = disc.PkiListing(certificates=[sub(), root()])
        assert [c.subject_dn for c in listing.roots] == [ROOT]
        assert [c.subject_dn for c in listing.intermediates] == [SUB]


class TestBrowsing:
    def _serve(self, monkeypatch, index=INDEX_HTML):
        calls: list[str] = []

        def fake_get(url, *, timeout=20, post=None, content_type=None):
            calls.append(url)
            if url.rstrip("/").endswith("PKI") or url.endswith("/PKI/"):
                return index.encode(), ""
            if url.endswith(".crt"):
                return b"DER", ""
            if url.endswith(".crl"):
                return b"CRLDER", ""
            return b"", f"{url}: 404"

        monkeypatch.setattr(disc, "http_get", fake_get)
        monkeypatch.setattr(disc, "_load_any", lambda d, source: [root()])
        return calls

    def test_only_certificates_and_crls_are_fetched(self, monkeypatch):
        self._serve(monkeypatch)
        listing = disc.browse_pki("http://pki.example/PKI/")
        assert any(u.endswith(".crt") for u in listing.listed)
        assert not any("web.config" in u for u in listing.listed)

    def test_offsite_links_are_not_followed(self, monkeypatch):
        """A URL someone typed is not a licence to crawl."""
        self._serve(monkeypatch)
        listing = disc.browse_pki("http://pki.example/PKI/")
        assert not any("elsewhere.example" in u for u in listing.listed)

    def test_a_bare_hostname_is_accepted(self, monkeypatch):
        calls = self._serve(monkeypatch)
        disc.browse_pki("pki.example/PKI")
        assert calls[0].startswith("http://pki.example/PKI/")

    def test_no_listing_is_reported_rather_than_guessed(self, monkeypatch):
        monkeypatch.setattr(
            disc, "http_get", lambda url, **kw: (b"<html>nothing</html>", "")
        )
        listing = disc.browse_pki("http://pki.example/")
        assert listing.certificates == []
        assert any("no PKI directory found" in e for e in listing.errors)
        # And it must say what to do instead, since the path is a local choice
        # the tool cannot be expected to guess.
        assert any("give the exact URL" in n for n in listing.notes)
        checks = disc.listing_checks(listing)
        assert checks[0].status == "FAIL"

    def test_the_trust_caveat_is_present_when_certificates_were_fetched(
        self, monkeypatch
    ):
        self._serve(monkeypatch)
        listing = disc.browse_pki("http://pki.example/PKI/")
        trust = [c for c in disc.listing_checks(listing) if c.name == "CA trust"]
        assert trust and trust[0].status == "WARN"


class TestADirectFileUrl:
    """--pki-url given a certificate, not a directory.

    Pasting the URL of a root CA certificate is the obvious thing to do with a
    flag called --pki-url. It used to be normalised with a trailing slash and
    asked for as a directory, producing a 404 about a directory that never
    existed and no certificate at all.
    """

    def _serve(self, monkeypatch, *, parent_lists=True):
        fetched: list[str] = []

        def fake_get(url, *, timeout=20, post=None, content_type=None):
            fetched.append(url)
            if url.endswith("/ROOTCA.crt"):
                return b"DER", ""
            if parent_lists and url.endswith("/"):
                return (
                    b'<a href="/ROOTCA.crt">root</a><a href="/SUBCA.crt">sub</a>',
                    "",
                )
            return b"", f"{url}: curl: (22) 404"

        monkeypatch.setattr(disc, "http_get", fake_get)
        monkeypatch.setattr(
            disc,
            "_load_any",
            lambda d, source: [root() if "ROOTCA" in source else sub()],
        )
        return fetched

    def test_the_certificate_itself_is_fetched(self, monkeypatch):
        self._serve(monkeypatch)
        listing = disc.browse_pki("http://pki.example/ROOTCA.crt")
        assert listing.certificates
        assert any("ROOTCA.crt" in u for u in listing.listed)

    def test_no_slash_is_appended_to_the_file(self, monkeypatch):
        fetched = self._serve(monkeypatch)
        disc.browse_pki("http://pki.example/ROOTCA.crt")
        assert "http://pki.example/ROOTCA.crt" in fetched
        assert not any(u.endswith("ROOTCA.crt/") for u in fetched)

    def test_the_parent_directory_is_listed_for_the_siblings(self, monkeypatch):
        self._serve(monkeypatch)
        listing = disc.browse_pki("http://pki.example/ROOTCA.crt")
        assert listing.base == "http://pki.example/"
        assert any("SUBCA.crt" in u for u in listing.listed)

    def test_the_file_is_not_downloaded_twice(self, monkeypatch):
        fetched = self._serve(monkeypatch)
        disc.browse_pki("http://pki.example/ROOTCA.crt")
        assert fetched.count("http://pki.example/ROOTCA.crt") == 1

    def test_a_parent_without_a_listing_is_not_a_failure(self, monkeypatch):
        """The file asked for was fetched; only its siblings are missing."""
        self._serve(monkeypatch, parent_lists=False)
        listing = disc.browse_pki("http://pki.example/ROOTCA.crt")
        assert listing.certificates
        checks = disc.listing_checks(listing)
        assert checks[0].status == "PASS"
        assert any("no directory listing" in n for n in listing.notes)

    def test_a_crl_url_is_loaded_as_a_crl(self, monkeypatch):
        def fake_get(url, **kw):
            return (b"CRLDER", "") if url.endswith(".crl") else (b"", "404")

        monkeypatch.setattr(disc, "http_get", fake_get)
        loaded: list[str] = []
        monkeypatch.setattr(
            "sssd_smartcard.ca.crl.load_crls",
            lambda data, source: loaded.append(source) or [FakeCrlStub()],
        )
        listing = disc.browse_pki("http://pki.example/ROOTCA.crl")
        assert loaded == ["http://pki.example/ROOTCA.crl"]
        assert len(listing.crls) == 1


class FakeCrlStub:
    issuer = "CN=Root CA"
    next_update = None
    expired = False
    revoked_count = 0

    def to_dict(self):
        return {"issuer": self.issuer}


class TestFindingAnUnusualPath:
    """The publishing path is a local choice; detection must not assume one."""

    def test_the_host_root_is_tried_as_well_as_the_url_given(self, monkeypatch):
        tried: list[str] = []

        def fake_get(url, **kw):
            tried.append(url)
            # Only a path nobody would guess relative to the given URL.
            if url == "http://pki.example/repository/":
                return b'<a href="/repository/CA.crt">ca</a>', ""
            if url.endswith("/repository/CA.crt"):
                return b"DER", ""
            return b"", "404"

        monkeypatch.setattr(disc, "http_get", fake_get)
        monkeypatch.setattr(disc, "_load_any", lambda d, s: [root()])
        listing = disc.browse_pki("http://pki.example/deep/nested/path/")
        assert listing.certificates, "a listing at the host root must be found"
        assert any("found a listing at" in n for n in listing.notes)

    def test_a_candidate_is_not_requested_twice(self, monkeypatch):
        tried: list[str] = []
        monkeypatch.setattr(
            disc, "http_get", lambda url, **kw: (tried.append(url), (b"", "404"))[1]
        )
        disc.browse_pki("http://pki.example/")
        assert len(tried) == len(set(tried))


class TestFollowingCertificatePointers:
    """The method an unusual layout cannot defeat.

    A certificate names its issuer's certificate and its own CRL by exact URL,
    so once any certificate is in hand the rest is reachable regardless of
    where the host publishes.
    """

    def test_an_issuer_pointer_is_followed(self, monkeypatch):
        leaf_cert = FakeCert(
            subject_dn=SUB, issuer_dn=ROOT, ca_issuer_urls=[AIA_ROOT], _fp="SUB"
        )

        def fake_get(url, **kw):
            if url == AIA_ROOT:
                return b"DER", ""
            if url.endswith(".crt"):
                return b"DER", ""
            if url.endswith("/"):
                return b'<a href="/SUB.crt">sub</a>', ""
            return b"", "404"

        monkeypatch.setattr(disc, "http_get", fake_get)
        monkeypatch.setattr(
            disc,
            "_load_any",
            lambda d, source: [root()] if source == AIA_ROOT else [leaf_cert],
        )
        listing = disc.browse_pki("http://pki.example/")
        subjects = {c.subject_dn for c in listing.certificates}
        assert ROOT in subjects, "the issuer named by AIA must be fetched"
        assert any("followed an issuer pointer" in n for n in listing.notes)

    def test_a_crl_pointer_is_followed(self, monkeypatch):
        with_cdp = FakeCert(
            subject_dn=SUB, issuer_dn=ROOT, crl_urls=[CDP_SUB], _fp="SUB"
        )

        def fake_get(url, **kw):
            if url.endswith("/"):
                return b'<a href="/SUB.crt">sub</a>', ""
            return b"DER", ""

        monkeypatch.setattr(disc, "http_get", fake_get)
        monkeypatch.setattr(disc, "_load_any", lambda d, s: [with_cdp])
        monkeypatch.setattr(
            "sssd_smartcard.ca.crl.load_crls", lambda data, source: [FakeCrlStub()]
        )
        listing = disc.browse_pki("http://pki.example/")
        assert listing.crls
        assert any("followed a CRL pointer" in n for n in listing.notes)

    def test_a_pointer_is_not_fetched_twice(self, monkeypatch):
        fetched: list[str] = []
        with_cdp = FakeCert(
            subject_dn=SUB, issuer_dn=ROOT, crl_urls=[CDP_SUB], _fp="SUB"
        )

        def fake_get(url, **kw):
            fetched.append(url)
            if url.endswith("/"):
                return b'<a href="/SUB.crt">sub</a>', ""
            return b"DER", ""

        monkeypatch.setattr(disc, "http_get", fake_get)
        monkeypatch.setattr(disc, "_load_any", lambda d, s: [with_cdp])
        monkeypatch.setattr(
            "sssd_smartcard.ca.crl.load_crls", lambda data, source: [FakeCrlStub()]
        )
        disc.browse_pki("http://pki.example/")
        assert fetched.count(CDP_SUB) == 1

    def test_it_terminates_when_nothing_new_appears(self, monkeypatch):
        """A pointer loop must not run forever."""
        looping = FakeCert(
            subject_dn=SUB, issuer_dn=ROOT, ca_issuer_urls=[AIA_ROOT], _fp="SUB"
        )

        def fake_get(url, **kw):
            if url.endswith("/"):
                return b'<a href="/SUB.crt">sub</a>', ""
            return b"DER", ""

        monkeypatch.setattr(disc, "http_get", fake_get)
        # Every fetch yields the same certificate, so the second pass adds
        # nothing and the walk has to stop.
        monkeypatch.setattr(disc, "_load_any", lambda d, s: [looping])
        listing = disc.browse_pki("http://pki.example/")
        assert len(listing.certificates) == 1


class TestCrlsAreCountedOnce:
    """The same CRL arrives by more than one route.

    The directory listing names it, and a certificate's distribution point
    names it again. Counted twice, the report said three CRLs where the PKI
    published two -- observed against a real two-tier PKI.
    """

    def _crl(self, issuer="CN=Root CA", last="2026-10-29"):
        stub = FakeCrlStub()
        stub.issuer = issuer
        stub.last_update = last
        return stub

    def test_the_same_crl_twice_is_held_once(self):
        listing = disc.PkiListing()
        assert disc._add_crls(listing, [self._crl()]) is True
        assert disc._add_crls(listing, [self._crl()]) is False
        assert len(listing.crls) == 1

    def test_a_different_issuer_is_a_different_crl(self):
        listing = disc.PkiListing()
        disc._add_crls(listing, [self._crl("CN=Root CA")])
        disc._add_crls(listing, [self._crl("CN=Issuing CA")])
        assert len(listing.crls) == 2

    def test_a_refreshed_crl_from_the_same_issuer_is_kept(self):
        """A newer thisUpdate is a new list, not a duplicate."""
        listing = disc.PkiListing()
        disc._add_crls(listing, [self._crl(last="2026-10-01")])
        disc._add_crls(listing, [self._crl(last="2026-10-19")])
        assert len(listing.crls) == 2

    def test_issuer_spacing_does_not_create_a_duplicate(self):
        listing = disc.PkiListing()
        disc._add_crls(listing, [self._crl("CN=Root CA")])
        disc._add_crls(listing, [self._crl("CN=Root  CA")])
        assert len(listing.crls) == 1

    def test_a_url_is_listed_once(self, monkeypatch):
        def fake_get(url, **kw):
            if url.endswith("/"):
                return b'<a href="/CA.crt">ca</a>', ""
            return b"DER", ""

        with_cdp = FakeCert(
            subject_dn=SUB, issuer_dn=ROOT, crl_urls=["http://pki.example/CA.crt"],
            _fp="SUB",
        )
        monkeypatch.setattr(disc, "http_get", fake_get)
        monkeypatch.setattr(disc, "_load_any", lambda d, s: [with_cdp])
        listing = disc.browse_pki("http://pki.example/")
        assert len(listing.listed) == len(set(listing.listed))
