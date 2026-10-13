"""Work out a PKI from one certificate, and fetch everything it needs.

Given the certificate on a card, almost everything else is discoverable. The
certificate names its issuer's certificate (AIA ``caIssuers``), where its
revocation list lives (``crlDistributionPoints``) and whether a responder
exists (AIA ``OCSP``). Following those gets the whole chain to the root, the
CRLs for every CA in it, and an answer to the question that actually decides
the configuration: *does this PKI offer working OCSP, or only CRLs?*

Two things this module is careful about.

**Downloading a CA certificate is not trusting it.** The chain fetched here is
a proposal. Its fingerprints must be checked against the PKI out of band before
it becomes a trust anchor -- anyone who can answer the AIA URL could otherwise
install themselves as a CA that logs in. The report prints fingerprints for
exactly that comparison and says so.

**An advertised responder is not a working responder.** An AIA OCSP URL only
says the CA put a URL in the certificate. So a real OCSP request is built,
sent, and the response parsed. "The URL is present" and "the responder answers
for this certificate" are different findings, and SSSD fails closed on the
difference: with OCSP enabled and no responder reachable, nobody logs in.

Sources: RFC 5280 section 4.2.2.1 (AIA) and 4.2.1.13 (CRL distribution
points); RFC 6960 for OCSP; ``sssd.conf(5)`` for how the result is expressed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

from ..util import Check, http_get
from ..x509.inspect import CertificateInfo, load_certificates

#: Content type RFC 6960 specifies for an OCSP request over HTTP.
OCSP_CONTENT_TYPE = "application/ocsp-request"

#: Stop following AIA after this many hops. A loop or a hostile AIA chain
#: should not turn discovery into an unbounded download.
MAX_CHAIN_DEPTH = 8


def _load_any(data: bytes, source: str) -> list[CertificateInfo]:
    """Parse PEM, DER or PKCS#7 -- AD CS serves all three from its AIA."""
    try:
        return load_certificates(data, source=source)
    except Exception:
        pass
    for loader in (x509.load_der_pkcs7_certificates, x509.load_pem_pkcs7_certificates):
        try:
            certs = loader(data)
        except Exception:
            continue
        out: list[CertificateInfo] = []
        for cert in certs:
            out.extend(
                load_certificates(
                    cert.public_bytes(serialization.Encoding.PEM), source=source
                )
            )
        if out:
            return out
    return []


#: Directories CA hosts commonly publish under, tried both relative to the URL
#: given and from the host root -- a file URL deep in a tree says nothing about
#: where the directory lives. The publishing path is a local choice, so this
#: list is a convenience and never a requirement: an unusual layout is handled
#: by following a certificate's own pointers instead.
COMMON_PKI_PATHS = (
    "",
    "PKI/", "pki/",
    "CertEnroll/", "certenroll/",
    "certdata/", "CertData/",
    "crl/", "CRL/",
    "certs/", "ca/", "CA/", "aia/",
    "certsrv/certenroll/",
    "repository/",
)

#: What is worth downloading from a listing.
CERT_SUFFIXES = (".crt", ".cer", ".pem", ".p7b", ".p7c", ".der")
CRL_SUFFIXES = (".crl",)

#: A listing should not turn into an unbounded download.
MAX_LISTED_FILES = 40

_HREF_RE = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


def _same_dn(a: str, b: str) -> bool:
    """Compare DNs without being defeated by spacing or case."""
    return re.sub(r"\s+", "", a).lower() == re.sub(r"\s+", "", b).lower()


def _add_crls(out: "PkiListing", crls: list) -> bool:
    """Add CRLs not already held, keyed by issuer and thisUpdate.

    The same CRL arrives by more than one route: from the directory listing and
    again from a certificate's distribution point. Counted twice, the report
    said three CRLs where the PKI published two.
    """
    added = False
    for crl in crls:
        def key(c):
            return (
                re.sub(r"\s+", "", str(getattr(c, "issuer", ""))).lower(),
                str(getattr(c, "last_update", "")),
            )

        if key(crl) not in {key(c) for c in out.crls}:
            out.crls.append(crl)
            added = True
    return added


@dataclass
class PkiListing:
    """What a PKI's web directory turned out to be publishing."""

    base: str = ""
    listed: list[str] = field(default_factory=list)
    certificates: list[CertificateInfo] = field(default_factory=list)
    crls: list[object] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def roots(self) -> list[CertificateInfo]:
        return [c for c in self.certificates if c.subject_dn == c.issuer_dn]

    @property
    def intermediates(self) -> list[CertificateInfo]:
        return [c for c in self.certificates if c.subject_dn != c.issuer_dn]

    @property
    def complete_chain(self) -> bool:
        """Every intermediate's issuer is also published here."""
        return bool(self.certificates) and all(
            any(_same_dn(c.issuer_dn, s.subject_dn) for s in self.certificates)
            for c in self.intermediates
        )

    def to_dict(self) -> dict:
        return {
            "base": self.base,
            "listed": self.listed,
            "certificates": [
                {
                    "subject": c.subject_dn,
                    "issuer": c.issuer_dn,
                    "sha256": c.fingerprint(),
                    "self_signed": c.subject_dn == c.issuer_dn,
                }
                for c in self.certificates
            ],
            "crls": [c.to_dict() for c in self.crls],
            "complete_chain": self.complete_chain,
            "errors": self.errors,
            "notes": self.notes,
        }


def _same_host(base: str, url: str) -> bool:
    from urllib.parse import urlparse

    a, b = urlparse(base), urlparse(url)
    return (b.scheme in ("http", "https")) and a.netloc.lower() == b.netloc.lower()


def browse_pki(base: str, *, timeout: int = 20) -> PkiListing:
    """Read a PKI's web directory and fetch the certificates and CRLs in it.

    Most AD CS deployments publish the CA certificates and CRLs over plain HTTP
    in one directory with a listing. Given that address, the whole PKI is
    visible without a card and without knowing any filenames -- which is the
    situation when setting up against a PKI for the first time.

    Only links on the same host are followed, and only a bounded number: a
    listing is a URL a person typed, not a reason to crawl.
    """
    from urllib.parse import urljoin

    if not base.lower().startswith(("http://", "https://")):
        base = "http://" + base

    # A URL naming a file is a file, not a directory. Appending a slash to it
    # and asking for a listing yields a 404 and an error message about the
    # directory that was never there.
    direct = ""
    path_part = base.split("?")[0]
    if path_part.lower().endswith(CERT_SUFFIXES + CRL_SUFFIXES):
        direct = base
        # The siblings almost always live beside it: the rest of the chain and
        # the CRLs. So the parent is listed as well, best effort.
        base = base[: base.rfind("/") + 1]

    if not base.endswith("/"):
        base += "/"

    out = PkiListing(base=base)
    # The download loop below walks out.listed, which already contains the
    # file fetched directly -- without this it would be fetched twice.
    already_fetched: set[str] = set()

    if direct:
        body, error = http_get(direct, timeout=timeout)
        if error:
            out.errors.append(error)
        else:
            out.listed.append(direct)
            already_fetched.add(direct)
            if path_part.lower().endswith(CRL_SUFFIXES):
                try:
                    from .crl import load_crls

                    _add_crls(out, load_crls(body, source=direct))
                except Exception as exc:
                    out.errors.append(f"{direct}: not a usable CRL ({exc})")
            else:
                found = _load_any(body, direct)
                if found:
                    out.certificates.extend(found)
                    out.notes.append(f"fetched {direct}")
                else:
                    out.errors.append(
                        f"{direct}: not a certificate in PEM, DER or PKCS#7"
                    )

    from urllib.parse import urlparse

    parts = urlparse(base)
    host_root = f"{parts.scheme}://{parts.netloc}/"
    candidates = [urljoin(base, s) for s in COMMON_PKI_PATHS]
    candidates += [urljoin(host_root, s) for s in COMMON_PKI_PATHS]

    index = ""
    chosen = base
    tried: set[str] = set()
    for candidate in candidates:
        if candidate in tried:
            continue
        tried.add(candidate)
        body, error = http_get(candidate, timeout=timeout)
        if error:
            out.errors.append(error)
            continue
        text = body.decode("utf-8", errors="replace")
        if _HREF_RE.search(text):
            index, chosen = text, candidate
            if candidate != base:
                out.notes.append(f"found a listing at {candidate}")
            break
        out.errors.append(f"{candidate}: served no links")
    if not index:
        if out.certificates or out.crls:
            # The file asked for was fetched; only its siblings are missing.
            out.notes.append(
                f"{base} has no directory listing, so only the file named was "
                "fetched. The rest of the chain and the CRLs have to come from "
                "their own URLs, or from a certificate with --from-card."
            )
            out.errors = [
                e for e in out.errors if "404" not in e and "served no links" not in e
            ]
            return out
        out.errors.append(
            f"no PKI directory found at or under {base}, nor at the host root. "
            "Publishing paths are a local choice, so the names tried (PKI, pki, "
            "CertEnroll, certdata, crl, certs, ca, aia, repository) are only the "
            "common ones, and many hosts disable listings entirely."
        )
        out.notes.append(
            "give the exact URL instead: either the directory holding the files, "
            "or a single certificate, whose own AIA and CRL pointers are then "
            "followed to the rest -- "
            "--pki-url http://host/whatever/path/  or  "
            "--pki-url http://host/whatever/CA.crt"
        )
        return out

    seen: set[str] = set()
    for href in _HREF_RE.findall(index):
        url = urljoin(chosen, href)
        if url in seen or not _same_host(base, url):
            continue
        lower = url.lower().split("?")[0]
        if not lower.endswith(CERT_SUFFIXES + CRL_SUFFIXES):
            continue
        if url in out.listed:
            continue  # already have it from the direct fetch
        seen.add(url)
        if len(seen) > MAX_LISTED_FILES:
            out.notes.append(
                f"stopped after {MAX_LISTED_FILES} files; narrow the URL if more "
                "are expected"
            )
            break
        out.listed.append(url)

    for url in out.listed:
        if url in already_fetched:
            continue
        body, error = http_get(url, timeout=timeout)
        if error:
            out.errors.append(error)
            continue
        if url.lower().split("?")[0].endswith(CRL_SUFFIXES):
            try:
                from .crl import load_crls

                _add_crls(out, load_crls(body, source=url))
            except Exception as exc:
                out.errors.append(f"{url}: not a usable CRL ({exc})")
            continue
        found = _load_any(body, url)
        if not found:
            out.errors.append(f"{url}: not a certificate in PEM, DER or PKCS#7")
            continue
        for cert in found:
            if all(cert.fingerprint() != c.fingerprint() for c in out.certificates):
                out.certificates.append(cert)

    # Whatever the directory layout, a certificate names its issuer and its own
    # CRL by exact URL. This is the only method an unusual publishing path
    # cannot defeat, so it runs regardless of what the listing turned up.
    _follow_pointers(out, already_fetched, timeout)
    return out


def _follow_pointers(out: "PkiListing", already_fetched: set, timeout: int) -> None:
    """Fetch what the certificates already in hand point at.

    An intermediate's AIA names its issuer's certificate; a CRL distribution
    point names its CRL. Following those needs no knowledge of where the host
    publishes, which is what makes it work on a layout nobody guessed.
    """
    from .crl import load_crls

    for _ in range(MAX_CHAIN_DEPTH):
        wanted: list[str] = []
        for cert in list(out.certificates):
            for url in list(cert.ca_issuer_urls) + list(cert.crl_urls):
                if url.lower().startswith("http") and url not in already_fetched:
                    wanted.append(url)
        wanted = list(dict.fromkeys(wanted))
        if not wanted:
            return

        progressed = False
        for url in wanted:
            already_fetched.add(url)
            body, error = http_get(url, timeout=timeout)
            if error:
                out.errors.append(error)
                continue
            if url not in out.listed:
                out.listed.append(url)
            if url.lower().split("?")[0].endswith(CRL_SUFFIXES):
                try:
                    if _add_crls(out, load_crls(body, source=url)):
                        out.notes.append(f"followed a CRL pointer: {url}")
                        progressed = True
                except Exception as exc:
                    out.errors.append(f"{url}: not a usable CRL ({exc})")
                continue
            for cert in _load_any(body, url):
                if all(
                    cert.fingerprint() != c.fingerprint() for c in out.certificates
                ):
                    out.certificates.append(cert)
                    out.notes.append(f"followed an issuer pointer: {url}")
                    progressed = True
        if not progressed:
            return


def listing_checks(listing: PkiListing) -> list[Check]:
    """The listing as checks, with the trust caveat where it belongs."""
    checks: list[Check] = []

    if not listing.certificates and not listing.crls:
        checks.append(
            Check(
                "PKI listing",
                "FAIL",
                f"nothing usable at {listing.base}",
                hint="; ".join(listing.errors[:2])
                or "Check the address, or pass the CA files with --ca.",
            )
        )
        return checks

    checks.append(
        Check(
            "PKI listing",
            "PASS",
            f"{len(listing.certificates)} certificate(s) and "
            f"{len(listing.crls)} CRL(s) at {listing.base}",
        )
    )

    for cert in listing.certificates:
        role = "root" if cert.subject_dn == cert.issuer_dn else "intermediate"
        checks.append(
            Check(f"  {role}", "INFO", f"{cert.subject_dn}")
        )
        checks.append(
            Check("    SHA-256", "INFO", cert.fingerprint())
        )
        checks.append(
            Check("    valid until", "INFO", str(getattr(cert, "not_after", "unknown")))
        )

    if listing.certificates:
        checks.append(
            Check(
                "chain",
                "PASS" if listing.complete_chain else "WARN",
                "every intermediate's issuer is published here"
                if listing.complete_chain
                else "an intermediate's issuer is not published here",
                hint="" if listing.complete_chain
                else "The missing CA has to come from somewhere else, or the bundle "
                "will not verify a full chain.",
            )
        )
        checks.append(
            Check(
                "CA trust",
                "WARN",
                "these certificates were downloaded, not verified",
                hint="Downloading a CA is not trusting it: anything in the bundle "
                "can issue a certificate that logs in. Compare the fingerprints "
                "above against the PKI out of band before importing them.",
            )
        )

    for crl in listing.crls:
        expired = getattr(crl, "expired", False)
        nxt = getattr(crl, "next_update", None)
        checks.append(
            Check(
                f"  CRL {getattr(crl, 'issuer', '?')}",
                "FAIL" if expired else "INFO",
                ("EXPIRED " if expired else "next update ")
                + (f"{nxt:%Y-%m-%d}" if nxt else "not set")
                + f", {getattr(crl, 'revoked_count', 0)} revoked",
            )
        )

    for note in listing.notes:
        checks.append(Check("PKI listing", "INFO", note))
    return checks


@dataclass
class OcspProbe:
    """What happened when a real OCSP request was sent."""

    url: str = ""
    attempted: bool = False
    answered: bool = False
    status: str = ""
    error: str = ""

    @property
    def working(self) -> bool:
        """The responder answered with a verdict about this certificate."""
        return self.answered and self.status in ("good", "revoked")

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "attempted": self.attempted,
            "answered": self.answered,
            "working": self.working,
            "status": self.status,
            "error": self.error,
        }


def probe_ocsp(
    cert: CertificateInfo, issuer: CertificateInfo, url: str, *, timeout: int = 20
) -> OcspProbe:
    """Ask the responder about *cert*, and report what it said.

    The response is parsed but not cryptographically validated here: the
    useful finding at discovery time is whether a responder answers at all,
    and saying more than was checked would be the kind of false pass this
    project has been bitten by.
    """
    probe = OcspProbe(url=url, attempted=True)
    try:
        builder = ocsp.OCSPRequestBuilder().add_certificate(
            cert.cert, issuer.cert, hashes.SHA1()
        )
        body = builder.build().public_bytes(serialization.Encoding.DER)
    except Exception as exc:  # pragma: no cover - malformed input
        probe.error = f"could not build an OCSP request: {exc}"
        return probe

    # SHA-1 is what RFC 6960 specifies for the certificate ID hash, and what
    # responders expect; it identifies the certificate, it does not secure it.
    data, error = http_get(
        url, timeout=timeout, post=body, content_type=OCSP_CONTENT_TYPE
    )
    if error:
        probe.error = error
        return probe

    try:
        response = ocsp.load_der_ocsp_response(data)
    except Exception as exc:
        probe.error = f"the reply was not a parsable OCSP response: {exc}"
        return probe

    probe.answered = True
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        probe.status = response.response_status.name.lower()
        probe.error = f"responder returned {probe.status}"
        return probe
    try:
        probe.status = response.certificate_status.name.lower()
    except Exception:  # pragma: no cover - unusual response
        probe.status = "unknown"
    return probe


@dataclass
class DiscoveryReport:
    """Everything derivable from one certificate, with what was fetched."""

    leaf: CertificateInfo | None = None
    chain: list[CertificateInfo] = field(default_factory=list)
    crl_urls: list[str] = field(default_factory=list)
    ocsp: list[OcspProbe] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def complete_chain(self) -> bool:
        """True when the chain reaches a self-signed certificate."""
        if not self.chain:
            return False
        last = self.chain[-1]
        return last.subject_dn == last.issuer_dn

    @property
    def ocsp_works(self) -> bool:
        return any(p.working for p in self.ocsp)

    @property
    def ocsp_advertised(self) -> bool:
        return bool(self.ocsp)

    @property
    def revocation_method(self) -> str:
        """What this PKI can actually enforce, as a profile method value."""
        if self.ocsp_works:
            return "ocsp"
        if self.crl_urls:
            return "crl"
        return "none"

    def bundle_pem(self) -> bytes:
        """The fetched CA certificates, root last, as one PEM."""
        return "".join(c.pem for c in self.chain).encode("ascii")

    def to_dict(self) -> dict:
        return {
            "leaf": self.leaf.subject_dn if self.leaf else "",
            "chain": [
                {
                    "subject": c.subject_dn,
                    "issuer": c.issuer_dn,
                    "sha256": c.fingerprint(),
                }
                for c in self.chain
            ],
            "complete_chain": self.complete_chain,
            "crl_urls": self.crl_urls,
            "ocsp": [p.to_dict() for p in self.ocsp],
            "ocsp_advertised": self.ocsp_advertised,
            "ocsp_works": self.ocsp_works,
            "revocation_method": self.revocation_method,
            "errors": self.errors,
            "notes": self.notes,
        }


def _candidate_urls(cert: CertificateInfo, pki_url: str | None) -> list[str]:
    """AIA caIssuers URLs, plus guesses under an operator-supplied base."""
    urls = [u for u in cert.ca_issuer_urls if u.lower().startswith("http")]
    if pki_url:
        # Some CAs publish only an LDAP AIA, or none. With a base URL the
        # issuer's own CN is the conventional filename on an AD CS web
        # enrolment host, so it is worth one attempt -- clearly a guess, and
        # reported as such when it fails.
        base = pki_url.rstrip("/")
        cn = ""
        for part in cert.issuer_dn.split(","):
            name, _, value = part.strip().partition("=")
            if name.upper() == "CN":
                cn = value.strip()
                break
        if cn:
            from urllib.parse import quote

            for ext in (".crt", ".cer", ".p7b"):
                urls.append(f"{base}/{quote(cn)}{ext}")
    return list(dict.fromkeys(urls))


def discover(
    cert: CertificateInfo,
    *,
    pki_url: str | None = None,
    probe_responders: bool = True,
    timeout: int = 20,
) -> DiscoveryReport:
    """Follow the certificate's own pointers and fetch what they name."""
    report = DiscoveryReport(leaf=cert)

    # --- the CA chain, by following AIA caIssuers upwards ------------------
    current = cert
    seen: set[str] = {cert.fingerprint()}
    for _ in range(MAX_CHAIN_DEPTH):
        if current.subject_dn == current.issuer_dn:
            break  # self-signed: the root is already in hand
        urls = _candidate_urls(current, pki_url)
        if not urls:
            report.errors.append(
                f"{current.subject_dn}: no HTTP caIssuers URL in the certificate, so "
                "its issuer cannot be fetched. Supply the CA file directly, or pass "
                "--pki-url with the base URL the CA publishes under."
            )
            break
        issuer = None
        for url in urls:
            data, error = http_get(url, timeout=timeout)
            if error:
                report.errors.append(error)
                continue
            found = _load_any(data, url)
            if not found:
                report.errors.append(f"{url}: served something that is not a certificate")
                continue
            # Take the one that actually issued the certificate in hand.
            for candidate in found:
                if candidate.subject_dn == current.issuer_dn:
                    issuer = candidate
                    break
            issuer = issuer or found[0]
            report.notes.append(f"fetched {issuer.subject_dn} from {url}")
            break
        if issuer is None:
            break
        if issuer.fingerprint() in seen:
            report.errors.append(
                f"{issuer.subject_dn}: AIA loops back to a certificate already seen; "
                "stopping"
            )
            break
        seen.add(issuer.fingerprint())
        report.chain.append(issuer)
        current = issuer

    if not report.complete_chain and report.chain:
        report.notes.append(
            "the chain does not reach a self-signed root; the topmost certificate "
            "fetched is an intermediate, so the root has to be supplied separately"
        )

    # --- revocation: CRL distribution points -------------------------------
    for source in [cert, *report.chain]:
        for url in source.crl_urls:
            if url.lower().startswith("http") and url not in report.crl_urls:
                report.crl_urls.append(url)
    if not report.crl_urls:
        ldap_only = any(
            u.lower().startswith("ldap") for s in [cert, *report.chain] for u in s.crl_urls
        )
        if ldap_only:
            report.notes.append(
                "the only CRL distribution points are LDAP URLs, which SSSD cannot "
                "fetch; export the CRL and pass it with 'ca crl update --from-file'"
            )

    # --- revocation: is there a responder that answers? --------------------
    if probe_responders:
        issuer = report.chain[0] if report.chain else None
        for url in cert.ocsp_urls:
            if not url.lower().startswith("http"):
                continue
            if issuer is None:
                probe = OcspProbe(url=url, attempted=False)
                probe.error = (
                    "cannot ask the responder without the issuer certificate, which "
                    "could not be fetched"
                )
                report.ocsp.append(probe)
                continue
            report.ocsp.append(probe_ocsp(cert, issuer, url, timeout=timeout))
    elif cert.ocsp_urls:
        for url in cert.ocsp_urls:
            report.ocsp.append(OcspProbe(url=url, attempted=False))

    return report


def discovery_checks(report: DiscoveryReport) -> list[Check]:
    """The report as checks, with the trust caveat stated where it matters."""
    checks: list[Check] = []

    if report.chain:
        checks.append(
            Check(
                "CA chain",
                "PASS" if report.complete_chain else "WARN",
                f"{len(report.chain)} certificate(s) fetched"
                + ("" if report.complete_chain else "; no self-signed root reached"),
                hint="" if report.complete_chain
                else "Supply the root with --ca, or the bundle will not verify a "
                "full chain.",
            )
        )
        for entry in report.chain:
            checks.append(
                Check(
                    f"  {entry.subject_dn}",
                    "INFO",
                    f"SHA-256 {entry.fingerprint()}",
                )
            )
        checks.append(
            Check(
                "CA trust",
                "WARN",
                "these certificates were downloaded, not verified",
                hint="Downloading a CA is not trusting it: anything in the bundle can "
                "issue a certificate that logs in. Compare the fingerprints above "
                "against the PKI out of band before importing them.",
            )
        )
    else:
        checks.append(
            Check(
                "CA chain",
                "FAIL",
                "no CA certificate could be fetched",
                hint="Pass the CA files directly with --ca, or give --pki-url the "
                "base URL the CA publishes under.",
            )
        )

    if report.crl_urls:
        checks.append(
            Check("CRL distribution", "PASS", "; ".join(report.crl_urls))
        )
    else:
        checks.append(
            Check(
                "CRL distribution",
                "WARN",
                "no HTTP CRL distribution point advertised",
                hint="Without a CRL and without OCSP, a revoked certificate still "
                "logs in.",
            )
        )

    for probe in report.ocsp:
        if probe.working:
            checks.append(
                Check(
                    "OCSP responder",
                    "PASS",
                    f"{probe.url} answered: {probe.status}",
                )
            )
        elif probe.answered:
            checks.append(
                Check(
                    "OCSP responder",
                    "WARN",
                    f"{probe.url} answered but gave no verdict ({probe.status})",
                    hint=probe.error
                    or "A responder that returns 'unknown' for this certificate "
                    "cannot enforce revocation for it.",
                )
            )
        elif probe.attempted:
            checks.append(
                Check(
                    "OCSP responder",
                    "FAIL",
                    f"{probe.url} did not answer",
                    hint=(probe.error or "")
                    + " SSSD fails closed on OCSP: enabling it with an unreachable "
                    "responder stops every card login. Use CRLs instead, or "
                    "revocation.fail_mode: open for soft_ocsp.",
                )
            )
        else:
            checks.append(
                Check("OCSP responder", "INFO", f"{probe.url} (not probed)")
            )
    if not report.ocsp:
        checks.append(
            Check(
                "OCSP responder",
                "INFO",
                "none advertised in the certificate",
                hint="This is why no_ocsp belongs in certificate_verification here: "
                "with OCSP left on and no responder, verification fails closed.",
            )
        )

    method = report.revocation_method
    if method == "ocsp":
        detail = "OCSP, confirmed working against a live responder"
    elif method == "crl":
        # Why there is no OCSP matters: never advertised is a PKI design
        # choice, advertised but silent is a broken responder.
        detail = (
            "CRL, because the advertised responder did not answer"
            if report.ocsp_advertised
            else "CRL, because this PKI advertises no OCSP responder"
        )
    else:
        detail = "none available -- a revoked certificate would still log in"
    checks.append(
        Check(
            "recommended revocation",
            "PASS" if method != "none" else "WARN",
            f"{method}: {detail}",
        )
    )

    for error in report.errors:
        checks.append(Check("discovery", "WARN", error))
    return checks
