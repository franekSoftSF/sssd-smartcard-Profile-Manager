"""Does the KDC's own certificate let MIT Kerberos do PKINIT?

PKINIT is mutual: the card proves the user to the KDC, and the KDC proves
itself to the client.  The second half is where AD deployments fail, and the
failure is invisible from the client's own configuration -- everything on this
side can be perfect and the handshake still collapses into a password prompt.

RFC 4556 says a KDC certificate carries the ``id-pkinit-KPKdc`` EKU
(1.3.6.1.5.2.3.5) and an ``id-pkinit-san`` otherName (1.3.6.1.5.2.2) naming
``krbtgt/REALM@REALM``.  Microsoft's older *Domain Controller* template issues
neither: it produces a plain TLS certificate with ``serverAuth`` and a
``dNSName``.  Windows clients accept that for backwards compatibility; MIT
Kerberos, by default, does not --  ``pkinit_eku_checking`` defaults to
``kpKDC``.

So this module fetches the certificate the domain controller actually presents
and says which ``pkinit_*`` options the client needs, rather than leaving the
operator to work it out from ``kinit`` falling back to a password.

Sources: RFC 4556 section 3.2.4; ``krb5.conf(5)`` -> ``pkinit_eku_checking``
(default ``kpKDC``) and ``pkinit_kdc_hostname`` (its presence accepts a
``dNSName`` SAN "rather than requiring the id-pkinit-san").
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..util import Check, run, which
from ..x509.inspect import CertificateInfo, load_certificates

#: ``id-pkinit-KPKdc`` -- the EKU RFC 4556 requires of a KDC certificate.  This
#: is also the OID Microsoft's "Kerberos Authentication" template issues, under
#: the name "KDC Authentication".
OID_PKINIT_KP_KDC = "1.3.6.1.5.2.3.5"
#: ``id-pkinit-san`` -- the otherName naming krbtgt/REALM@REALM.
OID_PKINIT_SAN = "1.3.6.1.5.2.2"
#: ``id-kp-serverAuth`` -- what the old Domain Controller template grants.
OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"

#: LDAPS is the one port that reliably presents the DC's own certificate.
#: Samba and Windows both serve the same certificate there that their KDC uses.
DEFAULT_LDAPS_PORT = 636


@dataclass
class KdcCertificate:
    """The certificate a domain controller presents, and what it supports."""

    host: str = ""
    fetched: bool = False
    error: str = ""
    chain: list[CertificateInfo] = field(default_factory=list)

    @property
    def leaf(self) -> CertificateInfo | None:
        return self.chain[0] if self.chain else None

    @property
    def issuer(self) -> str:
        leaf = self.leaf
        return leaf.issuer_dn if leaf else ""

    @property
    def eku_oids(self) -> list[str]:
        leaf = self.leaf
        return list(leaf.eku_oids) if leaf else []

    @property
    def has_kdc_eku(self) -> bool:
        return OID_PKINIT_KP_KDC in self.eku_oids

    @property
    def has_server_auth(self) -> bool:
        return OID_SERVER_AUTH in self.eku_oids

    @property
    def has_pkinit_san(self) -> bool:
        """An ``id-pkinit-san`` otherName, as RFC 4556 requires."""
        leaf = self.leaf
        if leaf is None:
            return False
        return bool(getattr(leaf.san, "pkinit", None))

    @property
    def dns_names(self) -> list[str]:
        leaf = self.leaf
        if leaf is None:
            return []
        return list(getattr(leaf.san, "dns", []) or [])

    @property
    def rfc4556_compliant(self) -> bool:
        return self.has_kdc_eku and self.has_pkinit_san

    def required_options(self) -> dict[str, str]:
        """``pkinit_*`` settings this certificate forces on the client.

        Empty when the certificate is RFC 4556 compliant and the defaults work.
        """
        options: dict[str, str] = {}
        if not self.has_kdc_eku and self.has_server_auth:
            options["pkinit_eku_checking"] = "kpServerAuth"
        if not self.has_pkinit_san and self.dns_names:
            options["pkinit_kdc_hostname"] = self.dns_names[0]
        return options

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "fetched": self.fetched,
            "error": self.error,
            "subject": self.leaf.subject_dn if self.leaf else "",
            "issuer": self.issuer,
            "eku": self.leaf.eku_labels if self.leaf else [],
            "has_kdc_eku": self.has_kdc_eku,
            "has_pkinit_san": self.has_pkinit_san,
            "dns_names": self.dns_names,
            "rfc4556_compliant": self.rfc4556_compliant,
            "required_options": self.required_options(),
        }


def fetch_kdc_certificate(
    host: str, *, port: int = DEFAULT_LDAPS_PORT, timeout: int = 20
) -> KdcCertificate:
    """Read the certificate chain *host* presents on LDAPS.

    Read-only: it opens a TLS connection, takes the certificate and closes.
    Nothing is sent but the handshake, and no credentials are involved.
    """
    out = KdcCertificate(host=host)
    if not which("openssl"):
        out.error = "openssl not found; cannot read the KDC certificate"
        return out
    result = run(
        [
            "openssl",
            "s_client",
            "-connect",
            f"{host}:{port}",
            "-showcerts",
            "-servername",
            host,
        ],
        timeout=timeout,
        input_text="",
    )
    if not result.found:
        out.error = "openssl could not be executed"
        return out
    text = result.stdout or ""
    if "BEGIN CERTIFICATE" not in text:
        out.error = (
            f"no certificate received from {host}:{port}"
            + (f" -- {result.stderr.strip().splitlines()[0]}" if result.stderr.strip() else "")
        )
        return out
    try:
        out.chain = load_certificates(text.encode("utf-8"), source=f"{host}:{port}")
        out.fetched = bool(out.chain)
    except Exception as exc:  # pragma: no cover - malformed server certificate
        out.error = f"could not parse the certificate from {host}:{port}: {exc}"
    return out


def kdc_certificate_checks(cert: KdcCertificate) -> list[Check]:
    """Turn the certificate into checks that name the options to set."""
    if not cert.fetched:
        return [
            Check(
                "KDC certificate",
                "WARN",
                cert.error or f"could not read a certificate from {cert.host}",
                hint="PKINIT needs the KDC to prove itself to the client. Without "
                "seeing its certificate this tool cannot say which pkinit_* options "
                "you need, so check it by hand: openssl s_client -connect "
                f"{cert.host}:636 | openssl x509 -noout -text",
            )
        ]

    checks = [
        Check(
            "KDC certificate",
            "PASS",
            f"{cert.leaf.subject_dn} issued by {cert.issuer}",
        )
    ]

    if cert.rfc4556_compliant:
        checks.append(
            Check(
                "KDC certificate PKINIT suitability",
                "PASS",
                "has id-pkinit-KPKdc and id-pkinit-san, so MIT's defaults work",
            )
        )
        return checks

    missing = []
    if not cert.has_kdc_eku:
        missing.append("id-pkinit-KPKdc EKU (1.3.6.1.5.2.3.5)")
    if not cert.has_pkinit_san:
        missing.append("id-pkinit-san otherName (1.3.6.1.5.2.2)")
    options = cert.required_options()

    checks.append(
        Check(
            "KDC certificate PKINIT suitability",
            "WARN" if options else "FAIL",
            "lacks " + " and ".join(missing)
            + (
                f"; EKU is {', '.join(cert.leaf.eku_labels)}"
                if cert.leaf and cert.leaf.eku_labels
                else ""
            ),
            hint=(
                "This is a Domain Controller certificate, not a Kerberos "
                "Authentication one. Windows accepts it for backwards "
                "compatibility; MIT Kerberos does not, because "
                "pkinit_eku_checking defaults to kpKDC. Either reissue the DC "
                "certificate from a template that includes the KDC EKU, or tell "
                "the client to accept this one by adding to [libdefaults]: "
                + "; ".join(f"{k} = {v}" for k, v in options.items())
            )
            if options
            else (
                "This certificate cannot be used for PKINIT by MIT Kerberos and no "
                "client-side option relaxes it far enough. The DC needs a "
                "certificate from a Kerberos Authentication template."
            ),
        )
    )
    for key, value in options.items():
        checks.append(Check(f"needs {key}", "INFO", value))
    return checks
