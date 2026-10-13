"""Certificate Inspector -- everything about an X.509 cert that SSSD cares about.

This module is deliberately read-only and offline: it never touches a private
key and never talks to the network.  It is the input to both the mapping
recommender and the local matchrule evaluator.
"""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import re
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, ObjectIdentifier

from ..errors import CertificateError
from . import der
from .names import dn_components, format_dn

OID_MS_UPN = ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
OID_KRB5_PRINCIPAL = ObjectIdentifier("1.3.6.1.5.2.2")
OID_NTDS_SECURITY_EXT = ObjectIdentifier("1.3.6.1.4.1.311.25.2")
OID_MS_SMARTCARD_LOGON = ObjectIdentifier("1.3.6.1.4.1.311.20.2.2")
OID_PKINIT_KP_CLIENT_AUTH = ObjectIdentifier("1.3.6.1.5.2.3.4")

#: EKU OIDs that ``sss-certmap(5)`` documents as accepting a symbolic name.
#: Anything outside this table is emitted as a dotted-decimal OID, which the
#: matching rule syntax accepts everywhere a name is accepted.  We never invent
#: a keyword -- an OID always works.
EKU_KEYWORDS: dict[str, str] = {
    ExtendedKeyUsageOID.SERVER_AUTH.dotted_string: "serverAuth",
    ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string: "clientAuth",
    ExtendedKeyUsageOID.CODE_SIGNING.dotted_string: "codeSigning",
    ExtendedKeyUsageOID.EMAIL_PROTECTION.dotted_string: "emailProtection",
    ExtendedKeyUsageOID.TIME_STAMPING.dotted_string: "timeStamping",
    ExtendedKeyUsageOID.OCSP_SIGNING.dotted_string: "OCSPSigning",
    OID_MS_SMARTCARD_LOGON.dotted_string: "msScLogin",
}

#: Human labels, used for display only.
EKU_LABELS: dict[str, str] = {
    **EKU_KEYWORDS,
    OID_PKINIT_KP_CLIENT_AUTH.dotted_string: "id-pkinit-KPClientAuth",
    "1.3.6.1.4.1.311.20.2.1": "msCertificateRequestAgent",
    "1.3.6.1.4.1.311.10.3.12": "msDocumentSigning",
    "1.3.6.1.5.5.7.3.21": "secureShellClient",
    "2.16.840.1.101.3.6.8": "pivContentSigning",
}

#: Spellings an administrator may write in a profile, normalised to an OID.
EKU_ALIASES: dict[str, str] = {
    "serverauth": ExtendedKeyUsageOID.SERVER_AUTH.dotted_string,
    "clientauth": ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string,
    "codesigning": ExtendedKeyUsageOID.CODE_SIGNING.dotted_string,
    "emailprotection": ExtendedKeyUsageOID.EMAIL_PROTECTION.dotted_string,
    "timestamping": ExtendedKeyUsageOID.TIME_STAMPING.dotted_string,
    "ocspsigning": ExtendedKeyUsageOID.OCSP_SIGNING.dotted_string,
    # Every spelling people use for Microsoft Smart Card Logon.  SSSD's own
    # keyword is msScLogin; the profile accepts the friendlier names too.
    "mssclogin": OID_MS_SMARTCARD_LOGON.dotted_string,
    "smartcardlogon": OID_MS_SMARTCARD_LOGON.dotted_string,
    "smartcardlogin": OID_MS_SMARTCARD_LOGON.dotted_string,
    "msclogin": OID_MS_SMARTCARD_LOGON.dotted_string,
    "kpclientauth": OID_PKINIT_KP_CLIENT_AUTH.dotted_string,
    "pkinit": OID_PKINIT_KP_CLIENT_AUTH.dotted_string,
}

KU_FLAGS = (
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly",
)

_KU_ATTRS = {
    "digitalSignature": "digital_signature",
    "nonRepudiation": "content_commitment",
    "keyEncipherment": "key_encipherment",
    "dataEncipherment": "data_encipherment",
    "keyAgreement": "key_agreement",
    "keyCertSign": "key_cert_sign",
    "cRLSign": "crl_sign",
    "encipherOnly": "encipher_only",
    "decipherOnly": "decipher_only",
}


def normalise_eku(value: str) -> str:
    """Turn a profile EKU spelling into a dotted-decimal OID."""
    value = value.strip()
    if re.fullmatch(r"[0-9]+(\.[0-9]+)+", value):
        return value
    oid = EKU_ALIASES.get(value.lower())
    if oid is None:
        known = ", ".join(sorted(set(EKU_KEYWORDS.values())))
        raise CertificateError(
            f"unknown EKU {value!r}; use a dotted-decimal OID or one of: {known}"
        )
    return oid


def eku_certmap_token(oid: str) -> str:
    """The token to write into an ``<EKU>`` matching rule for *oid*.

    Symbolic names appear only where ``sss-certmap(5)`` documents them; the
    rest fall back to the OID, which the syntax accepts everywhere.
    """
    return EKU_KEYWORDS.get(oid, oid)


@dataclass
class SanInfo:
    """Everything found in the Subject Alternative Name extension."""

    dns: list[str] = field(default_factory=list)
    rfc822: list[str] = field(default_factory=list)
    uri: list[str] = field(default_factory=list)
    ip: list[str] = field(default_factory=list)
    directory_name: list[str] = field(default_factory=list)
    registered_id: list[str] = field(default_factory=list)
    upn: list[str] = field(default_factory=list)
    pkinit: list[str] = field(default_factory=list)
    other_name: list[tuple[str, str]] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not any(
            (
                self.dns,
                self.rfc822,
                self.uri,
                self.ip,
                self.directory_name,
                self.registered_id,
                self.upn,
                self.pkinit,
                self.other_name,
            )
        )

    def to_dict(self) -> dict:
        return {
            "dns": self.dns,
            "rfc822": self.rfc822,
            "uri": self.uri,
            "ip": self.ip,
            "directory_name": self.directory_name,
            "registered_id": self.registered_id,
            "upn": self.upn,
            "pkinit": self.pkinit,
            "other_name": [{"oid": o, "value": v} for o, v in self.other_name],
        }


@dataclass
class CertificateInfo:
    """A parsed certificate plus the derived values SSSD templates use."""

    cert: x509.Certificate
    der_bytes: bytes
    source: str = "<memory>"

    # ---- identity -----------------------------------------------------
    @property
    def subject_dn(self) -> str:
        return format_dn(self.cert.subject, "nss_ldap")

    @property
    def issuer_dn(self) -> str:
        return format_dn(self.cert.issuer, "nss_ldap")

    def subject_dn_as(self, style: str) -> str:
        return format_dn(self.cert.subject, style)

    def issuer_dn_as(self, style: str) -> str:
        return format_dn(self.cert.issuer, style)

    @property
    def subject_components(self) -> list[tuple[str, str]]:
        return dn_components(self.cert.subject)

    @property
    def issuer_components(self) -> list[tuple[str, str]]:
        return dn_components(self.cert.issuer)

    @property
    def common_name(self) -> str | None:
        for label, value in self.subject_components:
            if label == "CN":
                return value
        return None

    @property
    def dc_domain(self) -> str | None:
        """Domain implied by the DC components of the subject DN, if any."""
        dcs = [value for label, value in self.subject_components if label == "DC"]
        return ".".join(dcs) if dcs else None

    @property
    def issuer_dc_domain(self) -> str | None:
        dcs = [value for label, value in self.issuer_components if label == "DC"]
        return ".".join(dcs) if dcs else None

    # ---- serial / validity -------------------------------------------
    @property
    def serial_int(self) -> int:
        return self.cert.serial_number

    def serial_bytes(self) -> bytes:
        value = self.serial_int
        length = max((value.bit_length() + 7) // 8, 1)
        raw = value.to_bytes(length, "big")
        return raw

    def serial_hex(
        self, *, upper: bool = False, reverse: bool = False, colon: bool = False
    ) -> str:
        raw = self.serial_bytes()
        if reverse:
            raw = raw[::-1]
        text = ":".join(f"{b:02x}" for b in raw) if colon else raw.hex()
        return text.upper() if upper else text

    @property
    def not_before(self) -> _dt.datetime:
        return _utc(self.cert, "not_valid_before")

    @property
    def not_after(self) -> _dt.datetime:
        return _utc(self.cert, "not_valid_after")

    @property
    def expired(self) -> bool:
        return self.not_after < _dt.datetime.now(_dt.timezone.utc)

    @property
    def not_yet_valid(self) -> bool:
        return self.not_before > _dt.datetime.now(_dt.timezone.utc)

    @property
    def days_remaining(self) -> int:
        return (self.not_after - _dt.datetime.now(_dt.timezone.utc)).days

    # ---- fingerprints -------------------------------------------------
    def fingerprint(
        self, algorithm: str = "sha256", *, colon: bool = True, upper: bool = True
    ) -> str:
        digest = hashlib.new(algorithm, self.der_bytes).digest()
        text = ":".join(f"{b:02x}" for b in digest) if colon else digest.hex()
        return text.upper() if upper else text

    def digest_hex(self, algorithm: str = "sha256") -> str:
        return hashlib.new(algorithm, self.der_bytes).hexdigest()

    @property
    def base64_der(self) -> str:
        return base64.b64encode(self.der_bytes).decode("ascii")

    @property
    def pem(self) -> str:
        return self.cert.public_bytes(Encoding.PEM).decode("ascii")

    # ---- extensions ---------------------------------------------------
    def _ext(self, oid):
        try:
            return self.cert.extensions.get_extension_for_oid(oid)
        except x509.ExtensionNotFound:
            return None

    @property
    def san(self) -> SanInfo:
        info = SanInfo()
        ext = self._ext(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        if ext is None:
            return info
        for name in ext.value:
            if isinstance(name, x509.DNSName):
                info.dns.append(name.value)
            elif isinstance(name, x509.RFC822Name):
                info.rfc822.append(name.value)
            elif isinstance(name, x509.UniformResourceIdentifier):
                info.uri.append(name.value)
            elif isinstance(name, x509.IPAddress):
                info.ip.append(str(name.value))
            elif isinstance(name, x509.DirectoryName):
                info.directory_name.append(format_dn(name.value, "nss_ldap"))
            elif isinstance(name, x509.RegisteredID):
                info.registered_id.append(name.value.dotted_string)
            elif isinstance(name, x509.OtherName):
                if name.type_id == OID_MS_UPN:
                    upn = der.decode_upn(name.value)
                    if upn:
                        info.upn.append(upn)
                        continue
                elif name.type_id == OID_KRB5_PRINCIPAL:
                    principal = der.decode_krb5_principal(name.value)
                    if principal:
                        info.pkinit.append(principal)
                        continue
                text = der.decode_string(name.value) or base64.b64encode(
                    name.value
                ).decode("ascii")
                info.other_name.append((name.type_id.dotted_string, text))
        return info

    @property
    def principals(self) -> list[str]:
        """Kerberos principals that ``<SAN>`` / ``{subject_principal}`` see."""
        san = self.san
        return list(san.pkinit) + list(san.upn)

    @property
    def eku_oids(self) -> list[str]:
        ext = self._ext(ExtensionOID.EXTENDED_KEY_USAGE)
        return [oid.dotted_string for oid in ext.value] if ext else []

    @property
    def eku_labels(self) -> list[str]:
        return [EKU_LABELS.get(oid, oid) for oid in self.eku_oids]

    @property
    def key_usage(self) -> list[str]:
        ext = self._ext(ExtensionOID.KEY_USAGE)
        if ext is None:
            return []
        out = []
        for flag in KU_FLAGS:
            try:
                if getattr(ext.value, _KU_ATTRS[flag]):
                    out.append(flag)
            except ValueError:
                # encipherOnly/decipherOnly raise unless keyAgreement is set.
                continue
        return out

    @property
    def subject_key_id(self) -> bytes | None:
        ext = self._ext(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        return ext.value.digest if ext else None

    @property
    def authority_key_id(self) -> bytes | None:
        ext = self._ext(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        return ext.value.key_identifier if ext else None

    @property
    def basic_constraints(self) -> tuple[bool, int | None] | None:
        ext = self._ext(ExtensionOID.BASIC_CONSTRAINTS)
        return (ext.value.ca, ext.value.path_length) if ext else None

    @property
    def is_ca(self) -> bool:
        bc = self.basic_constraints
        return bool(bc and bc[0])

    @property
    def is_self_signed(self) -> bool:
        return self.cert.subject == self.cert.issuer

    @property
    def sid(self) -> str | None:
        """The AD SID from the KB5014754 security extension, if present."""
        ext = self._ext(OID_NTDS_SECURITY_EXT)
        if ext is None:
            return None
        value = ext.value
        raw = getattr(value, "value", None)
        return der.decode_sid_extension(raw) if isinstance(raw, bytes) else None

    @property
    def crl_urls(self) -> list[str]:
        ext = self._ext(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        if ext is None:
            return []
        urls: list[str] = []
        for point in ext.value:
            for name in point.full_name or []:
                if isinstance(name, x509.UniformResourceIdentifier):
                    urls.append(name.value)
        return urls

    def _aia(self, method) -> list[str]:
        ext = self._ext(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        if ext is None:
            return []
        return [
            d.access_location.value
            for d in ext.value
            if d.access_method == method
            and isinstance(d.access_location, x509.UniformResourceIdentifier)
        ]

    @property
    def ocsp_urls(self) -> list[str]:
        from cryptography.x509.oid import AuthorityInformationAccessOID as AIA

        return self._aia(AIA.OCSP)

    @property
    def ca_issuer_urls(self) -> list[str]:
        from cryptography.x509.oid import AuthorityInformationAccessOID as AIA

        return self._aia(AIA.CA_ISSUERS)

    @property
    def public_key_algorithm(self) -> str:
        key = self.cert.public_key()
        # cryptography's concrete classes are private (_RSAPublicKey), so strip
        # the leading underscore or the output reads "_RSA 2048 bit".
        name = type(key).__name__.replace("PublicKey", "").lstrip("_")
        curve = getattr(key, "curve", None)
        if curve is not None:
            return f"{name} ({curve.name})"
        size = getattr(key, "key_size", None)
        return f"{name} {size} bit" if size else name

    @property
    def signature_algorithm(self) -> str:
        try:
            algo = self.cert.signature_hash_algorithm
            if algo is not None:
                return algo.name.upper()
        except Exception:  # pragma: no cover - exotic algorithms
            pass
        return self.cert.signature_algorithm_oid.dotted_string

    # ---- serialisation -------------------------------------------------
    def to_dict(self) -> dict:
        bc = self.basic_constraints
        return {
            "source": self.source,
            "subject": self.subject_dn,
            "subject_ad_x500": self.subject_dn_as("ad_x500"),
            "issuer": self.issuer_dn,
            "issuer_ad_x500": self.issuer_dn_as("ad_x500"),
            "serial_number": {
                "decimal": str(self.serial_int),
                "hex": self.serial_hex(colon=True, upper=True),
                "ad_altsecid_hex": self.serial_hex(upper=True, reverse=True),
            },
            "validity": {
                "not_before": self.not_before.isoformat(),
                "not_after": self.not_after.isoformat(),
                "expired": self.expired,
                "not_yet_valid": self.not_yet_valid,
                "days_remaining": self.days_remaining,
            },
            "fingerprint_sha256": self.fingerprint("sha256"),
            "fingerprint_sha1": self.fingerprint("sha1"),
            "subject_key_id": self.subject_key_id.hex().upper()
            if self.subject_key_id
            else None,
            "authority_key_id": self.authority_key_id.hex().upper()
            if self.authority_key_id
            else None,
            "basic_constraints": {"ca": bc[0], "path_length": bc[1]} if bc else None,
            "key_usage": self.key_usage,
            "extended_key_usage": [
                {"oid": oid, "label": EKU_LABELS.get(oid, oid)} for oid in self.eku_oids
            ],
            "san": self.san.to_dict(),
            "sid_extension": self.sid,
            "crl_distribution_points": self.crl_urls,
            "ocsp_responders": self.ocsp_urls,
            "ca_issuers": self.ca_issuer_urls,
            "public_key": self.public_key_algorithm,
            "signature_algorithm": self.signature_algorithm,
            "self_signed": self.is_self_signed,
        }


def _utc(cert: x509.Certificate, base: str) -> _dt.datetime:
    """Prefer the timezone-aware accessors, fall back on older cryptography."""
    value = getattr(cert, base + "_utc", None)
    if value is None:
        value = getattr(cert, base).replace(tzinfo=_dt.timezone.utc)
    return value


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

_PEM_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL
)


def load_certificates(data: bytes, *, source: str = "<memory>") -> list[CertificateInfo]:
    """Parse one or many certificates from PEM, DER or bare base64."""
    if not data or not data.strip():
        raise CertificateError(f"{source}: empty input")

    blocks = _PEM_RE.findall(data)
    if blocks:
        out = []
        for block in blocks:
            cert = x509.load_pem_x509_certificate(block)
            out.append(CertificateInfo(cert, cert.public_bytes(Encoding.DER), source))
        return out

    try:
        cert = x509.load_der_x509_certificate(data)
        return [CertificateInfo(cert, data, source)]
    except Exception:
        pass

    # Bare base64, e.g. `openssl x509 -outform der | base64 -w0`, which is also
    # the shape sssctl cert-show and cert-eval-rule expect.
    try:
        raw = base64.b64decode(re.sub(rb"\s+", b"", data), validate=True)
        cert = x509.load_der_x509_certificate(raw)
        return [CertificateInfo(cert, raw, source)]
    except Exception as exc:
        raise CertificateError(
            f"{source}: not a PEM, DER or base64 encoded certificate ({exc})"
        ) from exc


def load_certificate(data: bytes, *, source: str = "<memory>") -> CertificateInfo:
    certs = load_certificates(data, source=source)
    if len(certs) > 1:
        raise CertificateError(
            f"{source}: expected a single certificate, found {len(certs)}"
        )
    return certs[0]


def load_certificate_file(path: str) -> CertificateInfo:
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        raise CertificateError(f"cannot read {path}: {exc}") from exc
    return load_certificate(data, source=path)
