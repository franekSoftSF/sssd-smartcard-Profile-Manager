"""Synthetic certificates that look like the real thing.

The fixtures build certificates with the extensions an AD CS / PIV smart card
logon certificate actually carries, so the recommender and the evaluator are
exercised against realistic input rather than a minimal stub.
"""

from __future__ import annotations

import datetime as _dt
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sssd_smartcard.x509.inspect import (  # noqa: E402
    OID_KRB5_PRINCIPAL,
    OID_MS_SMARTCARD_LOGON,
    OID_MS_UPN,
    OID_NTDS_SECURITY_EXT,
    CertificateInfo,
)

UPN = "jan.kowalski@domain-a.local"
SID = "S-1-5-21-1111111111-2222222222-3333333333-1104"
ISSUER_DN_PARTS = [
    x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "local"),
    x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "domain-a"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Enterprise Issuing CA"),
]


def _der_utf8(text: str) -> bytes:
    """Encode *text* as a DER UTF8String."""
    raw = text.encode("utf-8")
    return bytes([0x0C, len(raw)]) + raw


def _der_krb5_principal(name: str, realm: str) -> bytes:
    """Encode a minimal KRB5PrincipalName for the PKINIT SAN."""

    def tlv(tag: int, content: bytes) -> bytes:
        return bytes([tag, len(content)]) + content

    general_string = tlv(0x1B, name.encode())
    name_string = tlv(0x30, general_string)
    principal = tlv(0x30, tlv(0xA0, tlv(0x02, b"\x01")) + tlv(0xA1, name_string))
    realm_part = tlv(0xA0, tlv(0x1B, realm.encode()))
    return tlv(0x30, realm_part + tlv(0xA1, principal))


def _der_sid_extension(sid: str) -> bytes:
    """Encode szOID_NTDS_CA_SECURITY_EXT holding *sid* as a string."""

    def tlv(tag: int, content: bytes) -> bytes:
        return bytes([tag, len(content)]) + content

    oid = b"\x2b\x06\x01\x04\x01\x82\x37\x19\x02\x01"
    octet = tlv(0x04, sid.encode())
    other_name = tlv(0xA0, tlv(0x06, oid) + tlv(0xA0, octet))
    return tlv(0x30, other_name)


def build_cert(
    *,
    subject_cn: str = "Jan Kowalski",
    upn: str | None = UPN,
    pkinit: tuple[str, str] | None = None,
    email: str | None = None,
    sid: str | None = SID,
    ekus: tuple[ObjectIdentifier, ...] = (
        ExtendedKeyUsageOID.CLIENT_AUTH,
        OID_MS_SMARTCARD_LOGON,
    ),
    days_valid: int = 365,
    days_ago: int = 1,
    ca: bool = False,
    ocsp: str | None = "http://pki.domain-a.local/ocsp",
    crl: str | None = "http://pki.domain-a.local/crl/issuing.crl",
) -> CertificateInfo:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "local"),
            x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "domain-a"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Users"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
        ]
    )
    issuer = x509.Name(ISSUER_DN_PARTS)
    now = _dt.datetime.now(_dt.timezone.utc)

    san_entries: list[x509.GeneralName] = []
    if upn:
        san_entries.append(x509.OtherName(OID_MS_UPN, _der_utf8(upn)))
    if pkinit:
        san_entries.append(
            x509.OtherName(OID_KRB5_PRINCIPAL, _der_krb5_principal(*pkinit))
        )
    if email:
        san_entries.append(x509.RFC822Name(email))

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(0x4A3B2C1D5E6F7A8B)
        .not_valid_before(now - _dt.timedelta(days=days_ago))
        .not_valid_after(now - _dt.timedelta(days=days_ago) + _dt.timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
    )
    if ekus:
        builder = builder.add_extension(x509.ExtendedKeyUsage(list(ekus)), False)
    if san_entries:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries), critical=False
        )
    if sid:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(OID_NTDS_SECURITY_EXT, _der_sid_extension(sid)),
            critical=False,
        )
    if ocsp:
        from cryptography.x509.oid import AuthorityInformationAccessOID as AIA

        builder = builder.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AIA.OCSP, x509.UniformResourceIdentifier(ocsp)
                    )
                ]
            ),
            critical=False,
        )
    if crl:
        builder = builder.add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(crl)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )

    cert = builder.sign(key, hashes.SHA256())
    return CertificateInfo(cert, cert.public_bytes(Encoding.DER), "<test>")


@pytest.fixture
def piv_cert() -> CertificateInfo:
    """A typical AD CS smart card logon certificate."""
    return build_cert()


@pytest.fixture
def piv_cert_no_sid() -> CertificateInfo:
    """Same, but issued before the CA got the KB5014754 update."""
    return build_cert(sid=None)


@pytest.fixture
def email_only_cert() -> CertificateInfo:
    """A PKI that issues no UPN at all."""
    return build_cert(upn=None, sid=None, email="jan.kowalski@example.com")


@pytest.fixture
def pkinit_cert() -> CertificateInfo:
    return build_cert(upn=None, sid=None, pkinit=("jan.kowalski", "DOMAIN-A.LOCAL"))
