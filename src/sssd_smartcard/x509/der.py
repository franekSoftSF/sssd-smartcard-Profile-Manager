"""A deliberately small DER reader.

``cryptography`` hands back otherName SAN values and unknown extensions as raw
DER blobs.  Two of those blobs matter a great deal for Smart Card logon and
neither has a high level API:

* ``1.3.6.1.4.1.311.20.2.3`` -- Microsoft UPN, a UTF8String.
* ``1.3.6.1.5.2.2``         -- Kerberos ``KRB5PrincipalName``, used by PKINIT.
* ``1.3.6.1.4.1.311.25.2``  -- the AD "SID extension" (KB5014754).

Rather than pull in an ASN.1 library we decode just these shapes.  Every helper
returns ``None`` instead of raising, because a malformed extension in somebody
else's certificate must never crash an inspection run.
"""

from __future__ import annotations

from typing import Iterator

# Universal tags we care about.
TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_OID = 0x06
TAG_UTF8_STRING = 0x0C
TAG_PRINTABLE_STRING = 0x13
TAG_IA5_STRING = 0x16
TAG_GENERAL_STRING = 0x1B
TAG_BMP_STRING = 0x1E
TAG_SEQUENCE = 0x30

_STRING_TAGS = {
    TAG_UTF8_STRING,
    TAG_PRINTABLE_STRING,
    TAG_IA5_STRING,
    TAG_GENERAL_STRING,
    0x12,  # NumericString
    0x14,  # TeletexString
    0x15,  # VideotexString
    0x1A,  # VisibleString
}


class DerError(ValueError):
    """Raised internally; callers see ``None``."""


def _read_len(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        raise DerError("truncated length")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    count = first & 0x7F
    if count == 0 or count > 4 or pos + count > len(data):
        raise DerError("unsupported length encoding")
    value = int.from_bytes(data[pos : pos + count], "big")
    return value, pos + count


def read_tlv(data: bytes, pos: int = 0) -> tuple[int, bytes, int]:
    """Return ``(tag, content, next_position)`` for one TLV at *pos*."""
    if pos >= len(data):
        raise DerError("truncated tag")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise DerError("multi-byte tags are not supported")
    length, pos = _read_len(data, pos + 1)
    end = pos + length
    if end > len(data):
        raise DerError("truncated content")
    return tag, data[pos:end], end


def children(content: bytes) -> Iterator[tuple[int, bytes]]:
    """Iterate the TLVs inside a constructed value."""
    pos = 0
    while pos < len(content):
        tag, value, pos = read_tlv(content, pos)
        yield tag, value


def decode_string(data: bytes) -> str | None:
    """Decode a DER string value (optionally wrapped in one context tag)."""
    try:
        tag, content, _ = read_tlv(data)
    except DerError:
        return None
    if tag in _STRING_TAGS:
        return content.decode("utf-8", errors="replace")
    if tag == TAG_BMP_STRING:
        return content.decode("utf-16-be", errors="replace")
    if tag == TAG_OCTET_STRING:
        return content.decode("utf-8", errors="replace")
    if tag & 0xA0 == 0xA0:  # context-specific constructed wrapper
        return decode_string(content)
    return None


def decode_upn(value: bytes) -> str | None:
    """Microsoft UPN otherName -- a plain UTF8String."""
    text = decode_string(value)
    return text.strip() if text else None


def decode_krb5_principal(value: bytes) -> str | None:
    """Decode ``KRB5PrincipalName`` into ``name/component@REALM``.

    KRB5PrincipalName ::= SEQUENCE {
        realm         [0] Realm,
        principalName [1] PrincipalName }
    PrincipalName ::= SEQUENCE {
        name-type   [0] Int32,
        name-string [1] SEQUENCE OF KerberosString }
    """
    try:
        tag, outer, _ = read_tlv(value)
        if tag != TAG_SEQUENCE:
            return None
        realm: str | None = None
        parts: list[str] = []
        for ctag, content in children(outer):
            if ctag == 0xA0:  # realm
                realm = decode_string(content)
            elif ctag == 0xA1:  # principalName
                ptag, pseq, _ = read_tlv(content)
                if ptag != TAG_SEQUENCE:
                    continue
                for ntag, ncontent in children(pseq):
                    if ntag == 0xA1:  # name-string
                        stag, sseq, _ = read_tlv(ncontent)
                        if stag != TAG_SEQUENCE:
                            continue
                        for _, comp in children(sseq):
                            parts.append(comp.decode("utf-8", errors="replace"))
        if not parts:
            return None
        principal = "/".join(parts)
        return f"{principal}@{realm}" if realm else principal
    except DerError:
        return None


# szOID_NTDS_CA_SECURITY_EXT / szOID_NTDS_OBJECTSID
_SID_VALUE_OID = b"\x2b\x06\x01\x04\x01\x82\x37\x19\x02\x01"


def decode_sid_extension(value: bytes) -> str | None:
    """Pull the ``S-1-5-21-...`` string out of the AD SID extension.

    The extension body is a ``GeneralNames`` holding one ``otherName`` whose
    value is an OCTET STRING containing the SID in its textual form.
    """
    try:
        tag, seq, _ = read_tlv(value)
        if tag != TAG_SEQUENCE:
            return None
        for gtag, gcontent in children(seq):
            if gtag != 0xA0:  # otherName
                continue
            oid_seen = False
            for itag, icontent in children(gcontent):
                if itag == TAG_OID:
                    oid_seen = icontent == _SID_VALUE_OID
                elif itag == 0xA0 and oid_seen:
                    text = decode_string(icontent)
                    if text and text.upper().startswith("S-"):
                        return text
        return None
    except DerError:
        return None
