"""Distinguished-name rendering in the four styles libsss_certmap knows.

``sss-certmap(5)`` lets a mapping rule ask for a DN as ``{subject_dn!ad_x500}``
and friends.  The two axes are:

* *component order* -- ``x500`` puts the most general component first (the DER
  order, which is what Active Directory shows in ``altSecurityIdentities``);
  ``ldap`` puts the most specific component first (RFC 4514 order).
* *attribute naming* -- ``ad`` uses Active Directory's short names, ``nss``
  uses the names NSS prints.

CAVEAT: the name tables below cover the attributes that actually turn up in
PIV/AD logon certificates.  They are a local approximation of what
libsss_certmap does, good enough to preview a rule offline.  Whenever SSSD is
installed the caller should prefer ``sssctl cert-eval-rule``, which is the
authority -- see :mod:`sssd_smartcard.certmap.evaluator`.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.x509.oid import NameOID

STYLES = ("nss", "nss_ldap", "nss_x500", "ad", "ad_ldap", "ad_x500")

# Names both dialects agree on.
_COMMON: dict[str, str] = {
    NameOID.COMMON_NAME.dotted_string: "CN",
    NameOID.ORGANIZATIONAL_UNIT_NAME.dotted_string: "OU",
    NameOID.ORGANIZATION_NAME.dotted_string: "O",
    NameOID.LOCALITY_NAME.dotted_string: "L",
    NameOID.COUNTRY_NAME.dotted_string: "C",
    NameOID.DOMAIN_COMPONENT.dotted_string: "DC",
    NameOID.USER_ID.dotted_string: "UID",
    NameOID.STREET_ADDRESS.dotted_string: "STREET",
    NameOID.SERIAL_NUMBER.dotted_string: "SERIALNUMBER",
    NameOID.SURNAME.dotted_string: "SN",
    NameOID.GIVEN_NAME.dotted_string: "GN",
    NameOID.TITLE.dotted_string: "T",
}

# Where the dialects differ.
_NSS_ONLY: dict[str, str] = {
    NameOID.STATE_OR_PROVINCE_NAME.dotted_string: "ST",
    NameOID.EMAIL_ADDRESS.dotted_string: "E",
}
_AD_ONLY: dict[str, str] = {
    NameOID.STATE_OR_PROVINCE_NAME.dotted_string: "S",
    NameOID.EMAIL_ADDRESS.dotted_string: "E",
}

_NSS_NAMES = {**_COMMON, **_NSS_ONLY}
_AD_NAMES = {**_COMMON, **_AD_ONLY}

#: RFC 4514 section 2.4 -- characters that must be escaped inside an RDN value.
_ESCAPE = {
    ",": r"\,",
    "+": r"\+",
    '"': r"\"",
    "\\": "\\\\",
    "<": r"\<",
    ">": r"\>",
    ";": r"\;",
}


def normalise_style(style: str | None) -> tuple[str, str]:
    """Return ``(dialect, order)`` for a template conversion suffix."""
    style = (style or "nss_ldap").lower()
    if style not in STYLES:
        raise ValueError(f"unknown DN style {style!r}; expected one of {', '.join(STYLES)}")
    if style in ("nss", "nss_ldap"):
        return "nss", "ldap"
    if style == "nss_x500":
        return "nss", "x500"
    if style in ("ad", "ad_x500"):
        return "ad", "x500"
    return "ad", "ldap"  # ad_ldap


def _escape_value(value: str) -> str:
    out = "".join(_ESCAPE.get(ch, ch) for ch in value)
    if out.startswith("#") or out.startswith(" "):
        out = "\\" + out
    if out.endswith(" ") and not out.endswith("\\ "):
        out = out[:-1] + "\\ "
    return out


def _attr_text(attr: x509.NameAttribute, names: dict[str, str]) -> str:
    oid = attr.oid.dotted_string
    label = names.get(oid, oid)
    value = attr.value
    if isinstance(value, bytes):
        return f"{label}=#" + value.hex()
    return f"{label}={_escape_value(value)}"


def format_dn(name: x509.Name, style: str | None = "nss_ldap") -> str:
    """Render *name* the way libsss_certmap's ``{subject_dn!style}`` would."""
    dialect, order = normalise_style(style)
    names = _AD_NAMES if dialect == "ad" else _NSS_NAMES
    # cryptography keeps ``rdns`` in DER order == most general first == X.500.
    rdns = list(name.rdns)
    if order == "ldap":
        rdns = list(reversed(rdns))
    parts = []
    for rdn in rdns:
        parts.append("+".join(_attr_text(attr, names) for attr in rdn))
    return ",".join(parts)


def dn_components(name: x509.Name, style: str | None = "nss_ldap") -> list[tuple[str, str]]:
    """Flat ``(attribute, value)`` list, most specific first (LDAP order)."""
    dialect, _ = normalise_style(style)
    names = _AD_NAMES if dialect == "ad" else _NSS_NAMES
    out: list[tuple[str, str]] = []
    for rdn in reversed(list(name.rdns)):
        for attr in rdn:
            label = names.get(attr.oid.dotted_string, attr.oid.dotted_string)
            value = attr.value
            out.append((label, value if isinstance(value, str) else value.hex()))
    return out
