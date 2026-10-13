"""The registry of certificate-to-user mapping mechanisms.

A mechanism knows four things:

* which ``<...>`` matching-rule components it contributes,
* which LDAP mapping rule it produces,
* which SSSD features that rule depends on,
* how well it suits a given certificate (used by the recommender).

Adding a mechanism is a matter of subclassing :class:`MappingMechanism` and
decorating it with :func:`register`.  Nothing else in the code base enumerates
mechanisms by name.

Deliberately, none of this is tied to a particular PKI.  Microsoft AD CS,
EJBCA, Blinky or anything else that emits X.509 all feed the same mechanisms --
what differs is only which fields their certificates happen to carry.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..errors import ProfileError
from ..model.profile import SmartCardProfile
from ..x509.inspect import CertificateInfo, eku_certmap_token, normalise_eku
from .compat import DEFAULT_VERSION, Version
from .rules import MapRule, MatchRule, MatchTerm, anchored, escape_regex

#: Attribute names per provider.  Only the identity store differs, not the
#: mechanism, which is why this lives in one small table.
ATTRS = {
    "ad": {
        "upn": "userPrincipalName",
        "short": "sAMAccountName",
        "altsecid": "altSecurityIdentities",
        "sid": "objectSid",
        "mail": "mail",
        "cert": "userCertificate;binary",
    },
    "ldap": {
        "upn": "userPrincipalName",
        "short": "uid",
        "altsecid": "altSecurityIdentities",
        "sid": "objectSid",
        "mail": "mail",
        "cert": "userCertificate;binary",
    },
    "ipa": {
        "upn": "krbPrincipalName",
        "short": "uid",
        "altsecid": "ipaCertMapData",
        "sid": "ipaNTSecurityIdentifier",
        "mail": "mail",
        "cert": "userCertificate;binary",
    },
}


@dataclass
class BuildContext:
    """Everything a mechanism needs to render a rule."""

    profile: SmartCardProfile
    version: Version = DEFAULT_VERSION
    cert: CertificateInfo | None = None

    @property
    def attrs(self) -> dict[str, str]:
        return ATTRS.get(self.profile.provider, ATTRS["ad"])

    def option(self, name: str, default=None):
        return self.profile.mapping.options.get(name, default)


@dataclass
class BuiltRule:
    """A rendered certmap rule plus everything worth telling the operator."""

    matchrule: MatchRule
    maprule: MapRule
    domains: list[str] = field(default_factory=list)
    priority: int | None = None
    requires: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    extra_domain_options: dict[str, str] = field(default_factory=dict)


REGISTRY: dict[str, "MappingMechanism"] = {}


def register(cls):
    instance = cls()
    if not instance.key:
        raise ValueError(f"{cls.__name__} has no key")
    REGISTRY[instance.key] = instance
    for alias in instance.aliases:
        REGISTRY.setdefault(alias, instance)
    return cls


def get_mechanism(key: str) -> "MappingMechanism":
    mechanism = REGISTRY.get((key or "").strip().lower())
    if mechanism is None:
        known = ", ".join(sorted({m.key for m in REGISTRY.values()}))
        raise ProfileError(f"unknown mapping type {key!r}; available types: {known}")
    return mechanism


def mechanisms() -> list["MappingMechanism"]:
    """Every distinct mechanism, in registration order."""
    seen: dict[str, MappingMechanism] = {}
    for mechanism in REGISTRY.values():
        seen.setdefault(mechanism.key, mechanism)
    return list(seen.values())


class MappingMechanism:
    """Base class for a certificate-to-user mapping mechanism."""

    key: str = ""
    aliases: tuple[str, ...] = ()
    title: str = ""
    summary: str = ""
    requires: tuple[str, ...] = ()
    options: dict[str, str] = {}
    #: True when the identity store needs data added before this can resolve
    #: a user (e.g. altSecurityIdentities must be populated by an AD admin).
    needs_directory_setup: bool = False

    # -- rule construction ------------------------------------------------
    def match_terms(self, ctx: BuildContext) -> list[MatchTerm]:
        return []

    def map_rule(self, ctx: BuildContext) -> MapRule:  # pragma: no cover - abstract
        raise NotImplementedError

    def notes(self, ctx: BuildContext) -> list[str]:
        return []

    def warnings(self, ctx: BuildContext) -> list[str]:
        return []

    # -- recommendation ---------------------------------------------------
    def confidence(self, cert: CertificateInfo) -> tuple[int, str] | None:
        """Return ``(score 0-100, reason)`` or ``None`` if not applicable."""
        return None

    def expected_identity(self, cert: CertificateInfo) -> str | None:
        """The identity string this mechanism would search for."""
        return None

    def derive_options(self, cert: CertificateInfo) -> dict:
        """Options the recommender should write into a generated profile."""
        return {}

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} {self.key}>"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _suffix_regex(suffix: str | None) -> str:
    """Regex matching any principal, optionally pinned to a realm suffix."""
    if not suffix:
        return ".*"
    return ".*@" + escape_regex(suffix) + "$"


def _upn_suffix(ctx: BuildContext) -> str | None:
    explicit = ctx.option("upn_suffix")
    if explicit is not None:
        return None if explicit in (False, "", "*", "any") else str(explicit)
    if ctx.option("any_suffix") is True:
        return None
    # The accounts may live in a trusted domain, so default to the domain the
    # rule searches rather than the domain whose section it sits in.
    return ctx.profile.target_domains[0]


def base_match_terms(ctx: BuildContext) -> list[MatchTerm]:
    """Issuer/subject/EKU/KU components derived from the profile."""
    terms: list[MatchTerm] = []
    cc = ctx.profile.certificate
    if cc.issuer_regex:
        terms.append(MatchTerm("ISSUER", cc.issuer_regex))
    elif cc.issuer and ctx.profile.validation.check_issuer:
        terms.append(MatchTerm("ISSUER", anchored(cc.issuer)))
    if cc.subject_regex:
        terms.append(MatchTerm("SUBJECT", cc.subject_regex))
    elif cc.subject:
        terms.append(MatchTerm("SUBJECT", anchored(cc.subject)))
    if cc.eku and ctx.profile.validation.check_eku:
        tokens = [eku_certmap_token(normalise_eku(e)) for e in cc.eku]
        terms.append(MatchTerm("EKU", ",".join(tokens)))
    if cc.key_usage:
        terms.append(MatchTerm("KU", ",".join(cc.key_usage)))
    return terms


def build_rule(profile: SmartCardProfile, *, version: Version = DEFAULT_VERSION,
               cert: CertificateInfo | None = None) -> BuiltRule:
    """Render *profile* into a complete certmap rule."""
    ctx = BuildContext(profile, version, cert)
    mechanism = get_mechanism(profile.mapping.type)

    if profile.mapping.matchrule:
        matchrule = MatchRule.parse(profile.mapping.matchrule)
    else:
        terms = base_match_terms(ctx) + mechanism.match_terms(ctx)
        matchrule = MatchRule([terms]) if terms else MatchRule([])

    if profile.mapping.maprule:
        maprule = MapRule.parse(profile.mapping.maprule)
    else:
        maprule = mechanism.map_rule(ctx)

    requires = list(mechanism.requires)
    if maprule.requires_ldapu1:
        requires.append("map.ldapu1_extended")
    requires.append("certmap.section")

    warnings = list(mechanism.warnings(ctx))
    warnings.extend(maprule.validate())
    warnings.extend(matchrule.validate())

    return BuiltRule(
        matchrule=matchrule,
        maprule=maprule,
        domains=profile.target_domains,
        priority=profile.mapping.priority,
        requires=sorted(set(requires)),
        notes=list(mechanism.notes(ctx)),
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Mechanisms
# ---------------------------------------------------------------------------


@register
class SanUpn(MappingMechanism):
    key = "san-upn"
    aliases = ("upn", "san_upn", "ntprincipalname")
    title = "SAN otherName / Microsoft UPN"
    summary = (
        "Read the User Principal Name from the certificate's "
        "otherName=1.3.6.1.4.1.311.20.2.3 SAN and look the user up by it. "
        "The standard mechanism for AD and PIV cards."
    )
    options = {
        "upn_suffix": "Pin the UPN to this realm suffix (default: the profile domain).",
        "any_suffix": "true accepts any UPN suffix.",
        "short_name_fallback": "false drops the sAMAccountName/uid branch of the filter.",
    }

    def match_terms(self, ctx):
        return [MatchTerm("SAN:ntPrincipalName", _suffix_regex(_upn_suffix(ctx)))]

    def map_rule(self, ctx):
        attrs = ctx.attrs
        if ctx.option("short_name_fallback") is False:
            return MapRule(f"({attrs['upn']}={{subject_nt_principal}})")
        return MapRule(
            f"(|({attrs['upn']}={{subject_nt_principal}})"
            f"({attrs['short']}={{subject_nt_principal.short_name}}))"
        )

    def notes(self, ctx):
        suffix = _upn_suffix(ctx)
        if suffix:
            return [
                f"The rule only accepts UPNs ending in @{suffix}. If your users have an "
                "alternative UPN suffix, set mapping.options.upn_suffix or any_suffix: true."
            ]
        return ["Any UPN suffix is accepted."]

    def confidence(self, cert):
        upns = cert.san.upn
        if not upns:
            return None
        return 95, f"certificate carries a SAN UPN ({upns[0]})"

    def expected_identity(self, cert):
        return cert.san.upn[0] if cert.san.upn else None

    def derive_options(self, cert):
        upn = cert.san.upn[0] if cert.san.upn else None
        if upn and "@" in upn:
            return {"upn_suffix": upn.rsplit("@", 1)[1]}
        return {}


@register
class SanPkinit(MappingMechanism):
    key = "san-pkinit"
    aliases = ("pkinit", "san_pkinit")
    title = "SAN otherName / Kerberos PKINIT principal"
    summary = (
        "Read the Kerberos principal from the id-pkinit-san SAN "
        "(otherName=1.3.6.1.5.2.2). Used by IPA and by MIT-issued certificates."
    )
    options = {
        "realm": "Pin the principal to this realm (default: the profile domain).",
        "any_suffix": "true accepts any realm.",
    }

    def match_terms(self, ctx):
        default = None if ctx.option("any_suffix") is True else ctx.profile.target_domains[0]
        realm = ctx.option("realm", default)
        return [MatchTerm("SAN:pkinit", _suffix_regex(realm))]

    def map_rule(self, ctx):
        attrs = ctx.attrs
        return MapRule(
            f"(|({attrs['upn']}={{subject_pkinit_principal}})"
            f"({attrs['short']}={{subject_pkinit_principal.short_name}}))"
        )

    def confidence(self, cert):
        principals = cert.san.pkinit
        if not principals:
            return None
        return 85, f"certificate carries a PKINIT principal ({principals[0]})"

    def expected_identity(self, cert):
        return cert.san.pkinit[0] if cert.san.pkinit else None


@register
class SanRfc822(MappingMechanism):
    key = "san-rfc822"
    aliases = ("rfc822", "email", "san-email")
    title = "SAN rfc822Name / e-mail address"
    summary = (
        "Look the user up by the e-mail address in the SAN. Useful for PKIs that "
        "do not issue a UPN, but only as strong as the mail attribute in the directory."
    )
    options = {
        "attribute": "Directory attribute holding the address (default: mail).",
        "domain_suffix": "Pin the address to this domain.",
    }

    def match_terms(self, ctx):
        suffix = ctx.option("domain_suffix")
        pattern = ".*@" + escape_regex(str(suffix)) + "$" if suffix else ".*@.*"
        return [MatchTerm("SAN:rfc822Name", pattern)]

    def map_rule(self, ctx):
        attrs = ctx.attrs
        attribute = ctx.option("attribute", attrs["mail"])
        if ctx.profile.provider == "ad":
            return MapRule(
                f"(|({attribute}={{subject_rfc822_name}})"
                f"({attrs['upn']}={{subject_rfc822_name}}))"
            )
        return MapRule(
            f"(|({attribute}={{subject_rfc822_name}})"
            f"({attrs['short']}={{subject_rfc822_name.short_name}}))"
        )

    def warnings(self, ctx):
        return [
            "E-mail mapping is only as trustworthy as the mail attribute in the "
            "directory; make sure it is unique and administratively controlled."
        ]

    def confidence(self, cert):
        mails = cert.san.rfc822
        if not mails:
            return None
        return 55, f"certificate carries a SAN rfc822Name ({mails[0]})"

    def expected_identity(self, cert):
        return cert.san.rfc822[0] if cert.san.rfc822 else None

    def derive_options(self, cert):
        mails = cert.san.rfc822
        if mails and "@" in mails[0]:
            return {"domain_suffix": mails[0].rsplit("@", 1)[1]}
        return {}


@register
class SubjectDn(MappingMechanism):
    key = "subject"
    aliases = ("subject-dn", "subject_dn")
    title = "Subject DN"
    summary = (
        "Match on the certificate's subject DN and look the user up through the "
        "directory attribute that records it (altSecurityIdentities on AD)."
    )
    needs_directory_setup = True
    options = {
        "attribute": "Directory attribute to search (default: provider specific).",
        "form": "'ad-subject' (default) writes X509:<S>..., 'raw' writes the bare DN.",
        "dn_style": "DN rendering: ad_x500 (default for AD), nss_ldap, ...",
    }

    def match_terms(self, ctx):
        if ctx.profile.certificate.subject or ctx.profile.certificate.subject_regex:
            return []  # already contributed by base_match_terms
        return [MatchTerm("SUBJECT", ".*")]

    def map_rule(self, ctx):
        attrs = ctx.attrs
        attribute = ctx.option("attribute", attrs["altsecid"])
        form = str(ctx.option("form", "ad-subject"))
        style = str(ctx.option("dn_style", "ad_x500" if ctx.profile.provider == "ad" else "nss_ldap"))
        if form == "raw":
            return MapRule(f"({attribute}={{subject_dn!{style}}})")
        return MapRule(f"({attribute}=X509:<S>{{subject_dn!{style}}})")

    def warnings(self, ctx):
        return [
            "Subject-only mapping is a weak binding: any CA the host trusts could issue "
            "a certificate with the same subject. Prefer san-upn, sid-extension or "
            "issuer-serial, or at minimum pin certificate.issuer."
        ]

    def confidence(self, cert):
        return 35, "every certificate has a subject, but the binding is weak and the "\
                   "directory attribute must be populated by hand"

    def expected_identity(self, cert):
        return cert.subject_dn_as("ad_x500")


@register
class IssuerSubject(MappingMechanism):
    key = "issuer-subject"
    aliases = ("issuer_subject", "issuer-and-subject")
    title = "Issuer + Subject"
    summary = (
        "Bind both the issuing CA and the subject DN, the classic AD "
        "altSecurityIdentities X509:<I>...<S>... form."
    )
    needs_directory_setup = True
    options = {
        "attribute": "Directory attribute to search (default: provider specific).",
        "dn_style": "DN rendering (default: ad_x500, which is what AD stores).",
    }

    def match_terms(self, ctx):
        terms = []
        if not (ctx.profile.certificate.issuer or ctx.profile.certificate.issuer_regex):
            terms.append(MatchTerm("ISSUER", ".*"))
        return terms

    def map_rule(self, ctx):
        attribute = ctx.option("attribute", ctx.attrs["altsecid"])
        style = str(ctx.option("dn_style", "ad_x500"))
        return MapRule(
            f"({attribute}=X509:<I>{{issuer_dn!{style}}}<S>{{subject_dn!{style}}})"
        )

    def notes(self, ctx):
        return [
            "The directory entry must contain a matching altSecurityIdentities value. "
            "Run `sssd-smartcard mapping test` against a real certificate to see the "
            "exact string to add."
        ]

    def confidence(self, cert):
        return 60, "works for any certificate, but altSecurityIdentities must be "\
                   "populated on the user object first"

    def expected_identity(self, cert):
        return (
            f"X509:<I>{cert.issuer_dn_as('ad_x500')}<S>{cert.subject_dn_as('ad_x500')}"
        )


@register
class IssuerSerial(MappingMechanism):
    key = "issuer-serial"
    aliases = ("issuer_serial", "altsecid-serial", "strong-serial")
    title = "Issuer + Serial Number (AD strong mapping)"
    summary = (
        "The X509:<I>...<SR>... form Microsoft counts as a strong certificate "
        "mapping under KB5014754."
    )
    requires = ("map.ldapu1_extended",)
    needs_directory_setup = True
    options = {
        "attribute": "Directory attribute to search (default: provider specific).",
        "dn_style": "Issuer DN rendering (default: ad_x500).",
    }

    def match_terms(self, ctx):
        if not (ctx.profile.certificate.issuer or ctx.profile.certificate.issuer_regex):
            return [MatchTerm("ISSUER", ".*")]
        return []

    def map_rule(self, ctx):
        attribute = ctx.option("attribute", ctx.attrs["altsecid"])
        style = str(ctx.option("dn_style", "ad_x500"))
        return MapRule(
            f"({attribute}=X509:<I>{{issuer_dn!{style}}}<SR>{{serial_number!hex_ur}})",
            prefix="LDAPU1",
        )

    def notes(self, ctx):
        return [
            "Requires SSSD 2.8.2 or newer for the {serial_number} template.",
            "AD stores the serial byte-reversed and upper case, which is what "
            "{serial_number!hex_ur} produces.",
        ]

    def confidence(self, cert):
        return 60, "a strong AD mapping, but altSecurityIdentities must be populated "\
                   "on the user object first"

    def expected_identity(self, cert):
        return (
            f"X509:<I>{cert.issuer_dn_as('ad_x500')}"
            f"<SR>{cert.serial_hex(upper=True, reverse=True)}"
        )


@register
class SubjectKeyId(MappingMechanism):
    key = "subject-key-id"
    aliases = ("ski", "subject_key_id")
    title = "Subject Key Identifier (AD strong mapping)"
    summary = "The X509:<SKI>... altSecurityIdentities form."
    requires = ("map.ldapu1_extended",)
    needs_directory_setup = True
    options = {"attribute": "Directory attribute to search."}

    def match_terms(self, ctx):
        return []

    def map_rule(self, ctx):
        attribute = ctx.option("attribute", ctx.attrs["altsecid"])
        return MapRule(
            f"({attribute}=X509:<SKI>{{subject_key_id!hex_u}})", prefix="LDAPU1"
        )

    def notes(self, ctx):
        return ["Requires SSSD 2.8.2 or newer for the {subject_key_id} template."]

    def confidence(self, cert):
        if not cert.subject_key_id:
            return None
        return 58, "certificate has a Subject Key Identifier, but "\
                   "altSecurityIdentities must be populated first"

    def expected_identity(self, cert):
        ski = cert.subject_key_id
        return f"X509:<SKI>{ski.hex().upper()}" if ski else None


@register
class SidExtension(MappingMechanism):
    key = "sid-extension"
    aliases = ("sid", "ntds-sid", "kb5014754")
    title = "AD SID security extension"
    summary = (
        "Look the user up by the SID embedded in the certificate by AD CS "
        "(szOID_NTDS_CA_SECURITY_EXT, 1.3.6.1.4.1.311.25.2). The strongest binding "
        "available and it needs no changes on the user object."
    )
    requires = ("map.ldapu1_extended",)
    options = {"attribute": "Directory attribute holding the SID (default: objectSid)."}

    def match_terms(self, ctx):
        return []

    def map_rule(self, ctx):
        attribute = ctx.option("attribute", ctx.attrs["sid"])
        return MapRule(f"({attribute}={{sid}})", prefix="LDAPU1")

    def notes(self, ctx):
        return [
            "Requires SSSD 2.8.2 or newer for the {sid} template.",
            "Only certificates issued by an AD CS that adds the SID extension carry "
            "this value; certificates from other PKIs will not match this rule.",
        ]

    def confidence(self, cert):
        sid = cert.sid
        if not sid:
            return None
        return 90, f"certificate carries the AD SID extension ({sid})"

    def expected_identity(self, cert):
        return cert.sid


@register
class SubjectDnComponent(MappingMechanism):
    key = "subject-dn-component"
    aliases = ("dn-component", "subject_dn_component")
    title = "Single Subject DN component"
    summary = (
        "Take one attribute out of the subject DN (typically CN or UID) and use it "
        "as the login name."
    )
    requires = ("map.ldapu1_extended",)
    options = {
        "component": "DN attribute to take, e.g. CN or UID (default: CN).",
        "attribute": "Directory attribute to search (default: provider short name).",
    }

    def match_terms(self, ctx):
        if ctx.profile.certificate.subject or ctx.profile.certificate.subject_regex:
            return []
        component = str(ctx.option("component", "CN"))
        return [MatchTerm("SUBJECT", escape_regex(component + "=") + ".*")]

    def map_rule(self, ctx):
        component = str(ctx.option("component", "CN"))
        attribute = ctx.option("attribute", ctx.attrs["short"])
        return MapRule(
            f"({attribute}={{subject_dn_component.{component}}})", prefix="LDAPU1"
        )

    def warnings(self, ctx):
        component = str(ctx.option("component", "CN"))
        return [
            f"This assumes the certificate's {component} is exactly the login name. "
            "Verify with `sssd-smartcard mapping test` before relying on it."
        ]

    def confidence(self, cert):
        cn = cert.common_name
        if not cn:
            return None
        if "@" in cn or " " in cn:
            return 20, f"the CN ({cn!r}) does not look like a login name"
        return 40, f"the CN ({cn!r}) could be the login name, but this is a guess"

    def expected_identity(self, cert):
        return cert.common_name


@register
class CertificateBinary(MappingMechanism):
    key = "certificate-binary"
    aliases = ("cert-binary", "certificate", "usercertificate")
    title = "Full certificate stored on the user object"
    summary = (
        "Search for the whole DER certificate in the directory. This is SSSD's own "
        "default mapping rule."
    )
    # The certificate has to be published on the user object first.
    needs_directory_setup = True
    options = {
        "attribute": "Directory attribute holding the certificate.",
        "encoding": "'bin' (default, escaped hex) or 'base64'.",
    }

    def match_terms(self, ctx):
        return []

    def map_rule(self, ctx):
        attribute = ctx.option("attribute", ctx.attrs["cert"])
        encoding = str(ctx.option("encoding", "bin"))
        if encoding not in ("bin", "base64"):
            raise ProfileError(
                "mapping.options.encoding: expected 'bin' or 'base64', got "
                f"{encoding!r}"
            )
        return MapRule(f"({attribute}={{cert!{encoding}}})")

    def warnings(self, ctx):
        if ctx.profile.provider == "ad":
            return [
                "The AD provider does not read certificates by default. Add "
                "ldap_user_certificate = userCertificate;binary to the domain section, "
                "otherwise this rule can never match.",
            ]
        return []

    def confidence(self, cert):
        return 45, "always renders, but the exact certificate must already be stored "\
                   "on the user object"

    def expected_identity(self, cert):
        return f"<DER certificate, SHA-256 {cert.fingerprint('sha256')}>"


@register
class CustomRule(MappingMechanism):
    key = "custom"
    aliases = ("raw",)
    title = "Hand-written matchrule / maprule"
    summary = (
        "Pass matchrule, maprule and domains straight through, for rules the "
        "built-in mechanisms do not cover."
    )
    options = {}

    def match_terms(self, ctx):
        return []

    def map_rule(self, ctx):
        if not ctx.profile.mapping.maprule:
            raise ProfileError(
                "mapping.type is 'custom' but mapping.maprule is not set; a custom "
                "mapping must supply its own maprule (and usually a matchrule)"
            )
        return MapRule.parse(ctx.profile.mapping.maprule)

    def notes(self, ctx):
        return [
            "Custom rules are passed through verbatim. Validate them with "
            "`sssctl cert-eval-rule` on the target host before applying."
        ]

    def confidence(self, cert):
        return None
