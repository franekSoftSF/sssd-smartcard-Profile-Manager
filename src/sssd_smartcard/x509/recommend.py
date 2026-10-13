"""Turn a real certificate into a ready-to-use profile.

This is the module behind ``cert inspect`` and ``cert autoconfig``: read a
certificate off a card or a file, work out which mapping mechanisms it can
actually support, rank them, and emit a complete ``SmartCardProfile`` whose
rendered certmap section is meant to work as-is.

Every ranking decision carries the reason it was made, because an administrator
should be able to disagree with the tool and see exactly what it looked at.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field

from .. import __version__
from ..certmap.compat import DEFAULT_VERSION, Version, feature
from ..certmap.mappings import MappingMechanism, get_mechanism, mechanisms
from ..model.profile import (
    LOCAL_SMARTCARD_PROVIDERS,
    AuthenticationSpec,
    CATrustSpec,
    CertificateConstraints,
    MappingSpec,
    RevocationSpec,
    SmartCardProfile,
    ValidationSpec,
)
from .inspect import (
    EKU_KEYWORDS,
    OID_MS_SMARTCARD_LOGON,
    CertificateInfo,
)
from cryptography.x509.oid import ExtendedKeyUsageOID

CLIENT_AUTH_OID = ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string
SMARTCARD_LOGON_OID = OID_MS_SMARTCARD_LOGON.dotted_string

#: EKUs worth pinning in a matching rule.  Pinning every EKU a certificate
#: happens to carry makes the rule brittle; these two are the ones that mean
#: "this certificate is for interactive logon".
PINNABLE_EKUS = (CLIENT_AUTH_OID, SMARTCARD_LOGON_OID)


#: Subtracted from a mechanism's intrinsic score when it cannot resolve anyone
#: until an administrator writes a value onto every user object.  A mechanism
#: that works against an untouched directory is worth more in practice than a
#: theoretically stronger one that nobody has provisioned yet.
DIRECTORY_SETUP_PENALTY = 20


@dataclass
class Candidate:
    """One mapping mechanism scored against a certificate."""

    mechanism: MappingMechanism
    score: int
    reason: str
    identity: str | None = None
    options: dict = field(default_factory=dict)
    blocked: str | None = None
    intrinsic_score: int | None = None
    penalty: int = 0

    @property
    def key(self) -> str:
        return self.mechanism.key

    @property
    def usable(self) -> bool:
        return self.blocked is None

    def to_dict(self) -> dict:
        return {
            "type": self.key,
            "title": self.mechanism.title,
            "score": self.score,
            "intrinsic_score": self.intrinsic_score,
            "provisioning_penalty": self.penalty,
            "reason": self.reason,
            "resolved_identity": self.identity,
            "options": self.options,
            "needs_directory_setup": self.mechanism.needs_directory_setup,
            "blocked": self.blocked,
        }


@dataclass
class Observation:
    """Something noticed about the certificate, with a severity."""

    level: str  # info | warn | error
    text: str
    hint: str = ""

    def to_dict(self) -> dict:
        return {"level": self.level, "text": self.text, "hint": self.hint}


@dataclass
class Recommendation:
    """The full result of inspecting one certificate."""

    cert: CertificateInfo
    candidates: list[Candidate]
    observations: list[Observation]
    domain: str | None
    domain_reason: str
    version: Version
    provider: str

    @property
    def best(self) -> Candidate | None:
        usable = [c for c in self.candidates if c.usable]
        return usable[0] if usable else None

    @property
    def alternatives(self) -> list[Candidate]:
        best = self.best
        return [c for c in self.candidates if c is not best]

    @property
    def blocking(self) -> list[Observation]:
        return [o for o in self.observations if o.level == "error"]

    def to_dict(self) -> dict:
        best = self.best
        return {
            "certificate": self.cert.to_dict(),
            "domain": self.domain,
            "domain_reason": self.domain_reason,
            "target_sssd_version": str(self.version),
            "provider": self.provider,
            "recommended": best.to_dict() if best else None,
            "candidates": [c.to_dict() for c in self.candidates],
            "observations": [o.to_dict() for o in self.observations],
        }


# ---------------------------------------------------------------------------
# Domain inference
# ---------------------------------------------------------------------------


def infer_domain(cert: CertificateInfo) -> tuple[str | None, str]:
    """Guess the AD domain the user lives in, and say why."""
    for upn in cert.san.upn:
        if "@" in upn:
            return upn.rsplit("@", 1)[1].lower(), "taken from the SAN UPN suffix"
    for principal in cert.san.pkinit:
        if "@" in principal:
            return principal.rsplit("@", 1)[1].lower(), "taken from the PKINIT realm"
    dc = cert.dc_domain
    if dc:
        return dc.lower(), "built from the DC components of the subject DN"
    dc = cert.issuer_dc_domain
    if dc:
        return dc.lower(), "built from the DC components of the issuer DN (the CA's domain)"
    for mail in cert.san.rfc822:
        if "@" in mail:
            return mail.rsplit("@", 1)[1].lower(), "taken from the SAN e-mail domain"
    return None, "could not be derived from the certificate"


# ---------------------------------------------------------------------------
# Observations
# ---------------------------------------------------------------------------


def observe(cert: CertificateInfo, version: Version) -> list[Observation]:
    out: list[Observation] = []

    if cert.expired:
        out.append(
            Observation(
                "error",
                f"the certificate expired on {cert.not_after:%Y-%m-%d %H:%M UTC}",
                "SSSD rejects expired certificates; use a current one to build the profile.",
            )
        )
    elif cert.not_yet_valid:
        out.append(
            Observation(
                "error",
                f"the certificate is not valid until {cert.not_before:%Y-%m-%d %H:%M UTC}",
            )
        )
    elif cert.days_remaining < 30:
        out.append(
            Observation("warn", f"the certificate expires in {cert.days_remaining} day(s)")
        )

    if cert.is_ca:
        out.append(
            Observation(
                "error",
                "this is a CA certificate (basicConstraints CA:TRUE), not a user certificate",
                "Pass a user/PIV certificate here; feed CA certificates to `ca import` instead.",
            )
        )

    eku = cert.eku_oids
    if not eku:
        out.append(
            Observation(
                "warn",
                "the certificate has no Extended Key Usage extension",
                "SSSD's built-in default matchrule is KRB5:<EKU>clientAuth, which such a "
                "certificate can never satisfy. The generated profile therefore does not "
                "pin an EKU -- consider pinning the issuer instead.",
            )
        )
    else:
        if CLIENT_AUTH_OID not in eku:
            out.append(
                Observation(
                    "warn",
                    "the certificate does not carry the clientAuth EKU",
                    "SSSD's default matchrule requires clientAuth. The generated rule pins "
                    "the EKUs this certificate actually has, so it still matches.",
                )
            )
        if SMARTCARD_LOGON_OID not in eku:
            out.append(
                Observation(
                    "info",
                    "no Microsoft Smart Card Logon EKU (1.3.6.1.4.1.311.20.2.2)",
                    "Windows requires it for smart card logon; SSSD does not. Harmless on Linux.",
                )
            )

    san = cert.san
    if san.empty:
        out.append(
            Observation(
                "warn",
                "the certificate has no Subject Alternative Name",
                "Only subject-based or full-certificate mappings are possible.",
            )
        )
    if len(san.upn) > 1:
        out.append(
            Observation(
                "warn",
                f"the certificate carries {len(san.upn)} UPNs: {', '.join(san.upn)}",
                "The generated rule uses the first one.",
            )
        )

    if cert.sid:
        if feature("map.ldapu1_extended").available_in(version):
            out.append(
                Observation(
                    "info",
                    f"the AD SID security extension is present ({cert.sid})",
                    "This allows the strongest mapping available (KB5014754).",
                )
            )
        else:
            out.append(
                Observation(
                    "warn",
                    f"the AD SID extension is present ({cert.sid}) but the target SSSD "
                    f"{version} is older than 2.8.2",
                    "Upgrade SSSD to use the {sid} template, or map by UPN.",
                )
            )
    else:
        out.append(
            Observation(
                "info",
                "no AD SID security extension",
                "Certificates from AD CS carry it only when the CA has the KB5014754 update "
                "and the template is configured for it.",
            )
        )

    if cert.ocsp_urls:
        out.append(
            Observation("info", "OCSP responder advertised: " + ", ".join(cert.ocsp_urls))
        )
    if cert.crl_urls:
        out.append(
            Observation(
                "info",
                "CRL distribution point advertised: " + ", ".join(cert.crl_urls),
                "SSSD reads a CRL from a local PEM file (crl_file=); it does not fetch this "
                "URL itself, so something has to download and refresh it.",
            )
        )
    if not cert.ocsp_urls and not cert.crl_urls:
        out.append(
            Observation(
                "info",
                "the certificate advertises neither OCSP nor a CRL distribution point",
                "Revocation checking would need a manually supplied CRL or default responder.",
            )
        )

    if cert.is_self_signed:
        out.append(
            Observation(
                "warn",
                "the certificate is self-signed",
                "There is no issuing CA to pin or to put in the trust bundle.",
            )
        )
    return out


# ---------------------------------------------------------------------------
# Ranking
# ---------------------------------------------------------------------------


def rank(cert: CertificateInfo, version: Version) -> list[Candidate]:
    """Score every registered mechanism against *cert*."""
    out: list[Candidate] = []
    for mechanism in mechanisms():
        scored = mechanism.confidence(cert)
        if scored is None:
            continue
        intrinsic, reason = scored
        blocked = None
        for key in mechanism.requires:
            feat = feature(key)
            if not feat.available_in(version):
                blocked = (
                    f"needs SSSD {feat.since} or newer ({feat.description}); "
                    f"target is {version}"
                )
                break
        penalty = DIRECTORY_SETUP_PENALTY if mechanism.needs_directory_setup else 0
        out.append(
            Candidate(
                mechanism=mechanism,
                score=max(intrinsic - penalty, 0),
                reason=reason,
                identity=mechanism.expected_identity(cert),
                options=mechanism.derive_options(cert),
                blocked=blocked,
                intrinsic_score=intrinsic,
                penalty=penalty,
            )
        )
    out.sort(key=lambda c: (c.blocked is not None, -c.score, c.key))
    return out


def recommend(
    cert: CertificateInfo,
    *,
    domain: str | None = None,
    provider: str = "ad",
    version: Version = DEFAULT_VERSION,
) -> Recommendation:
    """Inspect *cert* and rank the mapping mechanisms it can support."""
    inferred, reason = infer_domain(cert)
    if domain:
        chosen, chosen_reason = domain, "given on the command line"
        if inferred and inferred != domain.lower():
            reason = f"{reason}: {inferred}"
    else:
        chosen, chosen_reason = inferred, reason
    return Recommendation(
        cert=cert,
        candidates=rank(cert, version),
        observations=observe(cert, version),
        domain=chosen,
        domain_reason=chosen_reason,
        version=version,
        provider=provider,
    )


# ---------------------------------------------------------------------------
# Profile generation
# ---------------------------------------------------------------------------


def suggest_name(cert: CertificateInfo, mechanism_key: str, domain: str | None) -> str:
    """A stable, readable profile name derived from the certificate."""
    base = (domain or "sc").split(".")[0].upper()
    suffix = {
        "san-upn": "UPN",
        "san-pkinit": "PKINIT",
        "san-rfc822": "MAIL",
        "sid-extension": "SID",
        "issuer-serial": "ISSUER-SERIAL",
        "issuer-subject": "ISSUER-SUBJECT",
        "subject-key-id": "SKI",
        "subject": "SUBJECT",
        "subject-dn-component": "DN-COMPONENT",
        "certificate-binary": "CERT",
    }.get(mechanism_key, mechanism_key.upper())
    return f"{base}-{suffix}"


def recommended_ekus(cert: CertificateInfo) -> list[str]:
    """EKU tokens worth pinning, taken from what the certificate really has."""
    present = cert.eku_oids
    pinned = [oid for oid in PINNABLE_EKUS if oid in present]
    if not pinned:
        # Nothing recognisable: pin everything rather than pin a lie, but only
        # when the list is short enough to stay readable.
        pinned = present[:3]
    return [EKU_KEYWORDS.get(oid, oid) for oid in pinned]


def build_profile(
    recommendation: Recommendation,
    *,
    name: str | None = None,
    mechanism_key: str | None = None,
    pin_issuer: bool = True,
    pin_eku: bool = True,
    with_revocation: bool = False,
    require_smartcard: bool = False,
    ca_bundle: str | None = None,
    section_domain: str | None = None,
    sssd_domains: list[str] | None = None,
) -> SmartCardProfile:
    """Compose a complete profile from an inspection result.

    ``section_domain`` is the SSSD domain whose ``[certmap/...]`` section the
    rule belongs to -- the domain this host is *joined* to.  When it differs
    from the domain the certificate points at, the accounts live in a trusted
    domain and the difference is written out as ``mapping.domains``.
    """
    cert = recommendation.cert
    if mechanism_key:
        mechanism = get_mechanism(mechanism_key)
        candidate = next(
            (c for c in recommendation.candidates if c.key == mechanism.key), None
        )
        options = candidate.options if candidate else mechanism.derive_options(cert)
    else:
        candidate = recommendation.best
        if candidate is None:
            from ..errors import CertificateError

            raise CertificateError(
                "no mapping mechanism fits this certificate on the target SSSD version; "
                "run `cert inspect` to see why"
            )
        mechanism, options = candidate.mechanism, candidate.options

    account_domain = recommendation.domain or "example.local"
    domain = section_domain or account_domain
    # A UPN suffix that differs from the joined domain is either a trusted
    # domain or an alternative UPN suffix, and the two want opposite
    # configurations. The question that separates them: is that suffix a domain
    # SSSD actually knows?
    search_domains: list[str] = []
    known = {d.lower() for d in (sssd_domains or [])}
    if section_domain and section_domain.lower() != account_domain.lower():
        if not known or account_domain.lower() in known:
            # A real trusted domain, or no way to tell -- direct the search
            # there, which is what domains= is for.
            search_domains = [account_domain]
        else:
            # An alternative UPN suffix: the accounts live in this domain and
            # merely log in under another suffix. domains= would name a domain
            # SSSD has never heard of, and pinning this one suffix would reject
            # every card issued under any other -- a lab can have several, with
            # the AD UPN aligned to Entra ID. Accept any suffix instead; the
            # trust still rests on the pinned issuer and EKU, and the LDAP
            # lookup resolves whatever UPN the card actually carries.
            options = dict(options)
            options.pop("upn_suffix", None)
            options["any_suffix"] = True

    constraints = CertificateConstraints()
    if pin_issuer and not cert.is_self_signed:
        constraints.issuer = cert.issuer_dn
    if pin_eku:
        constraints.eku = recommended_ekus(cert)

    revocation = RevocationSpec()
    if with_revocation:
        if cert.ocsp_urls:
            revocation = RevocationSpec(
                enabled=True, method="ocsp", fail_mode="closed", ocsp_digest="sha256"
            )
        elif cert.crl_urls:
            revocation = RevocationSpec(
                enabled=True,
                method="crl",
                fail_mode="closed",
                crl_file="/etc/sssd/pki/revocation.crl.pem",
            )

    profile = SmartCardProfile(
        name=name or suggest_name(cert, mechanism.key, recommendation.domain),
        domain=domain,
        description=(
            f"Generated from {cert.source} -- {mechanism.title}"
            + (f" for {candidate.identity}" if candidate and candidate.identity else "")
        ),
        provider=recommendation.provider,
        certificate=constraints,
        mapping=MappingSpec(
            type=mechanism.key, options=dict(options), domains=search_domains
        ),
        validation=ValidationSpec(
            check_issuer=bool(constraints.issuer),
            check_eku=bool(constraints.eku),
            check_expiration=True,
            check_revocation=revocation.enabled,
        ),
        authentication=AuthenticationSpec(
            mode="required" if require_smartcard else "optional",
            # Stated explicitly rather than left to the provider default, so the
            # saved profile shows the operator the option that decides whether a
            # card produces a PIN prompt or a password prompt.
            local_smartcard=(
                recommendation.provider in LOCAL_SMARTCARD_PROVIDERS
                if feature("auth.local_smartcard").available_in(recommendation.version)
                else None
            ),
        ),
        ca_trust=CATrustSpec(bundle_path=ca_bundle) if ca_bundle else CATrustSpec(),
        revocation=revocation,
        metadata={
            "generated_by": f"sssd-smartcard {__version__}",
            "generated_at": _dt.datetime.now(_dt.timezone.utc)
            .replace(microsecond=0)
            .isoformat(),
            "source_certificate": cert.source,
            "certificate_sha256": cert.fingerprint("sha256"),
            "certificate_subject": cert.subject_dn,
            "expected_identity": candidate.identity if candidate else None,
            "account_domain": account_domain,
            "target_sssd_version": str(recommendation.version),
        },
    )
    return profile
