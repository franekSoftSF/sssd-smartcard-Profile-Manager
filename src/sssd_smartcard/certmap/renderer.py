"""Render a profile into concrete ``sssd.conf`` settings.

The version compatibility layer lives here::

    Version -> get_renderer() -> CertMapRenderer
                                    |
                                    +-- SSSD2xRenderer   (2.0 .. present)
                                    +-- future renderers

A renderer only ever emits options this project has seen documented, and it
refuses -- rather than silently degrades -- when a profile asks for something
the target version does not have.  ``allow_degraded=True`` turns the refusal
into a warning and drops the option.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..errors import UnsupportedFeature
from ..model.profile import DEFAULT_CA_DB, SmartCardProfile
from ..platform import DistroInfo, detect_distro
from .compat import DEFAULT_VERSION, Version, feature
from .mappings import BuiltRule, build_rule

#: Where a ``certificate_verification`` value should be written.
VERIFICATION_SCOPES = ("sssd", "pam")


@dataclass
class ConfigChange:
    """One ``section`` / ``key = value`` setting the profile needs."""

    section: str
    key: str
    value: str
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "section": self.section,
            "key": self.key,
            "value": self.value,
            "reason": self.reason,
        }


@dataclass
class ManualStep:
    """Something the operator must do outside sssd.conf."""

    title: str
    command: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        return {"title": self.title, "command": self.command, "detail": self.detail}


@dataclass
class RenderedConfig:
    """Everything a profile turns into."""

    profile: SmartCardProfile
    rule: BuiltRule
    version: Version
    distro: DistroInfo = field(default_factory=DistroInfo)
    changes: list[ConfigChange] = field(default_factory=list)
    manual_steps: list[ManualStep] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def sections(self) -> list[str]:
        out: list[str] = []
        for change in self.changes:
            if change.section not in out:
                out.append(change.section)
        return out

    def section_items(self, section: str) -> list[ConfigChange]:
        return [c for c in self.changes if c.section == section]

    def to_ini(self, *, with_comments: bool = True) -> str:
        """The configuration fragment, ready to paste into sssd.conf."""
        lines: list[str] = []
        for section in self.sections:
            lines.append(f"[{section}]")
            for change in self.section_items(section):
                if with_comments and change.reason:
                    lines.append(f"# {change.reason}")
                lines.append(f"{change.key} = {change.value}")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def to_dict(self) -> dict:
        return {
            "profile": self.profile.name,
            "domain": self.profile.domain,
            "target_sssd_version": str(self.version),
            "distro": self.distro.to_dict(),
            "certmap_section": self.profile.section,
            "matchrule": self.rule.matchrule.render() or None,
            "maprule": self.rule.maprule.render(),
            "domains": self.rule.domains,
            "priority": self.rule.priority,
            "changes": [c.to_dict() for c in self.changes],
            "manual_steps": [s.to_dict() for s in self.manual_steps],
            "notes": self.notes,
            "warnings": self.warnings,
        }


class CertMapRenderer:
    """Base class of the version compatibility layer."""

    name = "base"
    min_version: Version | None = None
    max_version: Version | None = None

    def handles(self, version: Version) -> bool:
        if self.min_version and version < self.min_version:
            return False
        if self.max_version and version > self.max_version:
            return False
        return True

    def render(
        self,
        profile: SmartCardProfile,
        *,
        version: Version = DEFAULT_VERSION,
        verification_scope: str = "sssd",
        allow_degraded: bool = False,
        distro: DistroInfo | None = None,
    ) -> RenderedConfig:  # pragma: no cover - abstract
        raise NotImplementedError


class SSSD2xRenderer(CertMapRenderer):
    """Renderer for the SSSD 2.x series.

    Every option written here is documented in ``sssd.conf(5)`` or
    ``sss-certmap(5)``; nothing is invented.
    """

    name = "sssd-2.x"
    min_version = Version.parse("2.0.0")

    def render(
        self,
        profile: SmartCardProfile,
        *,
        version: Version = DEFAULT_VERSION,
        verification_scope: str = "sssd",
        allow_degraded: bool = False,
        distro: DistroInfo | None = None,
    ) -> RenderedConfig:
        if verification_scope not in VERIFICATION_SCOPES:
            raise ValueError(
                f"verification_scope must be one of {', '.join(VERIFICATION_SCOPES)}"
            )
        distro = distro if distro is not None else detect_distro()
        rule = build_rule(profile, version=version)
        out = RenderedConfig(profile=profile, rule=rule, version=version, distro=distro)
        out.notes.extend(rule.notes)
        out.warnings.extend(rule.warnings)

        self._require(rule.requires, version, out, allow_degraded)
        self._certmap_section(profile, rule, out)
        self._pam_section(profile, out, version, allow_degraded)
        self._verification(profile, out, version, verification_scope, allow_degraded)
        self._local_auth_policy(profile, out, version, allow_degraded)
        self._domain_section(profile, out)
        self._manual_steps(profile, out, distro)
        return out

    # -- pieces ----------------------------------------------------------
    def _require(self, keys, version, out, allow_degraded) -> None:
        for key in keys:
            feat = feature(key)
            if feat.available_in(version):
                continue
            message = (
                f"{feat.description} requires SSSD {feat.since} or newer, "
                f"target is {version} (source: {feat.source})"
            )
            if allow_degraded:
                out.warnings.append(message)
            else:
                raise UnsupportedFeature(message)

    def _certmap_section(self, profile: SmartCardProfile, rule: BuiltRule, out) -> None:
        section = profile.section
        matchrule = rule.matchrule.render()
        if matchrule:
            out.changes.append(
                ConfigChange(
                    section,
                    "matchrule",
                    matchrule,
                    "which certificates this rule accepts",
                )
            )
        else:
            out.notes.append(
                "No matchrule is emitted, so SSSD falls back to its default "
                "KRB5:<EKU>clientAuth. Pin certificate.issuer to narrow that down."
            )
        out.changes.append(
            ConfigChange(
                section,
                "maprule",
                rule.maprule.render(),
                "how a matching certificate is turned into a user search",
            )
        )
        domains = rule.domains
        if domains and domains != [profile.domain]:
            out.changes.append(
                ConfigChange(
                    section,
                    "domains",
                    ",".join(domains),
                    "search these domains, including trusted ones",
                )
            )
        elif domains == [profile.domain]:
            out.notes.append(
                f"domains= is omitted: SSSD defaults to the rule's own domain "
                f"({profile.domain}). Set mapping.domains explicitly when the user "
                "accounts live in a trusted domain."
            )
        if rule.priority is not None:
            out.changes.append(
                ConfigChange(
                    section,
                    "priority",
                    str(rule.priority),
                    "lower number wins; 0 is the highest priority",
                )
            )

    def _pam_section(self, profile, out, version, allow_degraded) -> None:
        auth = profile.authentication
        out.changes.append(
            ConfigChange(
                "pam",
                "pam_cert_auth",
                "True",
                "enable certificate based Smart Card authentication",
            )
        )
        bundle = profile.ca_trust.bundle_path
        if bundle and bundle != DEFAULT_CA_DB:
            out.changes.append(
                ConfigChange(
                    "pam",
                    "pam_cert_db_path",
                    bundle,
                    f"CA trust bundle (default is {DEFAULT_CA_DB})",
                )
            )
        if auth.p11_uri:
            feat = feature("pam.p11_uri")
            if feat.available_in(version):
                out.changes.append(
                    ConfigChange(
                        "pam",
                        "p11_uri",
                        auth.p11_uri,
                        "restrict which PKCS#11 device may be used (RFC 7512 URI)",
                    )
                )
            elif allow_degraded:
                out.warnings.append(
                    f"p11_uri dropped: requires SSSD {feat.since}, target is {version}"
                )
            else:
                raise UnsupportedFeature(
                    f"p11_uri requires SSSD {feat.since} or newer, target is {version}"
                )
        if auth.p11_child_timeout is not None:
            out.changes.append(
                ConfigChange(
                    "pam",
                    "p11_child_timeout",
                    str(auth.p11_child_timeout),
                    "seconds pam_sss waits for p11_child (default 10)",
                )
            )
        if auth.allowed_services:
            out.changes.append(
                ConfigChange(
                    "pam",
                    "pam_p11_allowed_services",
                    ", ".join(auth.allowed_services),
                    "PAM services allowed to use Smart Cards",
                )
            )
            out.warnings.append(
                "pam_p11_allowed_services replaces the built-in list rather than "
                "adding to it; include every service you still need (login, su, "
                "gdm-smartcard, sudo, ...). Prefix an entry with '+' to extend the "
                "default list if your SSSD supports it."
            )

    def _verification(self, profile, out, version, scope, allow_degraded) -> None:
        values, notes, warnings = self.verification_values(
            profile, version, allow_degraded
        )
        out.notes.extend(notes)
        out.warnings.extend(warnings)
        if not values:
            return
        if scope == "pam":
            out.changes.append(
                ConfigChange(
                    "pam",
                    "pam_cert_verification",
                    ", ".join(values),
                    "certificate verification, scoped to PAM only",
                )
            )
        else:
            out.changes.append(
                ConfigChange(
                    "sssd",
                    "certificate_verification",
                    ", ".join(values),
                    "certificate verification for the whole of SSSD",
                )
            )

    def verification_values(
        self, profile: SmartCardProfile, version: Version, allow_degraded: bool
    ) -> tuple[list[str], list[str], list[str]]:
        """Translate validation + revocation intent into documented tokens."""
        values: list[str] = []
        notes: list[str] = []
        warnings: list[str] = []
        revocation = profile.revocation
        validation = profile.validation

        def gate(key: str, token: str) -> bool:
            feat = feature(key)
            if feat.available_in(version):
                return True
            message = (
                f"certificate_verification={token} requires SSSD {feat.since} or newer, "
                f"target is {version}"
            )
            if allow_degraded:
                warnings.append(message + " -- dropped")
                return False
            raise UnsupportedFeature(message)

        if not validation.check_chain:
            warnings.append(
                "validation.check_chain is false, which renders "
                "certificate_verification=no_verification. Any certificate the card "
                "presents will be accepted. Use this for troubleshooting only."
            )
            return ["no_verification"], notes, warnings

        if validation.partial_chain:
            if gate("verify.partial_chain", "partial_chain"):
                values.append("partial_chain")

        if not revocation.enabled or revocation.method == "none":
            if gate("verify.no_ocsp", "no_ocsp"):
                values.append("no_ocsp")
            notes.append(
                "Revocation checking is off (no_ocsp). SSSD attempts OCSP by default "
                "when a certificate advertises a responder, so this is an explicit "
                "opt-out, not a no-op."
            )
            return values, notes, warnings

        wants_ocsp = revocation.method in ("ocsp", "ocsp+crl")
        wants_crl = revocation.method in ("crl", "ocsp+crl")

        if wants_ocsp:
            if revocation.fail_mode == "open":
                if gate("verify.soft_ocsp", "soft_ocsp"):
                    values.append("soft_ocsp")
                warnings.append(
                    "revocation.fail_mode is 'open' (soft_ocsp): a user still logs in "
                    "when the responder is unreachable."
                )
            if revocation.ocsp_digest:
                if gate("verify.ocsp_dgst", f"ocsp_dgst={revocation.ocsp_digest}"):
                    values.append(f"ocsp_dgst={revocation.ocsp_digest}")
            if revocation.ocsp_responder:
                values.append(f"ocsp_default_responder={revocation.ocsp_responder}")
                warnings.append(
                    "sssd.conf(5) states ocsp_default_responder is currently ignored, and "
                    "that every needed certificate must be present in the PEM file given "
                    "by pam_cert_db_path. Do not rely on it."
                )
            notes.append(
                "OCSP is SSSD's default behaviour; the profile simply refrains from "
                "disabling it and adds the tuning options above."
            )
        else:
            if gate("verify.no_ocsp", "no_ocsp"):
                values.append("no_ocsp")

        if wants_crl:
            if not revocation.crl_file:
                warnings.append(
                    "revocation.method requests CRL checking but no crl_file is set."
                )
            elif gate("verify.crl_file", "crl_file"):
                values.append(f"crl_file={revocation.crl_file}")
                notes.append(
                    "SSSD reads the CRL from this local PEM file. It does not download "
                    "CRL distribution points, so schedule a job to refresh the file: "
                    "'sssd-smartcard ca crl update' installs the systemd timer."
                )
                # Measured on SSSD 2.9.4: crl_file puts OpenSSL into
                # X509_V_FLAG_CRL_CHECK_ALL, so a CRL is required for EVERY CA
                # in the chain.  One CRL short and verification fails with
                # "unable to get certificate CRL" for every card -- a lockout,
                # because crl_file fails closed.
                warnings.append(
                    "crl_file needs a current CRL for EVERY CA in the chain, not just "
                    "the one that issued the card's certificate. Measured: with any "
                    "CA's CRL missing, verification fails with 'unable to get "
                    "certificate CRL' and no card works at all. Concatenate one CRL "
                    "per CA into this one PEM file -- 'sssd-smartcard ca crl update' "
                    "does that and refuses to install an incomplete set."
                )
            if revocation.fail_mode == "open":
                if gate("verify.soft_crl", "soft_crl"):
                    values.append("soft_crl")
                warnings.append(
                    "soft_crl lets an expired CRL still be used; intended for offline "
                    "hosts. Measured: it forgives an expired CRL but never a missing "
                    "one, so it is no safety net against an incomplete CRL set."
                )

        # partial_chain and crl_file do not work together.  Measured: a
        # complete, valid CRL set that verifies cleanly on its own starts
        # failing with "unable to get certificate CRL" as soon as
        # partial_chain is added.  Emitting both would hand over a host where
        # no card authenticates.
        if wants_crl and revocation.crl_file and "partial_chain" in values:
            values.remove("partial_chain")
            warnings.append(
                "partial_chain was dropped: combined with crl_file it breaks "
                "verification outright. Measured on SSSD 2.9.4 -- a complete CRL set "
                "that passes on its own fails with 'unable to get certificate CRL' "
                "once partial_chain is set. Choose one: CRL checking, or "
                "partial_chain for an incomplete trust chain."
            )

        if revocation.method == "ocsp+crl":
            notes.append(
                "Mixed OCSP and CRL: note that enabling OCSP does NOT relax the CRL "
                "requirement. Measured -- with crl_file set, every CA in the chain "
                "still needs its own CRL even with ocsp_dgst or soft_ocsp present. So "
                "'OCSP at the issuing CA, CRL only at the root' cannot be expressed "
                "this way; either supply every CA's CRL, or use OCSP alone and leave "
                "crl_file unset."
            )
        return values, notes, warnings

    def _local_auth_policy(self, profile, out, version, allow_degraded) -> None:
        """Write ``local_auth_policy`` into the domain section.

        This is the option that decides whether a working card produces a PIN
        prompt or a password prompt.  ``local_auth_policy`` defaults to
        ``match``, which means "offer what the backend offers"; the AD and LDAP
        backends have no Smart Card authentication of their own, so SSSD reads
        the card, verifies the certificate against the trust bundle, maps it to
        a real user -- and then declines, logging

            [pam_reply] Local auth policy allowed: smartcard [False]

        and pam_sss falls through to the password prompt.  Nothing in
        ``sssctl cert-map``, ``cert-eval-rule`` or the certmap rule shows the
        problem, which is why the tool now always states the policy it expects.
        """
        auth = profile.authentication
        policy = auth.policy_for(profile.provider)
        if policy is None:
            if profile.provider in ("ad", "ldap"):
                out.warnings.append(
                    "local_auth_policy is left at its default 'match'. With the "
                    f"{profile.provider} provider that means local Smart Card "
                    "authentication stays off: SSSD will read and verify the card "
                    "and still ask for a password. Set "
                    "authentication.local_smartcard: true to enable it."
                )
            return

        feat = feature(
            "auth.local_smartcard"
            if auth.policy_enables_smartcard(policy)
            else "auth.local_auth_policy"
        )
        if not feat.available_in(version):
            message = (
                f"{feat.description} requires SSSD {feat.since} or newer, target "
                f"is {version} (source: {feat.source}). Without it the AD and LDAP "
                "providers cannot authenticate a Smart Card locally; the card can "
                "only be used through Kerberos PKINIT."
            )
            # Refuse only what the operator explicitly asked for.  When the
            # value came from the provider default, dropping it with a warning
            # is better than refusing to render anything at all.
            explicit = (
                auth.local_auth_policy is not None or auth.local_smartcard is not None
            )
            if explicit and not allow_degraded:
                raise UnsupportedFeature(message)
            out.warnings.append(message + " -- not written")
            return

        out.changes.append(
            ConfigChange(
                f"domain/{profile.domain}",
                "local_auth_policy",
                policy,
                "let SSSD check the Smart Card locally (default 'match' does not)",
            )
        )
        if auth.policy_enables_smartcard(policy):
            out.notes.append(
                "local_auth_policy = enable:smartcard makes the Smart Card the "
                "preferred method whenever a card is present, so the user is asked "
                "for a PIN instead of a password (sssd.conf(5)). It authenticates "
                "locally, which means no Kerberos TGT: use 'sssd-smartcard krb5 "
                "test --pkinit' to check the separate PKINIT path if you need one."
            )

    def _domain_section(self, profile: SmartCardProfile, out) -> None:
        section = f"domain/{profile.domain}"
        if profile.mapping.type in ("certificate-binary", "cert-binary") and (
            profile.provider == "ad"
        ):
            out.changes.append(
                ConfigChange(
                    section,
                    "ldap_user_certificate",
                    "userCertificate;binary",
                    "the AD provider does not read certificates unless told to",
                )
            )

        gpo = profile.gpo
        if not gpo.manage:
            if profile.provider == "ad":
                out.notes.append(
                    "GPO access control is left alone. Note that sssd-ad(5) documents "
                    "ad_gpo_access_control as defaulting to 'enforcing', so a freshly "
                    "joined host already denies login to anyone the domain's GPOs do not "
                    "grant InteractiveLogonRight. Set gpo.manage to take control of it."
                )
            return

        out.changes.append(
            ConfigChange(
                section,
                "ad_gpo_access_control",
                gpo.access_control,
                "how SSSD treats the Windows logon rights from GPO",
            )
        )
        if gpo.access_control == "enforcing":
            out.warnings.append(
                "ad_gpo_access_control = enforcing denies login to any user the domain's "
                "GPOs do not explicitly grant InteractiveLogonRight. Run permissive "
                "first, read the syslog messages, and only then switch."
            )
        if gpo.implicit_deny is not None:
            out.changes.append(
                ConfigChange(
                    section,
                    "ad_gpo_implicit_deny",
                    "True" if gpo.implicit_deny else "False",
                    "True requires an explicit GPO grant (default False)",
                )
            )
            if gpo.implicit_deny:
                out.warnings.append(
                    "ad_gpo_implicit_deny = True means a host with no applicable GPO "
                    "denies everyone. Confirm a working login before enabling it."
                )
        if gpo.ignore_unreadable is not None:
            out.changes.append(
                ConfigChange(
                    section,
                    "ad_gpo_ignore_unreadable",
                    "True" if gpo.ignore_unreadable else "False",
                    "skip GPOs whose files cannot be read (default False)",
                )
            )
        if gpo.map_interactive:
            out.changes.append(
                ConfigChange(
                    section,
                    "ad_gpo_map_interactive",
                    ", ".join(gpo.map_interactive),
                    "adjust the PAM services mapped onto InteractiveLogonRight",
                )
            )
            out.notes.append(
                "ad_gpo_map_interactive uses +service to add and -service to remove, so "
                "the documented default set (login, su, su-l, gdm-fingerprint, "
                "gdm-password, gdm-smartcard, kdm, lightdm, lxdm, plasmalogin, sddm, "
                "unity, xdm) is kept and only adjusted."
            )

    def _manual_steps(self, profile: SmartCardProfile, out, distro) -> None:
        required = profile.authentication.smartcard_required
        plan = distro.pam_plan()
        lockout_warning = (
            "sssd.conf has no 'Smart Card only' switch -- enforcement lives in the PAM "
            "stack via pam_sss.so require_cert_auth. Confirm a working card login in a "
            "second session BEFORE enabling this, or you can lock yourself out."
        )

        if plan.kind == "manual":
            line = plan.manual_lines.get("required" if required else "optional", "")
            out.manual_steps.append(
                ManualStep(
                    "Add pam_sss to the PAM stack by hand"
                    + (" (Smart Card only)" if required else " (Smart Card optional)"),
                    "",
                    f"{plan.detail}\nLine to add to /etc/pam.d/common-auth:\n    {line}"
                    + (f"\n{lockout_warning}" if required else ""),
                )
            )
        elif plan.kind == "unknown":
            out.manual_steps.append(
                ManualStep(
                    "Enable Smart Card authentication in the PAM stack",
                    "",
                    plan.detail
                    + "\n  RHEL family:  authselect enable-feature with-smartcard"
                    + (
                        "-required" if required else ""
                    )
                    + "\n  Ubuntu 23.10+: pam-auth-update --enable sss-smart-card-"
                    + ("required" if required else "optional")
                    + ("\n" + lockout_warning if required else ""),
                )
            )
        else:
            commands = plan.commands(require_smartcard=required)
            out.manual_steps.append(
                ManualStep(
                    "Enforce Smart Card only login"
                    if required
                    else "Enable Smart Card support in the PAM stack",
                    " && ".join(commands),
                    (lockout_warning if required else
                     "Smart Card stays optional: password login keeps working.")
                    + f"\n{plan.detail}",
                )
            )

        if profile.gpo.adsys:
            if distro.supports_adsys:
                out.manual_steps.append(
                    ManualStep(
                        "Install and refresh the Ubuntu Group Policy client",
                        "apt-get install -y adsys && adsysctl update -m",
                        "adsys applies real Group Policy on Ubuntu. Managing desktop "
                        "settings with dconf is available to everyone; the other "
                        "features need an Ubuntu Pro subscription, which is free for up "
                        "to five machines. This is separate from ad_gpo_access_control, "
                        "which is SSSD's own logon-rights check.",
                    )
                )
            else:
                out.warnings.append(
                    f"gpo.adsys is set but adsys is packaged by Canonical for Ubuntu "
                    f"only; this host is {distro.pretty_name or distro.id or 'not Ubuntu'}. "
                    "On the RHEL family, GPO support means ad_gpo_access_control, which "
                    "this profile already configures."
                )

        if profile.gpo.cert_autoenroll and distro.supports_adsys:
            out.manual_steps.append(
                ManualStep(
                    "Enable certificate auto-enrolment from AD CS",
                    "apt-get install -y certmonger cepces",
                    "adsys drives auto-enrolment through certmonger and cepces. Turn it "
                    "on in the GPO under Computer Configuration > Policies > Windows "
                    "Settings > Security Settings > Public Key Policies > Certificate "
                    "Services Client - Auto-Enrollment: set the Configuration Model to "
                    "Enabled. Debug with: adsysctl policy debug cert-autoenroll-script",
                )
            )

        if profile.ca_trust.sources:
            out.manual_steps.append(
                ManualStep(
                    "Build the CA trust bundle",
                    "sssd-smartcard ca import "
                    + " ".join(profile.ca_trust.sources)
                    + f" --bundle {profile.ca_trust.bundle_path}",
                    "SSSD verifies card certificates against this PEM bundle only.",
                )
            )


RENDERERS: list[CertMapRenderer] = [SSSD2xRenderer()]


def get_renderer(version: Version = DEFAULT_VERSION) -> CertMapRenderer:
    """Pick the renderer that handles *version*."""
    for renderer in RENDERERS:
        if renderer.handles(version):
            return renderer
    raise UnsupportedFeature(
        f"no certmap renderer covers SSSD {version}; this build supports "
        + ", ".join(
            f"{r.name} (>= {r.min_version})" for r in RENDERERS if r.min_version
        )
    )


def render(
    profile: SmartCardProfile,
    *,
    version: Version = DEFAULT_VERSION,
    verification_scope: str = "sssd",
    allow_degraded: bool = False,
    distro: DistroInfo | None = None,
) -> RenderedConfig:
    """Convenience wrapper around :func:`get_renderer`."""
    return get_renderer(version).render(
        profile,
        version=version,
        verification_scope=verification_scope,
        allow_degraded=allow_degraded,
        distro=distro,
    )
