"""The ``SmartCardProfile`` data model.

The model is intentionally open-ended: a mapping mechanism is identified by a
string key and carries a free-form ``options`` dictionary that only the
mechanism itself interprets.  Adding a new way to map a certificate to a user
therefore means registering a class in
:mod:`sssd_smartcard.certmap.mappings` -- no change here.

Anything the model does not understand is reported as an error with the list of
accepted keys, so a typo never silently produces a half-configured host.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Any

from ..errors import ProfileError

API_VERSION = "sssd-smartcard/v1"

PROVIDERS = ("ad", "ldap", "ipa")
AUTH_MODES = ("optional", "required")
REVOCATION_METHODS = ("none", "crl", "ocsp", "ocsp+crl")

#: Methods ``local_auth_policy`` knows, sssd.conf(5) -> local_auth_policy.
LOCAL_AUTH_METHODS = ("password", "otp", "passkey", "smartcard")
#: Providers that need local Smart Card authentication switched on explicitly.
#: The default policy ``match`` lets the backend decide, and the AD and LDAP
#: backends do not offer Smart Card authentication of their own, so the card is
#: read, verified, mapped -- and then refused.
LOCAL_SMARTCARD_PROVIDERS = ("ad", "ldap")
FAIL_MODES = ("closed", "open")
OCSP_DIGESTS = ("sha1", "sha256", "sha384", "sha512")

#: Documented default, ``sssd.conf(5)`` -> pam_cert_db_path.
DEFAULT_CA_DB = "/etc/sssd/pki/sssd_auth_ca_db.pem"


def _reject_unknown(data: dict, cls, where: str) -> None:
    known = {f.name for f in fields(cls)}
    unknown = sorted(set(data) - known)
    if unknown:
        raise ProfileError(
            f"{where}: unknown key(s) {', '.join(unknown)}; "
            f"accepted keys are {', '.join(sorted(known))}"
        )


def _as_list(value: Any, where: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    raise ProfileError(f"{where}: expected a string or a list of strings")


def _as_bool(value: Any, where: str, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "yes", "1", "on"):
        return True
    if isinstance(value, str) and value.strip().lower() in ("false", "no", "0", "off"):
        return False
    raise ProfileError(f"{where}: expected a boolean, got {value!r}")


def _local_auth_policy(value: Any) -> str | None:
    """Validate a verbatim ``local_auth_policy`` value.

    sssd.conf(5) documents ``match`` (the default), ``only`` and
    ``enable:<method>``; the upstream design page adds ``disable:<method>``.
    Values are comma separated.  Anything else is refused rather than written
    out, because an unparsable policy stops SSSD from starting the responder.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    tokens = [t.strip() for t in text.split(",") if t.strip()]
    for token in tokens:
        lowered = token.lower()
        if lowered in ("match", "only"):
            continue
        if ":" in lowered:
            verb, _, method = lowered.partition(":")
            if verb in ("enable", "disable") and method in LOCAL_AUTH_METHODS:
                continue
        raise ProfileError(
            f"authentication.local_auth_policy: {token!r} is not a documented "
            "value; use match, only, enable:<method> or disable:<method> with "
            f"<method> one of {', '.join(LOCAL_AUTH_METHODS)}"
        )
    return ", ".join(tokens)


def _one_of(value: Any, choices: tuple[str, ...], where: str, default: str) -> str:
    if value is None:
        return default
    text = str(value).strip().lower()
    if text not in choices:
        raise ProfileError(f"{where}: expected one of {', '.join(choices)}, got {value!r}")
    return text


@dataclass
class CertificateConstraints:
    """Which certificates a rule should accept.

    ``issuer``/``subject`` are literal DNs, escaped and anchored when rendered.
    ``issuer_regex``/``subject_regex`` are passed through verbatim for people
    who need a real regular expression.
    """

    issuer: str | None = None
    subject: str | None = None
    issuer_regex: str | None = None
    subject_regex: str | None = None
    eku: list[str] = field(default_factory=list)
    key_usage: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict | None) -> "CertificateConstraints":
        data = data or {}
        _reject_unknown(data, cls, "certificate")
        obj = cls(
            issuer=data.get("issuer"),
            subject=data.get("subject"),
            issuer_regex=data.get("issuer_regex"),
            subject_regex=data.get("subject_regex"),
            eku=_as_list(data.get("eku"), "certificate.eku"),
            key_usage=_as_list(data.get("key_usage"), "certificate.key_usage"),
        )
        if obj.issuer and obj.issuer_regex:
            raise ProfileError("certificate: set either issuer or issuer_regex, not both")
        if obj.subject and obj.subject_regex:
            raise ProfileError("certificate: set either subject or subject_regex, not both")
        return obj

    def to_dict(self) -> dict:
        out: dict[str, Any] = {}
        for key in ("issuer", "subject", "issuer_regex", "subject_regex"):
            value = getattr(self, key)
            if value:
                out[key] = value
        if self.eku:
            out["eku"] = list(self.eku)
        if self.key_usage:
            out["key_usage"] = list(self.key_usage)
        return out


@dataclass
class MappingSpec:
    """How a matching certificate is turned into a user search."""

    type: str = "san-upn"
    options: dict = field(default_factory=dict)
    domains: list[str] = field(default_factory=list)
    priority: int | None = None
    matchrule: str | None = None
    maprule: str | None = None

    @classmethod
    def from_dict(cls, data: dict | None) -> "MappingSpec":
        data = dict(data or {})
        # The example profile in the design brief nests mechanism settings under
        # their own key (``san: {type: ntPrincipalName}``).  Accept that shape by
        # folding anything that is not a known field into ``options``.
        known = {f.name for f in fields(cls)}
        options = dict(data.pop("options", {}) or {})
        for key in list(data):
            if key not in known:
                options[key] = data.pop(key)
        priority = data.get("priority")
        if priority is not None:
            try:
                priority = int(priority)
            except (TypeError, ValueError):
                raise ProfileError("mapping.priority: expected an integer") from None
            if priority < 0:
                raise ProfileError("mapping.priority: must be >= 0 (0 is the highest)")
        return cls(
            type=str(data.get("type") or "san-upn").strip().lower(),
            options=options,
            domains=_as_list(data.get("domains"), "mapping.domains"),
            priority=priority,
            matchrule=data.get("matchrule"),
            maprule=data.get("maprule"),
        )

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"type": self.type}
        if self.options:
            out["options"] = dict(self.options)
        if self.domains:
            out["domains"] = list(self.domains)
        if self.priority is not None:
            out["priority"] = self.priority
        if self.matchrule:
            out["matchrule"] = self.matchrule
        if self.maprule:
            out["maprule"] = self.maprule
        return out


@dataclass
class ValidationSpec:
    """Which checks the tool performs, and which it asks SSSD to perform."""

    check_issuer: bool = True
    check_eku: bool = True
    check_expiration: bool = True
    check_revocation: bool = False
    check_chain: bool = True
    partial_chain: bool = False

    @classmethod
    def from_dict(cls, data: dict | None) -> "ValidationSpec":
        data = data or {}
        _reject_unknown(data, cls, "validation")
        return cls(
            check_issuer=_as_bool(data.get("check_issuer"), "validation.check_issuer", True),
            check_eku=_as_bool(data.get("check_eku"), "validation.check_eku", True),
            check_expiration=_as_bool(
                data.get("check_expiration"), "validation.check_expiration", True
            ),
            check_revocation=_as_bool(
                data.get("check_revocation"), "validation.check_revocation", False
            ),
            check_chain=_as_bool(data.get("check_chain"), "validation.check_chain", True),
            partial_chain=_as_bool(
                data.get("partial_chain"), "validation.partial_chain", False
            ),
        )

    def to_dict(self) -> dict:
        return {f.name: getattr(self, f.name) for f in fields(self)}


@dataclass
class AuthenticationSpec:
    """Login-mode settings that land in the ``[pam]`` section."""

    mode: str = "optional"
    allowed_services: list[str] = field(default_factory=list)
    p11_uri: str | None = None
    p11_child_timeout: int | None = None
    #: Whether SSSD may authenticate the Smart Card locally.  ``None`` means
    #: "decide from the provider" -- see :meth:`policy_for`.  This is the
    #: difference between a PIN prompt and a password prompt: with the default
    #: policy the PAM responder reads the card, verifies the certificate, maps
    #: it to a user and then logs
    #: ``Local auth policy allowed: smartcard [False]`` and falls back.
    local_smartcard: bool | None = None
    #: Verbatim ``local_auth_policy`` value, for combining methods
    #: (``enable:smartcard, enable:passkey``) or for ``only``.
    local_auth_policy: str | None = None

    @property
    def smartcard_required(self) -> bool:
        return self.mode == "required"

    def policy_for(self, provider: str) -> str | None:
        """The ``local_auth_policy`` value to write, or None to leave it alone."""
        if self.local_auth_policy:
            return self.local_auth_policy
        enabled = (
            self.local_smartcard
            if self.local_smartcard is not None
            else provider in LOCAL_SMARTCARD_PROVIDERS
        )
        return "enable:smartcard" if enabled else None

    @staticmethod
    def policy_enables_smartcard(value: str | None) -> bool:
        """Does *value* let SSSD check a Smart Card locally?

        ``only`` on its own means "local methods only" and, per sssd.conf(5),
        still has to name them, so it alone is not enough.
        """
        if not value:
            return False
        tokens = [t.strip().lower() for t in value.split(",") if t.strip()]
        if "disable:smartcard" in tokens:
            return False
        return "enable:smartcard" in tokens

    @classmethod
    def from_dict(cls, data: dict | None) -> "AuthenticationSpec":
        data = dict(data or {})
        # ``smartcard_required: true`` from the design brief is a shorthand.
        required = data.pop("smartcard_required", None)
        mode = data.pop("mode", None)
        if mode is None and required is not None:
            mode = "required" if _as_bool(required, "authentication.smartcard_required") else "optional"
        known = {
            "allowed_services",
            "p11_uri",
            "p11_child_timeout",
            "local_smartcard",
            "local_auth_policy",
        }
        unknown = sorted(set(data) - known)
        if unknown:
            raise ProfileError(
                f"authentication: unknown key(s) {', '.join(unknown)}; accepted keys are "
                "mode, smartcard_required, allowed_services, p11_uri, "
                "p11_child_timeout, local_smartcard, local_auth_policy"
            )
        timeout = data.get("p11_child_timeout")
        if timeout is not None:
            try:
                timeout = int(timeout)
            except (TypeError, ValueError):
                raise ProfileError(
                    "authentication.p11_child_timeout: expected an integer"
                ) from None
        return cls(
            mode=_one_of(mode, AUTH_MODES, "authentication.mode", "optional"),
            allowed_services=_as_list(
                data.get("allowed_services"), "authentication.allowed_services"
            ),
            p11_uri=data.get("p11_uri"),
            p11_child_timeout=timeout,
            local_smartcard=(
                None
                if data.get("local_smartcard") is None
                else _as_bool(
                    data.get("local_smartcard"), "authentication.local_smartcard"
                )
            ),
            local_auth_policy=_local_auth_policy(data.get("local_auth_policy")),
        )

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"mode": self.mode}
        if self.allowed_services:
            out["allowed_services"] = list(self.allowed_services)
        if self.p11_uri:
            out["p11_uri"] = self.p11_uri
        if self.p11_child_timeout is not None:
            out["p11_child_timeout"] = self.p11_child_timeout
        if self.local_smartcard is not None:
            out["local_smartcard"] = self.local_smartcard
        if self.local_auth_policy:
            out["local_auth_policy"] = self.local_auth_policy
        return out


@dataclass
class CATrustSpec:
    """Where the CA trust bundle SSSD verifies against lives."""

    bundle_path: str = DEFAULT_CA_DB
    sources: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict | None) -> "CATrustSpec":
        data = data or {}
        _reject_unknown(data, cls, "ca_trust")
        return cls(
            bundle_path=str(data.get("bundle_path") or DEFAULT_CA_DB),
            sources=_as_list(data.get("sources"), "ca_trust.sources"),
        )

    def to_dict(self) -> dict:
        out = {"bundle_path": self.bundle_path}
        if self.sources:
            out["sources"] = list(self.sources)
        return out


@dataclass
class RevocationSpec:
    """Revocation intent, translated into ``certificate_verification`` values."""

    enabled: bool = False
    method: str = "none"
    fail_mode: str = "closed"
    crl_file: str | None = None
    ocsp_responder: str | None = None
    ocsp_digest: str | None = None

    @classmethod
    def from_dict(cls, data: dict | None) -> "RevocationSpec":
        data = data or {}
        _reject_unknown(data, cls, "revocation")
        enabled = _as_bool(data.get("enabled"), "revocation.enabled", False)
        method = _one_of(
            data.get("method"), REVOCATION_METHODS, "revocation.method",
            "ocsp" if enabled else "none",
        )
        digest = data.get("ocsp_digest")
        if digest is not None:
            digest = _one_of(digest, OCSP_DIGESTS, "revocation.ocsp_digest", "sha256")
        obj = cls(
            enabled=enabled,
            method=method,
            fail_mode=_one_of(
                data.get("fail_mode"), FAIL_MODES, "revocation.fail_mode", "closed"
            ),
            crl_file=data.get("crl_file"),
            ocsp_responder=data.get("ocsp_responder"),
            ocsp_digest=digest,
        )
        if obj.enabled and obj.method == "none":
            raise ProfileError(
                "revocation: enabled is true but method is none; pick crl, ocsp or ocsp+crl"
            )
        if obj.method in ("crl", "ocsp+crl") and obj.enabled and not obj.crl_file:
            raise ProfileError(
                "revocation: method crl requires crl_file (SSSD reads a PEM CRL from disk, "
                "it does not download CRL distribution points itself)"
            )
        return obj

    def to_dict(self) -> dict:
        out: dict[str, Any] = {
            "enabled": self.enabled,
            "method": self.method,
            "fail_mode": self.fail_mode,
        }
        for key in ("crl_file", "ocsp_responder", "ocsp_digest"):
            value = getattr(self, key)
            if value:
                out[key] = value
        return out


GPO_ACCESS_CONTROL = ("enforcing", "permissive", "disabled")


@dataclass
class GpoSpec:
    """Group Policy settings, which live in the domain section.

    Two unrelated things are called "GPO support" on Linux and the profile keeps
    them apart:

    * ``access_control`` is SSSD's own evaluation of the Windows logon rights
      (``ad_gpo_access_control`` in ``sssd-ad(5)``). It needs no extra package.
    * ``adsys`` is Canonical's Group Policy client for Ubuntu, which applies
      actual policy (dconf, privileges, scripts, certificate auto-enrolment).
      It is a separate package and this profile only records the intent; the
      setup script installs and configures it.

    NOTE: ``ad_gpo_access_control`` defaults to ``enforcing`` in current
    ``sssd-ad(5)``. On a freshly joined host that is enough to lock every user
    out if the domain's GPOs do not grant InteractiveLogonRight, so
    ``permissive`` is the safe first move.
    """

    manage: bool = False
    access_control: str = "permissive"
    implicit_deny: bool | None = None
    ignore_unreadable: bool | None = None
    map_interactive_add: list[str] = field(default_factory=list)
    map_interactive_remove: list[str] = field(default_factory=list)
    adsys: bool = False
    cert_autoenroll: bool = False

    @classmethod
    def from_dict(cls, data: dict | None) -> "GpoSpec":
        data = data or {}
        _reject_unknown(data, cls, "gpo")
        obj = cls(
            manage=_as_bool(data.get("manage"), "gpo.manage", False),
            access_control=_one_of(
                data.get("access_control"),
                GPO_ACCESS_CONTROL,
                "gpo.access_control",
                "permissive",
            ),
            implicit_deny=(
                None
                if data.get("implicit_deny") is None
                else _as_bool(data.get("implicit_deny"), "gpo.implicit_deny")
            ),
            ignore_unreadable=(
                None
                if data.get("ignore_unreadable") is None
                else _as_bool(data.get("ignore_unreadable"), "gpo.ignore_unreadable")
            ),
            map_interactive_add=_as_list(
                data.get("map_interactive_add"), "gpo.map_interactive_add"
            ),
            map_interactive_remove=_as_list(
                data.get("map_interactive_remove"), "gpo.map_interactive_remove"
            ),
            adsys=_as_bool(data.get("adsys"), "gpo.adsys", False),
            cert_autoenroll=_as_bool(
                data.get("cert_autoenroll"), "gpo.cert_autoenroll", False
            ),
        )
        overlap = set(obj.map_interactive_add) & set(obj.map_interactive_remove)
        if overlap:
            raise ProfileError(
                "gpo: service(s) "
                + ", ".join(sorted(overlap))
                + " appear in both map_interactive_add and map_interactive_remove"
            )
        if obj.cert_autoenroll and not obj.adsys:
            raise ProfileError(
                "gpo: cert_autoenroll requires adsys: true -- certificate "
                "auto-enrolment is driven by adsys through certmonger and cepces"
            )
        return obj

    @property
    def map_interactive(self) -> list[str]:
        """The ``ad_gpo_map_interactive`` value, using the documented +/- syntax."""
        return [f"+{s}" for s in self.map_interactive_add] + [
            f"-{s}" for s in self.map_interactive_remove
        ]

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"manage": self.manage}
        if self.manage:
            out["access_control"] = self.access_control
        for key in ("implicit_deny", "ignore_unreadable"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        for key in ("map_interactive_add", "map_interactive_remove"):
            value = getattr(self, key)
            if value:
                out[key] = list(value)
        if self.adsys:
            out["adsys"] = True
        if self.cert_autoenroll:
            out["cert_autoenroll"] = True
        return out


@dataclass
class SmartCardProfile:
    """A complete, self-contained Smart Card logon profile."""

    name: str
    domain: str
    description: str = ""
    provider: str = "ad"
    api_version: str = API_VERSION
    certificate: CertificateConstraints = field(default_factory=CertificateConstraints)
    mapping: MappingSpec = field(default_factory=MappingSpec)
    validation: ValidationSpec = field(default_factory=ValidationSpec)
    authentication: AuthenticationSpec = field(default_factory=AuthenticationSpec)
    ca_trust: CATrustSpec = field(default_factory=CATrustSpec)
    revocation: RevocationSpec = field(default_factory=RevocationSpec)
    gpo: GpoSpec = field(default_factory=GpoSpec)
    metadata: dict = field(default_factory=dict)
    source_path: str | None = None

    #: Section name in sssd.conf is [certmap/<section_domain>/<name>].
    @property
    def section(self) -> str:
        return f"certmap/{self.domain}/{self.name}"

    @property
    def target_domains(self) -> list[str]:
        """Domains the rule searches -- ``domains=`` in the certmap section."""
        return self.mapping.domains or [self.domain]

    @classmethod
    def from_dict(cls, data: dict, *, source_path: str | None = None) -> "SmartCardProfile":
        if not isinstance(data, dict):
            raise ProfileError("profile: expected a mapping at the top level")
        data = dict(data)
        api = str(data.pop("apiVersion", data.pop("api_version", API_VERSION)))
        if api != API_VERSION:
            raise ProfileError(
                f"profile: apiVersion {api!r} is not supported; this build understands "
                f"{API_VERSION!r}"
            )
        name = data.pop("name", None)
        if not name:
            raise ProfileError("profile: 'name' is required")
        if not str(name).strip() or any(c in str(name) for c in "/[] \t"):
            raise ProfileError(
                f"profile: name {name!r} must be non-empty and free of '/', '[', ']' and whitespace "
                "-- it becomes part of the [certmap/...] section name"
            )
        domain = data.pop("domain", None)
        if not domain:
            raise ProfileError(
                "profile: 'domain' is required -- it names the SSSD domain whose section "
                "the rule is attached to"
            )
        known = {
            "description",
            "provider",
            "certificate",
            "mapping",
            "validation",
            "authentication",
            "ca_trust",
            "revocation",
            "gpo",
            "metadata",
        }
        unknown = sorted(set(data) - known)
        if unknown:
            raise ProfileError(
                f"profile: unknown key(s) {', '.join(unknown)}; accepted top-level keys are "
                "apiVersion, name, domain, " + ", ".join(sorted(known))
            )
        return cls(
            name=str(name),
            domain=str(domain),
            description=str(data.get("description") or ""),
            provider=_one_of(data.get("provider"), PROVIDERS, "profile.provider", "ad"),
            api_version=api,
            certificate=CertificateConstraints.from_dict(data.get("certificate")),
            mapping=MappingSpec.from_dict(data.get("mapping")),
            validation=ValidationSpec.from_dict(data.get("validation")),
            authentication=AuthenticationSpec.from_dict(data.get("authentication")),
            ca_trust=CATrustSpec.from_dict(data.get("ca_trust")),
            revocation=RevocationSpec.from_dict(data.get("revocation")),
            gpo=GpoSpec.from_dict(data.get("gpo")),
            metadata=dict(data.get("metadata") or {}),
            source_path=source_path,
        )

    def to_dict(self) -> dict:
        out: dict[str, Any] = {
            "apiVersion": self.api_version,
            "name": self.name,
        }
        if self.description:
            out["description"] = self.description
        out["domain"] = self.domain
        out["provider"] = self.provider
        certificate = self.certificate.to_dict()
        if certificate:
            out["certificate"] = certificate
        out["mapping"] = self.mapping.to_dict()
        out["validation"] = self.validation.to_dict()
        out["authentication"] = self.authentication.to_dict()
        out["ca_trust"] = self.ca_trust.to_dict()
        out["revocation"] = self.revocation.to_dict()
        if self.gpo.manage or self.gpo.adsys:
            out["gpo"] = self.gpo.to_dict()
        if self.metadata:
            out["metadata"] = dict(self.metadata)
        return out
