"""Certificate Revocation Lists: fetch, combine, validate, watch them expire.

Without this, revocation is simply not enforced -- a revoked card still logs
in. The alternative, OCSP, needs a responder; where there is none, CRLs are the
only mechanism, and SSSD reads them from one local PEM file (``crl_file=``).
Nothing in SSSD downloads or refreshes that file.

Two measured facts shape this module, neither of them in ``sssd.conf(5)``:

**SSSD checks the CRL of every CA in the chain, not just the issuer of the
card's certificate.** Supplying only the issuing CA's CRL -- the obvious choice,
since that is the list naming revoked user certificates -- makes verification
fail for everyone::

    X509_verify_cert failed [3][unable to get certificate CRL]
    p11_child failed (22)

That is OpenSSL's ``X509_V_ERR_UNABLE_TO_GET_CRL`` under
``X509_V_FLAG_CRL_CHECK_ALL``. Since ``crl_file`` fails closed, the result is
that nobody can log in at all. Measured on SSSD 2.9.4 against a two-tier PKI.

**Several CRLs concatenated into one PEM file do work**, in any order. The man
page does not say so; ``p11_child --verification --verify=crl_file=...``
confirms it.

So a usable CRL file is the concatenation of one current CRL per CA in the trust
bundle, and this module refuses to install an incomplete set rather than
handing the operator a host that rejects every card.

Sources: ``sssd.conf(5)`` -> ``certificate_verification`` (``crl_file``: "The
CRL must be given in PEM format"; ``soft_crl``: "If a Certificate Revocation
List (CRL) is expired ignore the expiration time of the CRL"); the chain-wide
behaviour and multi-CRL support are measured, as above.
"""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..errors import CertificateError
from ..util import Check, run, which
from ..x509.inspect import CertificateInfo
from ..x509.names import format_dn
from .trust import CAEntry, load_bundle

#: Where the tool keeps the combined CRL by default.
DEFAULT_CRL_FILE = "/etc/sssd/pki/revocation.crl.pem"

#: Remembered CRL URL per CA.  The timer runs with no card inserted, so the
#: issuing CA CRL URL -- which is only advertised by end-entity certificates --
#: would be undiscoverable otherwise, and every unattended refresh would refuse
#: to install an incomplete set.  Recorded once, reused forever.
SOURCES_FILE = "/var/lib/sssd-smartcard/crl-sources.json"

#: Warn this many days before a CRL's nextUpdate.  An expired CRL stops every
#: login unless ``soft_crl`` is set, so the warning has to come early enough to
#: act on; the lab's issuing CA publishes weekly.
EXPIRY_WARN_DAYS = 3

_PEM_CRL_RE = re.compile(
    rb"-----BEGIN X509 CRL-----.+?-----END X509 CRL-----", re.DOTALL
)


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _aware(value: _dt.datetime) -> _dt.datetime:
    """cryptography returns naive UTC for the non-``_utc`` properties."""
    if value.tzinfo is None:
        return value.replace(tzinfo=_dt.timezone.utc)
    return value


@dataclass
class CrlInfo:
    """One CRL, and whether it is fit to use."""

    crl: x509.CertificateRevocationList
    source: str = "<memory>"

    @property
    def issuer(self) -> str:
        return format_dn(self.crl.issuer)

    @property
    def last_update(self) -> _dt.datetime:
        return _aware(self.crl.last_update)

    @property
    def next_update(self) -> _dt.datetime | None:
        value = self.crl.next_update
        return _aware(value) if value else None

    @property
    def revoked_count(self) -> int:
        try:
            return len(self.crl)
        except TypeError:  # pragma: no cover - empty CRL on old cryptography
            return 0

    @property
    def expired(self) -> bool:
        nxt = self.next_update
        return bool(nxt and nxt <= _utcnow())

    @property
    def days_left(self) -> float | None:
        nxt = self.next_update
        if not nxt:
            return None
        return (nxt - _utcnow()).total_seconds() / 86400.0

    def is_revoked(self, serial: int) -> bool:
        return self.crl.get_revoked_certificate_by_serial_number(serial) is not None

    def to_pem(self) -> bytes:
        return self.crl.public_bytes(serialization.Encoding.PEM)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "issuer": self.issuer,
            "last_update": self.last_update.isoformat(),
            "next_update": self.next_update.isoformat() if self.next_update else None,
            "revoked_count": self.revoked_count,
            "expired": self.expired,
            "days_left": round(self.days_left, 2) if self.days_left is not None else None,
        }


def load_crls(data: bytes, *, source: str = "<memory>") -> list[CrlInfo]:
    """Parse one or more CRLs from PEM or DER.

    A single file holding several concatenated PEM CRLs is the shape SSSD
    accepts, so parsing that shape back is the first thing this needs to do.
    """
    found: list[CrlInfo] = []
    for match in _PEM_CRL_RE.finditer(data):
        try:
            found.append(
                CrlInfo(x509.load_pem_x509_crl(match.group(0)), source=source)
            )
        except Exception as exc:
            raise CertificateError(f"{source}: a PEM CRL could not be parsed: {exc}")
    if found:
        return found
    try:
        return [CrlInfo(x509.load_der_x509_crl(data), source=source)]
    except Exception as exc:
        raise CertificateError(
            f"{source}: not a CRL in PEM or DER form ({exc}). Microsoft CAs publish "
            "DER; SSSD needs PEM, which this tool converts for you."
        ) from None


def load_crl_file(path: str | Path) -> list[CrlInfo]:
    path = Path(path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise CertificateError(f"cannot read {path}: {exc}") from None
    return load_crls(data, source=str(path))


def fetch_crl(url: str, *, timeout: int = 30) -> bytes:
    """Download a CRL over HTTP.

    Uses curl when present, because a Microsoft CA's CDP path is usually full of
    percent-encoded spaces and curl handles that without further encoding.
    """
    if url.lower().startswith("ldap"):
        raise CertificateError(
            f"{url}: LDAP distribution points are not fetched by this tool; use the "
            "HTTP CDP, or export the CRL and pass it as a file"
        )
    if not url.lower().startswith(("http://", "https://")):
        raise CertificateError(f"{url}: only http(s) distribution points are fetched")
    if not which("curl"):
        raise CertificateError("curl is not installed, so CRLs cannot be downloaded")
    # curl writes to a file rather than stdout: a CRL is usually DER, and the
    # shared run() helper decodes stdout as text.
    import tempfile

    with tempfile.TemporaryDirectory(prefix="sssd-smartcard-crl-") as tmp:
        target = Path(tmp) / "crl.bin"
        result = run(
            ["curl", "-sSfL", "--max-time", str(timeout), "-o", str(target), url],
            timeout=timeout + 10,
        )
        if not result.ok:
            raise CertificateError(
                f"{url}: download failed"
                + (f" -- {result.stderr.strip()}" if result.stderr.strip() else "")
            )
        try:
            data = target.read_bytes()
        except OSError as exc:
            raise CertificateError(f"{url}: nothing was downloaded ({exc})") from None
    if not data:
        raise CertificateError(f"{url}: the download was empty")
    return data


@dataclass
class CrlPlan:
    """A combined CRL file, and whether it covers the whole chain."""

    crl_file: str = DEFAULT_CRL_FILE
    cas: list[CAEntry] = field(default_factory=list)
    crls: list[CrlInfo] = field(default_factory=list)
    #: CA subject DNs with no CRL. Any entry here means every login would fail.
    missing: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    content: bytes = b""
    #: ``{normalised CA subject: URL}`` that worked, for the unattended refresh.
    sources: dict[str, str] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        return bool(self.crls) and not self.missing

    @property
    def expired(self) -> list[CrlInfo]:
        return [c for c in self.crls if c.expired]

    @property
    def soonest_expiry(self) -> CrlInfo | None:
        dated = [c for c in self.crls if c.next_update]
        if not dated:
            return None
        return min(dated, key=lambda c: c.next_update)

    def to_dict(self) -> dict:
        return {
            "crl_file": self.crl_file,
            "cas": [c.cert.subject_dn for c in self.cas],
            "crls": [c.to_dict() for c in self.crls],
            "missing": self.missing,
            "errors": self.errors,
            "complete": self.complete,
            "bytes": len(self.content),
        }


def load_sources(path: str | Path = SOURCES_FILE) -> dict[str, str]:
    """Remembered ``{normalised CA subject: CRL URL}``."""
    try:
        import json

        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.get("cas", {}).items() if v}


def save_sources(sources: dict[str, str], path: str | Path = SOURCES_FILE) -> None:
    """Record the URLs, merging with whatever is already known."""
    import json

    merged = load_sources(path)
    merged.update({k: v for k, v in sources.items() if v})
    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps({"cas": merged}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError:
        # Not fatal: the refresh still works today, it just will not remember.
        pass


def _normalise(dn: str) -> str:
    """Compare DNs without being defeated by spacing or case."""
    return re.sub(r"\s+", "", dn).lower()


def build_crl_plan(
    *,
    ca_bundle: str | Path,
    crl_file: str | Path = DEFAULT_CRL_FILE,
    local_files: list[str] | None = None,
    leaf_certs: list[CertificateInfo] | None = None,
    fetch: bool = True,
    use_remembered: bool = True,
) -> CrlPlan:
    """Collect one CRL per CA in *ca_bundle* and combine them.

    Where the CRLs come from is the subtle part. A certificate's
    ``crlDistributionPoints`` names the CRL that would revoke *that
    certificate* -- the one published by its **issuer**. So to obtain the CRL
    issued by CA *X*, look at the CDP of a certificate *X* signed, not at
    *X*'s own certificate:

    * the issuing CA's CRL is advertised by the **card's** certificate;
    * the root CA's CRL is advertised by the **issuing CA's** certificate;
    * a self-signed root advertises nothing, which is why reading each CA's own
      CDP finds the root's CRL twice and the issuing CA's never.

    Hence *leaf_certs*: without at least one end-entity certificate from this
    PKI, the issuing CA's CRL has no discoverable URL. Pass the card's
    certificate, or supply the file directly with *local_files*.
    """
    plan = CrlPlan(crl_file=str(crl_file))
    plan.cas = load_bundle(ca_bundle)
    if not plan.cas:
        plan.errors.append(f"{ca_bundle} contains no CA certificates")
        return plan

    by_issuer: dict[str, CrlInfo] = {}
    for path in local_files or []:
        try:
            for crl in load_crl_file(path):
                by_issuer[_normalise(crl.issuer)] = crl
        except CertificateError as exc:
            plan.errors.append(str(exc))

    # Every certificate that could advertise one of these CAs' CRLs.
    children: list[CertificateInfo] = list(leaf_certs or [])
    children.extend(entry.cert for entry in plan.cas)

    remembered = load_sources() if use_remembered else {}

    for entry in plan.cas:
        key = _normalise(entry.cert.subject_dn)
        if key in by_issuer or not fetch:
            continue
        urls: list[str] = []
        if remembered.get(key):
            urls.append(remembered[key])
        for child in children:
            if _normalise(child.issuer_dn) != key:
                continue
            if _normalise(child.subject_dn) == key:
                # Self-signed: its own CDP points at its parent, which is
                # itself, so it tells us nothing about the CRL it publishes.
                continue
            urls.extend(
                u for u in child.crl_urls if u.lower().startswith("http")
            )
        # Deduplicate while keeping order.
        urls = list(dict.fromkeys(urls))
        if not urls:
            plan.errors.append(
                f"{entry.cert.subject_dn}: cannot discover this CA's CRL. Its own "
                "certificate does not advertise it -- a crlDistributionPoints entry "
                "names the CRL of the ISSUER, so the URL has to come from a "
                "certificate this CA signed, and none was available. Run once with "
                "--from-card (or --from-cert) and the URL is remembered in "
                f"{SOURCES_FILE} for every later refresh; or pass the CRL itself "
                "with --from-file."
            )
            continue
        for url in urls:
            try:
                data = fetch_crl(url)
                crls = load_crls(data, source=url)
            except CertificateError as exc:
                plan.errors.append(str(exc))
                continue
            for crl in crls:
                issuer_key = _normalise(crl.issuer)
                by_issuer[issuer_key] = crl
                # Remember which URL served which CA, so a later refresh with
                # no card can find it again.
                plan.sources[issuer_key] = url
            break

    # Keep the bundle's own order, so the file reads like the chain.
    for entry in plan.cas:
        crl = by_issuer.get(_normalise(entry.cert.subject_dn))
        if crl is None:
            plan.missing.append(entry.cert.subject_dn)
        else:
            plan.crls.append(crl)

    plan.content = b"".join(c.to_pem() for c in plan.crls)
    return plan


def crl_plan_checks(plan: CrlPlan) -> list[Check]:
    """Turn a plan into checks, with the lockout risk stated plainly."""
    checks: list[Check] = []
    for error in plan.errors:
        checks.append(Check("CRL source", "WARN", error))

    for crl in plan.crls:
        if crl.expired:
            status, detail = "FAIL", f"EXPIRED {crl.next_update:%Y-%m-%d}"
        elif crl.days_left is not None and crl.days_left < EXPIRY_WARN_DAYS:
            status = "WARN"
            detail = f"expires {crl.next_update:%Y-%m-%d} ({crl.days_left:.1f} days)"
        else:
            status = "PASS"
            detail = (
                f"expires {crl.next_update:%Y-%m-%d}"
                if crl.next_update
                else "no nextUpdate"
            )
        checks.append(
            Check(
                f"CRL {crl.issuer}",
                status,
                f"{detail}, {crl.revoked_count} revoked",
                hint=""
                if status == "PASS"
                else "An expired CRL makes verification fail for every card, because "
                "crl_file fails closed. Refresh it, or set revocation.fail_mode: open "
                "to emit soft_crl, which keeps logins working on a stale CRL.",
            )
        )

    if plan.missing:
        checks.append(
            Check(
                "CRL coverage",
                "FAIL",
                "no CRL for " + ", ".join(plan.missing),
                hint="SSSD checks the CRL of every CA in the chain, not just the one "
                "that issued the card's certificate. Measured: with a CRL missing for "
                "any CA, verification fails with 'unable to get certificate CRL' and "
                "NOBODY can log in. Supply the missing CRL, or leave CRL checking off.",
            )
        )
    elif plan.crls:
        checks.append(
            Check(
                "CRL coverage",
                "PASS",
                f"{len(plan.crls)} CRL(s) covering all {len(plan.cas)} CA(s) in the bundle",
            )
        )
    return checks


def installed_crl_checks(
    crl_file: str | Path = DEFAULT_CRL_FILE,
    *,
    ca_bundle: str | Path | None = None,
) -> list[Check]:
    """Check the CRL file a host is actually using."""
    path = Path(crl_file)
    if not path.exists():
        return [
            Check(
                "CRL file",
                "WARN",
                f"{path} does not exist",
                hint="Referenced by certificate_verification = crl_file=. Until it "
                "exists, verification fails for every card. Create it with: "
                "sssd-smartcard ca crl update",
            )
        ]
    try:
        crls = load_crl_file(path)
    except CertificateError as exc:
        return [Check("CRL file", "FAIL", str(exc))]

    plan = CrlPlan(crl_file=str(path), crls=crls)
    if ca_bundle:
        try:
            plan.cas = load_bundle(ca_bundle)
            covered = {_normalise(c.issuer) for c in crls}
            plan.missing = [
                e.cert.subject_dn
                for e in plan.cas
                if _normalise(e.cert.subject_dn) not in covered
            ]
        except Exception as exc:  # pragma: no cover - unreadable bundle
            plan.errors.append(f"cannot compare against {ca_bundle}: {exc}")
    return crl_plan_checks(plan)


def _posix_parent(path: str) -> str:
    r"""Directory of a target-host path.

    Deliberately not ``pathlib.Path``: these paths are always Linux paths, and
    on Windows ``Path("/etc/sssd/pki/x.pem").parent`` renders as
    ``\etc\sssd\pki``, which would go straight into a systemd unit.
    """
    import posixpath

    return posixpath.dirname(path) or "/"


#: Unit names the refresh timer uses.
SERVICE_UNIT = "sssd-smartcard-crl.service"
TIMER_UNIT = "sssd-smartcard-crl.timer"


def timer_units(
    *,
    bundle: str,
    crl_file: str = DEFAULT_CRL_FILE,
    on_calendar: str = "daily",
) -> dict[str, str]:
    """systemd units that keep the CRL file current.

    The service runs ``ca crl update``, which refuses to install an incomplete
    or expired set -- so a failed refresh leaves the previous, working CRL in
    place rather than replacing it with something that locks everyone out.
    That is why ``Type=oneshot`` with a non-zero exit is acceptable here: the
    failure is visible in ``systemctl status`` and nothing was broken.

    ``Persistent=true`` matters because a host that was off over the CRL's
    ``nextUpdate`` must refresh on the next boot rather than waiting for the
    next scheduled tick -- by then every card login would already be failing.
    """
    service = f"""[Unit]
Description=Refresh the SSSD Smart Card CRL file
Documentation=man:sssd-smartcard(8)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/sssd-smartcard ca crl update --bundle {bundle} --crl-file {crl_file}
# A refresh that cannot complete must not replace a working CRL, so the
# command is allowed to fail loudly instead of installing a bad set.
SuccessExitStatus=0
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths={_posix_parent(crl_file)}
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""

    timer = f"""[Unit]
Description=Refresh the SSSD Smart Card CRL file on a schedule
Documentation=man:sssd-smartcard(8)

[Timer]
OnCalendar={on_calendar}
# Catch up after downtime: an expired CRL fails closed, so waiting for the
# next tick would mean nobody can log in until then.
Persistent=true
RandomizedDelaySec=15m
Unit={SERVICE_UNIT}

[Install]
WantedBy=timers.target
"""
    return {SERVICE_UNIT: service, TIMER_UNIT: timer}


def timer_checks() -> list[Check]:
    """Is something actually refreshing the CRL?"""
    result = run(["systemctl", "is-enabled", TIMER_UNIT], timeout=15)
    if not result.found:
        return [Check("CRL refresh timer", "SKIP", "systemctl is not available")]
    state = (result.stdout or result.stderr).strip()
    if state == "enabled":
        active = run(["systemctl", "is-active", TIMER_UNIT], timeout=15)
        running = (active.stdout or "").strip() == "active"
        return [
            Check(
                "CRL refresh timer",
                "PASS" if running else "WARN",
                f"{TIMER_UNIT} is enabled and {'running' if running else 'not running'}",
                hint="" if running else f"systemctl start {TIMER_UNIT}",
            )
        ]
    return [
        Check(
            "CRL refresh timer",
            "WARN",
            f"{TIMER_UNIT} is not enabled ({state or 'absent'})",
            hint="Nothing is refreshing the CRL. SSSD never downloads one, and an "
            "expired CRL fails closed -- every card login stops working the moment "
            "nextUpdate passes. Install it with: sssd-smartcard ca crl timer --install",
        )
    ]
