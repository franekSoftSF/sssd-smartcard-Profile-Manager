"""CA trust: inspect CA certificates and build the bundle SSSD verifies against.

SSSD verifies Smart Card certificates against the single PEM file named by
``pam_cert_db_path`` (default ``/etc/sssd/pki/sssd_auth_ca_db.pem``).  This
module imports CA certificates into that file without ever clobbering what is
already there: the existing bundle is read, parsed, and merged, and a backup is
taken before anything is written.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..backup import BackupSet, write_atomic
from ..errors import CertificateError
from ..model.profile import DEFAULT_CA_DB
from ..x509.inspect import CertificateInfo, load_certificates

ROLE_ROOT = "root"
ROLE_INTERMEDIATE = "intermediate"
ROLE_ISSUING = "issuing"
ROLE_LEAF = "end-entity"


def classify(cert: CertificateInfo) -> str:
    """Root, intermediate or end-entity, from basicConstraints alone."""
    bc = cert.basic_constraints
    if not bc or not bc[0]:
        return ROLE_LEAF
    if cert.is_self_signed:
        return ROLE_ROOT
    # pathlen:0 means it may only issue end-entity certificates.
    return ROLE_ISSUING if bc[1] == 0 else ROLE_INTERMEDIATE


@dataclass
class CAEntry:
    """A CA certificate plus what the operator needs to see about it."""

    cert: CertificateInfo
    role: str
    problems: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        return self.cert.fingerprint("sha256")

    def to_dict(self) -> dict:
        bc = self.cert.basic_constraints
        return {
            "role": self.role,
            "subject": self.cert.subject_dn,
            "issuer": self.cert.issuer_dn,
            "serial_number": self.cert.serial_hex(colon=True, upper=True),
            "fingerprint_sha256": self.fingerprint,
            "not_before": self.cert.not_before.isoformat(),
            "not_after": self.cert.not_after.isoformat(),
            "expired": self.cert.expired,
            "days_remaining": self.cert.days_remaining,
            "basic_constraints": {"ca": bc[0], "path_length": bc[1]} if bc else None,
            "subject_key_id": self.cert.subject_key_id.hex().upper()
            if self.cert.subject_key_id
            else None,
            "authority_key_id": self.cert.authority_key_id.hex().upper()
            if self.cert.authority_key_id
            else None,
            "source": self.cert.source,
            "problems": self.problems,
        }


def examine(cert: CertificateInfo) -> CAEntry:
    """Wrap *cert* with its role and any problems worth flagging."""
    role = classify(cert)
    problems: list[str] = []
    bc = cert.basic_constraints
    if bc is None:
        problems.append(
            "no basicConstraints extension; this certificate cannot act as a CA"
        )
    elif not bc[0]:
        problems.append("basicConstraints says CA:FALSE; this is not a CA certificate")
    if cert.expired:
        problems.append(f"expired on {cert.not_after:%Y-%m-%d}")
    elif cert.days_remaining < 90:
        problems.append(f"expires in {cert.days_remaining} day(s)")
    ku = cert.key_usage
    if bc and bc[0] and ku and "keyCertSign" not in ku:
        problems.append(
            "keyUsage does not include keyCertSign, which a CA certificate needs"
        )
    return CAEntry(cert, role, problems)


def load_ca_files(paths: list[str]) -> list[CAEntry]:
    """Read every certificate out of every given file."""
    entries: list[CAEntry] = []
    for path in paths:
        try:
            data = Path(path).read_bytes()
        except OSError as exc:
            raise CertificateError(f"cannot read {path}: {exc}") from exc
        for cert in load_certificates(data, source=path):
            entries.append(examine(cert))
    return entries


def load_bundle(path: str | Path) -> list[CAEntry]:
    """Read an existing trust bundle; a missing file is simply empty."""
    path = Path(path)
    if not path.exists():
        return []
    data = path.read_bytes()
    if not data.strip():
        return []
    return [examine(cert) for cert in load_certificates(data, source=str(path))]


def order_bundle(entries: list[CAEntry]) -> list[CAEntry]:
    """Roots first, then intermediates, then issuing CAs.

    Order does not matter to OpenSSL's verification, but a predictable file is
    far easier to diff and to review.
    """
    rank = {ROLE_ROOT: 0, ROLE_INTERMEDIATE: 1, ROLE_ISSUING: 2, ROLE_LEAF: 3}
    return sorted(entries, key=lambda e: (rank.get(e.role, 9), e.cert.subject_dn))


@dataclass
class BundlePlan:
    """What ``ca import`` would do, before it does it."""

    path: Path
    existing: list[CAEntry]
    added: list[CAEntry]
    skipped: list[CAEntry]
    final: list[CAEntry]
    content: str
    warnings: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.added)

    def to_dict(self) -> dict:
        return {
            "path": str(self.path),
            "existing": [e.to_dict() for e in self.existing],
            "added": [e.to_dict() for e in self.added],
            "skipped_already_present": [e.to_dict() for e in self.skipped],
            "total_after": len(self.final),
            "changed": self.changed,
            "warnings": self.warnings,
        }


def plan_bundle(sources: list[str], bundle_path: str | Path = DEFAULT_CA_DB) -> BundlePlan:
    """Work out the merged bundle without touching the filesystem."""
    bundle_path = Path(bundle_path)
    existing = load_bundle(bundle_path)
    incoming = load_ca_files(sources)

    seen = {e.fingerprint for e in existing}
    added: list[CAEntry] = []
    skipped: list[CAEntry] = []
    warnings: list[str] = []

    for entry in incoming:
        if entry.fingerprint in seen:
            skipped.append(entry)
            continue
        if entry.role == ROLE_LEAF:
            warnings.append(
                f"{entry.cert.subject_dn} is not a CA certificate (basicConstraints "
                "CA:FALSE or absent) -- it is being added, but check that this is "
                "really what you meant"
            )
        for problem in entry.problems:
            warnings.append(f"{entry.cert.subject_dn}: {problem}")
        seen.add(entry.fingerprint)
        added.append(entry)

    final = order_bundle(existing + added)
    header = (
        "# SSSD Smart Card CA trust bundle\n"
        "# Managed by sssd-smartcard. Certificates are appended, never replaced.\n"
    )
    body = []
    for entry in final:
        body.append(
            f"# {entry.role}: {entry.cert.subject_dn}\n"
            f"#   SHA-256: {entry.fingerprint}\n"
            f"#   valid until: {entry.cert.not_after:%Y-%m-%d}\n"
            f"{entry.cert.pem}"
        )
    return BundlePlan(
        path=bundle_path,
        existing=existing,
        added=added,
        skipped=skipped,
        final=final,
        content=header + "\n".join(body),
        warnings=warnings,
    )


def apply_bundle(plan: BundlePlan, backups: BackupSet) -> None:
    """Write the merged bundle, after backing up whatever is there now."""
    backups.add(plan.path)
    # Trust anchors are public certificates; p11_child reads this file as the
    # SSSD user, so it must stay world readable but never world writable.
    write_atomic(plan.path, plan.content, mode=0o644)
