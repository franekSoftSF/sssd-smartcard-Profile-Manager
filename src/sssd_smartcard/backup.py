"""Backups and atomic writes.

Every file this tool touches on a live system goes through here, so there is
exactly one place that decides how a backup is named, what mode a new file
gets, and how a rollback is performed.
"""

from __future__ import annotations

import datetime as _dt
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ApplyError

#: Backups live next to the SSSD configuration, not in /tmp.
DEFAULT_BACKUP_DIR = Path("/var/lib/sssd-smartcard/backups")


def timestamp() -> str:
    return _dt.datetime.now().strftime("%Y%m%d-%H%M%S")


@dataclass
class BackupEntry:
    """One saved file, and where it came from."""

    original: Path
    saved: Path
    existed: bool
    mode: int | None = None

    def to_dict(self) -> dict:
        return {
            "original": str(self.original),
            "backup": str(self.saved),
            "existed": self.existed,
            "mode": oct(self.mode) if self.mode is not None else None,
        }


@dataclass
class BackupSet:
    """A group of backups taken for one ``config apply`` run."""

    directory: Path
    entries: list[BackupEntry] = field(default_factory=list)

    def add(self, path: str | os.PathLike) -> BackupEntry:
        path = Path(path)
        self.directory.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.directory, 0o700)
        except OSError:
            pass
        target = self.directory / (path.name + ".orig")
        counter = 1
        while target.exists():
            target = self.directory / f"{path.name}.{counter}.orig"
            counter += 1
        if path.exists():
            shutil.copy2(path, target)
            mode = path.stat().st_mode & 0o777
            try:
                os.chmod(target, mode)
            except OSError:
                pass
            entry = BackupEntry(path, target, True, mode)
        else:
            # Record the absence so a rollback can delete a file we created.
            target.write_text("", encoding="utf-8")
            entry = BackupEntry(path, target, False, None)
        self.entries.append(entry)
        return entry

    def rollback(self) -> list[str]:
        """Put everything back. Returns a human readable log."""
        log: list[str] = []
        for entry in reversed(self.entries):
            try:
                if entry.existed:
                    shutil.copy2(entry.saved, entry.original)
                    if entry.mode is not None:
                        os.chmod(entry.original, entry.mode)
                    log.append(f"restored {entry.original}")
                elif entry.original.exists():
                    entry.original.unlink()
                    log.append(f"removed {entry.original} (did not exist before)")
            except OSError as exc:
                log.append(f"FAILED to restore {entry.original}: {exc}")
        return log

    def to_dict(self) -> dict:
        return {
            "directory": str(self.directory),
            "entries": [e.to_dict() for e in self.entries],
        }


#: ``20261011-224003`` -- the shape :func:`timestamp` produces.
_STAMP_RE = re.compile(r"^\d{8}-\d{6}$")


def new_backup_set(base: str | os.PathLike | None = None) -> BackupSet:
    """Create a backup set under *base*, or the default location.

    When *base* is already a timestamped directory -- which it is when the setup
    script hands us the run directory it is also backing up into -- use it
    directly rather than nesting a second timestamp inside it. Otherwise one run
    reports backups at ``backups/20261011-224003/20261011-224031``.
    """
    if base:
        root = Path(base)
        if _STAMP_RE.match(root.name):
            return BackupSet(root)
        return BackupSet(root / timestamp())
    return BackupSet(DEFAULT_BACKUP_DIR / timestamp())


def write_atomic(path: str | os.PathLike, content: str, *, mode: int = 0o600) -> None:
    """Write *content* to *path* atomically, with *mode* applied before rename.

    ``sssd.conf`` must not be world readable, and a half-written file must never
    be visible, hence the temp-file-plus-rename dance with the mode set first.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        try:
            stat = path.stat()
            os.chown(tmp, stat.st_uid, stat.st_gid)
        except (FileNotFoundError, AttributeError, PermissionError, OSError):
            # New file, or a platform without chown: defaults are fine.
            pass
        os.replace(tmp, path)
    except OSError as exc:
        tmp.unlink(missing_ok=True)
        raise ApplyError(f"could not write {path}: {exc}") from exc


def check_mode(path: str | os.PathLike, expected: int = 0o600) -> tuple[bool, int | None]:
    """Return ``(ok, actual_mode)`` for *path*."""
    path = Path(path)
    if not path.exists():
        return False, None
    actual = path.stat().st_mode & 0o777
    return actual <= expected and not (actual & 0o077), actual
