"""Loading and saving profiles from YAML files."""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from ..errors import ProfileError
from .profile import SmartCardProfile

#: Searched in order, most specific first: an explicit override, the user's own
#: profiles, the administrator's, the ones a package shipped, and finally the
#: ``profiles/`` directory of a source checkout.
#:
#: ``/usr/share/sssd-smartcard/profiles`` is where the Debian package puts its
#: examples. They live under /usr/share rather than /etc so that dpkg never has
#: to prompt about a modified conffile on upgrade; anything the administrator
#: writes goes in /etc and takes precedence.
DEFAULT_PROFILE_DIRS = (
    Path(os.environ["SSSD_SMARTCARD_PROFILES"])
    if os.environ.get("SSSD_SMARTCARD_PROFILES")
    else None,
    Path.home() / ".config" / "sssd-smartcard" / "profiles",
    Path("/etc/sssd-smartcard/profiles"),
    Path("/usr/share/sssd-smartcard/profiles"),
    Path(__file__).resolve().parents[3] / "profiles",
)


def profile_dirs() -> list[Path]:
    return [p for p in DEFAULT_PROFILE_DIRS if p is not None]


def load_profile_text(text: str, *, source_path: str | None = None) -> SmartCardProfile:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ProfileError(f"{source_path or '<stdin>'}: invalid YAML: {exc}") from exc
    if data is None:
        raise ProfileError(f"{source_path or '<stdin>'}: file is empty")
    return SmartCardProfile.from_dict(data, source_path=source_path)


def load_profile_file(path: str | os.PathLike) -> SmartCardProfile:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProfileError(f"cannot read profile {path}: {exc}") from exc
    return load_profile_text(text, source_path=str(path))


def find_profile(name_or_path: str) -> SmartCardProfile:
    """Resolve a profile by path, or by name across the search directories."""
    candidate = Path(name_or_path)
    if candidate.suffix in (".yaml", ".yml") or candidate.exists():
        return load_profile_file(candidate)
    for directory in profile_dirs():
        for suffix in (".yaml", ".yml"):
            path = directory / f"{name_or_path}{suffix}"
            if path.exists():
                return load_profile_file(path)
    searched = ", ".join(str(d) for d in profile_dirs())
    raise ProfileError(f"profile {name_or_path!r} not found; searched: {searched}")


def list_profiles() -> list[tuple[Path, SmartCardProfile | None, str | None]]:
    """Every profile found, as ``(path, profile, error)`` triples."""
    seen: set[str] = set()
    out: list[tuple[Path, SmartCardProfile | None, str | None]] = []
    for directory in profile_dirs():
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.y*ml")):
            if path.name in seen:
                continue
            seen.add(path.name)
            try:
                out.append((path, load_profile_file(path), None))
            except ProfileError as exc:
                out.append((path, None, str(exc)))
    return out


def dump_profile(profile: SmartCardProfile) -> str:
    return yaml.safe_dump(
        profile.to_dict(), sort_keys=False, allow_unicode=True, default_flow_style=False
    )


def save_profile(profile: SmartCardProfile, path: str | os.PathLike) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump_profile(profile), encoding="utf-8")
    return path
