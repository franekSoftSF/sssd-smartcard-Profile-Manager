"""A line-preserving editor for ``sssd.conf``.

``configparser`` would round-trip the semantics but throw away comments,
ordering and spacing.  An administrator reviewing ``config diff`` deserves to
see only the lines that actually changed, so this editor works on the original
lines and rewrites exactly the ones it must.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..errors import SmartCardError

DEFAULT_CONFIG = "/etc/sssd/sssd.conf"
DEFAULT_CONFD = "/etc/sssd/conf.d"

_SECTION_RE = re.compile(r"^\s*\[(?P<name>[^\]]+)\]\s*$")
_KEY_RE = re.compile(r"^(?P<indent>\s*)(?P<key>[^#;=\s][^=]*?)\s*=\s*(?P<value>.*?)\s*$")
_COMMENT_RE = re.compile(r"^\s*[#;]")


@dataclass
class SssdConfig:
    """``sssd.conf`` as a list of lines, with section-aware accessors."""

    lines: list[str] = field(default_factory=list)
    path: Path | None = None

    # -- construction ----------------------------------------------------
    @classmethod
    def parse(cls, text: str, *, path: str | Path | None = None) -> "SssdConfig":
        return cls(text.splitlines(), Path(path) if path else None)

    @classmethod
    def load(cls, path: str | Path = DEFAULT_CONFIG) -> "SssdConfig":
        path = Path(path)
        if not path.exists():
            return cls([], path)
        try:
            return cls.parse(path.read_text(encoding="utf-8"), path=path)
        except OSError as exc:
            raise SmartCardError(
                f"cannot read {path}: {exc}"
                + (
                    " (sssd.conf is normally mode 0600 and owned by root -- run as root)"
                    if isinstance(exc, PermissionError)
                    else ""
                )
            ) from exc

    def render(self) -> str:
        return "\n".join(self.lines).rstrip("\n") + "\n" if self.lines else ""

    # -- inspection ------------------------------------------------------
    def _section_bounds(self, name: str) -> tuple[int, int] | None:
        """``(header_index, end_index_exclusive)`` for section *name*."""
        start = None
        for index, line in enumerate(self.lines):
            match = _SECTION_RE.match(line)
            if match is None:
                continue
            if start is not None:
                return start, index
            if match.group("name").strip() == name:
                start = index
        if start is None:
            return None
        return start, len(self.lines)

    def sections(self) -> list[str]:
        out = []
        for line in self.lines:
            match = _SECTION_RE.match(line)
            if match:
                out.append(match.group("name").strip())
        return out

    def has_section(self, name: str) -> bool:
        return self._section_bounds(name) is not None

    def items(self, section: str) -> dict[str, str]:
        bounds = self._section_bounds(section)
        if bounds is None:
            return {}
        start, end = bounds
        out: dict[str, str] = {}
        for line in self.lines[start + 1 : end]:
            if _COMMENT_RE.match(line) or _SECTION_RE.match(line):
                continue
            match = _KEY_RE.match(line)
            if match:
                out[match.group("key").strip()] = match.group("value")
        return out

    def get(self, section: str, key: str, default: str | None = None) -> str | None:
        return self.items(section).get(key, default)

    def domains(self) -> list[str]:
        """Domains configured in the ``[sssd] domains =`` line."""
        raw = self.get("sssd", "domains", "") or ""
        return [d.strip() for d in raw.split(",") if d.strip()]

    def domain_sections(self) -> list[str]:
        return [s[len("domain/") :] for s in self.sections() if s.startswith("domain/")]

    def certmap_sections(self) -> list[str]:
        return [s for s in self.sections() if s.startswith("certmap/")]

    # -- mutation --------------------------------------------------------
    def set(self, section: str, key: str, value: str) -> bool:
        """Set ``key = value`` in *section*. Returns True when a line changed."""
        bounds = self._section_bounds(section)
        if bounds is None:
            if self.lines and self.lines[-1].strip():
                self.lines.append("")
            self.lines.append(f"[{section}]")
            self.lines.append(f"{key} = {value}")
            return True

        start, end = bounds
        last_key = start
        for index in range(start + 1, end):
            line = self.lines[index]
            if _COMMENT_RE.match(line) or not line.strip():
                continue
            match = _KEY_RE.match(line)
            if not match:
                continue
            last_key = index
            if match.group("key").strip() == key:
                if match.group("value") == value:
                    return False
                self.lines[index] = f"{match.group('indent')}{key} = {value}"
                return True
        self.lines.insert(last_key + 1, f"{key} = {value}")
        return True

    def unset(self, section: str, key: str) -> bool:
        bounds = self._section_bounds(section)
        if bounds is None:
            return False
        start, end = bounds
        for index in range(start + 1, end):
            match = _KEY_RE.match(self.lines[index])
            if match and match.group("key").strip() == key:
                del self.lines[index]
                return True
        return False

    def remove_section(self, section: str) -> bool:
        bounds = self._section_bounds(section)
        if bounds is None:
            return False
        start, end = bounds
        del self.lines[start:end]
        return True

    def copy(self) -> "SssdConfig":
        return SssdConfig(list(self.lines), self.path)


def unified_diff(before: str, after: str, *, path: str = "sssd.conf") -> str:
    """A unified diff of two configuration texts.

    The ``a/`` and ``b/`` prefixes follow the usual diff convention. The path is
    normally absolute, so strip its leading separator rather than emitting
    ``a//etc/sssd/sssd.conf``.
    """
    label = str(path).lstrip("/")
    diff = difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=f"a/{label}",
        tofile=f"b/{label}",
        n=3,
    )
    return "".join(diff)
