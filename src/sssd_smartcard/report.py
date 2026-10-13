"""Terminal output helpers: colours, headings, key/value blocks, diffs."""

from __future__ import annotations

import os
import sys

from .util import Check

_STATUS_COLOURS = {
    "PASS": "\033[32m",
    "FAIL": "\033[31m",
    "WARN": "\033[33m",
    "INFO": "\033[36m",
    "SKIP": "\033[90m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[90m"


def use_colour(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


class Printer:
    """Everything the CLI writes goes through one of these."""

    def __init__(self, stream=None, *, colour: bool | None = None) -> None:
        self.stream = stream or sys.stdout
        self.colour = use_colour(self.stream) if colour is None else colour

    # -- primitives -----------------------------------------------------
    def write(self, text: str = "") -> None:
        print(text, file=self.stream)

    def _c(self, text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if self.colour else text

    def bold(self, text: str) -> str:
        return self._c(text, _BOLD)

    def dim(self, text: str) -> str:
        return self._c(text, _DIM)

    # -- blocks ---------------------------------------------------------
    def heading(self, text: str) -> None:
        self.write()
        self.write(self.bold(text))
        self.write(self.dim("-" * len(text)))

    def kv(self, key: str, value, *, width: int = 22, indent: str = "  ") -> None:
        if value is None or value == [] or value == "":
            return
        if isinstance(value, (list, tuple)):
            first, *rest = list(value)
            self.write(f"{indent}{self.dim((key + ':').ljust(width))} {first}")
            for item in rest:
                self.write(f"{indent}{' ' * width} {item}")
            return
        text = str(value)
        if "\n" in text:
            lines = text.splitlines()
            self.write(f"{indent}{self.dim((key + ':').ljust(width))} {lines[0]}")
            for line in lines[1:]:
                self.write(f"{indent}{' ' * width} {line}")
            return
        self.write(f"{indent}{self.dim((key + ':').ljust(width))} {text}")

    def status(self, check: Check, *, indent: str = "") -> None:
        code = _STATUS_COLOURS.get(check.status, "")
        label = self._c(f"[{check.status}]".ljust(6), code)
        line = f"{indent}{label} {check.name}"
        if check.detail:
            line += f"  {self.dim(check.detail)}" if check.status == "PASS" else f"  {check.detail}"
        self.write(line)
        if check.hint and check.status in ("FAIL", "WARN"):
            self.write(f"{indent}       {self.dim('-> ' + check.hint)}")

    def bullet(self, text: str, *, marker: str = "*", indent: str = "  ") -> None:
        first, *rest = _wrap(text)
        self.write(f"{indent}{marker} {first}")
        for line in rest:
            self.write(f"{indent}  {line}")

    def note(self, text: str) -> None:
        self.bullet(self.dim(text), marker="i")

    def warn(self, text: str) -> None:
        self.bullet(self._c(text, _STATUS_COLOURS["WARN"]), marker="!")

    def error(self, text: str) -> None:
        self.write(self._c(f"error: {text}", _STATUS_COLOURS["FAIL"]))

    def diff(self, text: str) -> None:
        if not text.strip():
            self.write(self.dim("  (no changes)"))
            return
        for line in text.splitlines():
            if line.startswith("+++") or line.startswith("---"):
                self.write(self.bold(line))
            elif line.startswith("+"):
                self.write(self._c(line, _STATUS_COLOURS["PASS"]))
            elif line.startswith("-"):
                self.write(self._c(line, _STATUS_COLOURS["FAIL"]))
            elif line.startswith("@@"):
                self.write(self._c(line, _STATUS_COLOURS["INFO"]))
            else:
                self.write(line)

    def block(self, text: str, *, indent: str = "  ") -> None:
        for line in text.splitlines():
            self.write(f"{indent}{line}")

    def verdict(self, ok: bool, label_ok: str, label_bad: str) -> None:
        code = _STATUS_COLOURS["PASS" if ok else "FAIL"]
        self.write(self._c(self.bold(label_ok if ok else label_bad), code))


def _wrap(text: str, width: int = 88) -> list[str]:
    import textwrap

    return textwrap.wrap(text, width=width) or [""]
