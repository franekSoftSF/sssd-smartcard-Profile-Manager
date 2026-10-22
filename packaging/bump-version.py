#!/usr/bin/env python3
"""Set the project version everywhere it is declared, in one go.

The version lives in six declarations plus the Debian changelog, and they have
drifted before: the setup script reported 0.2.0 while the package said 0.2.2,
which is confusing exactly when it matters -- working out which build a machine
is running. The build already refuses to package mismatched versions; this
makes keeping them matched a single command.

Why versions have to move at all: `apt-get install` compares versions and stops
at *already the newest version* without unpacking anything. Re-releasing under
one number therefore leaves the old code installed and every test afterwards
runs against it, which happened here. A new number makes apt do the work, and
makes `--version` answer the question honestly.

Usage:
    python packaging/bump-version.py 0.2.3
    python packaging/bump-version.py --check
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: ``(path, regex)`` for each place the version is *declared*. The regex must
#: capture the version in group 1, so only the number is replaced. Deliberately
#: exact: "0.2.2" also appears in prose and in unrelated numbers, and a blanket
#: substitution would rewrite those too.
DECLARATIONS: list[tuple[str, str]] = [
    ("pyproject.toml", r'^version = "([0-9][^"]*)"$'),
    ("src/sssd_smartcard/__init__.py", r'^__version__ = "([0-9][^"]*)"$'),
    ("scripts/sssd-smartcard-setup.sh", r'^VERSION="([0-9][^"]*)"$'),
    ("scripts/ad-prepare.sh", r'^VERSION="([0-9][^"]*)"$'),
    ("scripts/ad-reset.sh", r'^VERSION="([0-9][^"]*)"$'),
    ("scripts/install-desktop.sh", r'^VERSION="([0-9][^"]*)"$'),
    ("scripts/sssd-smartcard-capture.sh", r'^VERSION="([0-9][^"]*)"$'),
]

CHANGELOG = "debian/changelog"
CHANGELOG_RE = r"^sssd-smartcard \(([0-9][^)]*)\)"

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


def read_versions() -> dict[str, str | None]:
    found: dict[str, str | None] = {}
    for name, pattern in DECLARATIONS + [(CHANGELOG, CHANGELOG_RE)]:
        path = ROOT / name
        if not path.is_file():
            found[name] = None
            continue
        match = re.search(pattern, path.read_text(encoding="utf-8"), re.MULTILINE)
        found[name] = match.group(1) if match else None
    return found


def check() -> int:
    found = read_versions()
    missing = [n for n, v in found.items() if v is None]
    values = {v for v in found.values() if v}
    for name, value in found.items():
        print(f"  {value or 'NOT FOUND':10}  {name}")
    if missing:
        print(f"\nno version declaration found in: {', '.join(missing)}", file=sys.stderr)
        return 1
    if len(values) != 1:
        print(f"\nversions disagree: {', '.join(sorted(values))}", file=sys.stderr)
        return 1
    print(f"\nall agree on {values.pop()}")
    return 0


def bump(new: str) -> int:
    if not VERSION_RE.match(new):
        print(f"{new!r} is not a MAJOR.MINOR.PATCH version", file=sys.stderr)
        return 2

    found = read_versions()
    current = {v for v in found.values() if v}
    if len(current) != 1:
        print("refusing to bump while versions disagree; run --check", file=sys.stderr)
        return 1
    old = current.pop()
    if old == new:
        print(f"already at {new}", file=sys.stderr)
        return 1

    for name, pattern in DECLARATIONS:
        path = ROOT / name
        text = path.read_text(encoding="utf-8")
        updated, count = re.subn(
            pattern,
            lambda m: m.group(0).replace(m.group(1), new),
            text,
            count=1,
            flags=re.MULTILINE,
        )
        assert count == 1, f"{name}: declaration not found on the second pass"
        path.write_text(updated, encoding="utf-8", newline="\n")
        print(f"  {old} -> {new}  {name}")

    print(f"\nNow add a {new} entry at the top of {CHANGELOG}, then:")
    print("  ./packaging/build-deb.sh && ./packaging/build-tarball.sh")
    print("  python packaging/build-windows-guide.py   # regenerate the PDF")
    print("  python packaging/build-windows-zip.py     # the Windows-side archive")
    print(f"  git commit -am 'Release {new}' && git tag -a v{new} -m {new}")
    print(f"  git push origin main && git push origin v{new}")
    print(f"  gh release create v{new} dist/*{new}* --title '{new} — ...'")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) == 1 or argv[1] in ("-h", "--help"):
        print(__doc__.strip())
        return 0
    if argv[1] == "--check":
        return check()
    return bump(argv[1])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
