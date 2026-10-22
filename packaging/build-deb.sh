#!/usr/bin/env bash
#
# build-deb.sh -- build sssd-smartcard_<version>_all.deb with dpkg-deb alone.
#
# Why this exists next to debian/: the canonical route is
#
#     dpkg-buildpackage -b -us -uc
#
# which needs debhelper, dh-python and pybuild. This script needs only dpkg-deb,
# which every Debian or Ubuntu system already has, and it does not need root or
# fakeroot (dpkg-deb --root-owner-group handles ownership). That makes it usable
# inside a plain WSL Ubuntu or a minimal container.
#
# There is deliberately no "build a .deb without dpkg" fallback. Hand-rolling
# the ar archive is easy to get subtly wrong, and a package that installs
# incorrectly on a server is worse than no package. Run this under WSL, a
# container, or the target host itself.
#
# Metadata is read from debian/control and debian/changelog, so this script and
# the debhelper route can never drift apart.

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"
PKGNAME="sssd-smartcard"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[90m'
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
else
    C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""
fi
step() { printf '\n%s==>%s %s\n' "$C_BOLD" "$C_RESET" "$*"; }
ok()   { printf '%s[ OK ]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
info() { printf '       %s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }
warn() { printf '%s[WARN]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
die()  { printf '%s[FAIL]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
step "Checking the build environment"
# ---------------------------------------------------------------------------
command -v dpkg-deb >/dev/null 2>&1 || die "$(cat <<'MSG'
dpkg-deb was not found, so a .deb cannot be built here.

Build it where dpkg lives:
  Windows + WSL : wsl -d Ubuntu -- bash /mnt/c/path/to/packaging/build-deb.sh
  container     : podman run --rm -v "$PWD":/src -w /src ubuntu:24.04 \
                      bash packaging/build-deb.sh
  target host   : bash packaging/build-deb.sh
MSG
)"
DPKG_DEB_VERSION="$(dpkg-deb --version | head -1)"
ok "$DPKG_DEB_VERSION"

# --root-owner-group landed in dpkg 1.19; without it the archive would record
# the building user and lintian would complain.
if dpkg-deb --help 2>&1 | grep -q -- "--root-owner-group"; then
    ROOT_OWNER_ARGS=(--root-owner-group)
    ok "using --root-owner-group (no root or fakeroot needed)"
elif [[ "$(id -u)" == "0" ]]; then
    ROOT_OWNER_ARGS=()
    warn "this dpkg-deb has no --root-owner-group; relying on running as root"
else
    die "this dpkg-deb has no --root-owner-group and you are not root; install a newer dpkg or use fakeroot"
fi

command -v gzip >/dev/null 2>&1 || die "gzip is required"
command -v python3 >/dev/null 2>&1 || warn "python3 not found; the post-build functional check will be skipped"

# ---------------------------------------------------------------------------
step "Reading metadata from debian/"
# ---------------------------------------------------------------------------
CHANGELOG="$ROOT/debian/changelog"
CONTROL_IN="$ROOT/debian/control"
[[ -f "$CHANGELOG" ]] || die "missing $CHANGELOG"
[[ -f "$CONTROL_IN" ]] || die "missing $CONTROL_IN"

VERSION="$(sed -n '1s/^[^(]*(\([^)]*\)).*/\1/p' "$CHANGELOG")"
[[ -n "$VERSION" ]] || die "could not read the version from the first line of debian/changelog"
ok "version $VERSION"

# The version in debian/changelog is authoritative; make sure the Python
# package agrees, because __version__ is what --version prints.
PY_VERSION="$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' "$ROOT/src/sssd_smartcard/__init__.py" | head -1)"
if [[ "$PY_VERSION" != "${VERSION%%-*}" ]]; then
    die "version mismatch: debian/changelog says $VERSION but src/sssd_smartcard/__init__.py says $PY_VERSION"
fi
ok "src/sssd_smartcard/__init__.py agrees ($PY_VERSION)"

for script in scripts/sssd-smartcard-setup.sh scripts/ad-prepare.sh \
              scripts/install-desktop.sh scripts/ad-reset.sh \
              scripts/sssd-smartcard-capture.sh; do
    script_version=$(awk -F'"' '/^VERSION=/ {print $2; exit}' "$ROOT/$script")
    [[ "$script_version" == "$VERSION" ]]         || die "$script reports $script_version, expected $VERSION"
done
ok "shell scripts agree ($VERSION)"

ARCH="$(dpkg --print-architecture 2>/dev/null || echo all)"
# This package is pure Python and architecture independent.
DEB_ARCH="all"
info "building for Architecture: $DEB_ARCH (host is $ARCH)"

MAINTAINER="${DEB_MAINTAINER:-$(
    awk '/^Maintainer:/ { sub(/^Maintainer:[[:space:]]*/, ""); print; exit }' "$CONTROL_IN"
)}"
[[ -n "$MAINTAINER" ]] || die "no Maintainer in debian/control and DEB_MAINTAINER is unset"
info "maintainer: $MAINTAINER"

DEB_BASENAME="${PKGNAME}_${VERSION}_${DEB_ARCH}.deb"
DEB="$DIST/$DEB_BASENAME"

# Stage on a native filesystem, never inside the repository. A Windows drive
# mounted into WSL (drvfs) reports every file as mode 777 and silently ignores
# chmod, so staging there would produce a package with world-writable Python
# files -- and dpkg-deb refuses the control directory outright, which is how
# this was caught.
BUILD_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/sssd-smartcard-deb.XXXXXX")"
CHECK_ROOT=""
cleanup() { rm -rf "$BUILD_ROOT" ${CHECK_ROOT:+"$CHECK_ROOT"}; }
trap cleanup EXIT
STAGE="$BUILD_ROOT/${PKGNAME}_${VERSION}_${DEB_ARCH}"
mkdir -p "$STAGE/DEBIAN"
chmod 0755 "$STAGE" "$STAGE/DEBIAN"

# Prove the staging filesystem honours modes before building anything on it.
: >"$BUILD_ROOT/.modetest"
chmod 0644 "$BUILD_ROOT/.modetest"
MODETEST="$(stat -c '%a' "$BUILD_ROOT/.modetest")"
rm -f "$BUILD_ROOT/.modetest"
[[ "$MODETEST" == "644" ]] || die "$(cat <<MSG
$BUILD_ROOT does not honour file permissions (chmod 0644 produced $MODETEST).

Set TMPDIR to a native Linux filesystem and try again, for example:
  TMPDIR=/var/tmp bash packaging/build-deb.sh
MSG
)"
info "staging in $STAGE"
rm -f "$DEB" "$DEB.sha256"

# ---------------------------------------------------------------------------
step "Running the test suite"
# ---------------------------------------------------------------------------
# A package that ships a broken certmap renderer is worse than no package.
if [[ "${SKIP_TESTS:-0}" == "1" ]]; then
    warn "SKIP_TESTS=1: the test suite was not run"
elif python3 -c 'import pytest' >/dev/null 2>&1; then
    ( cd "$ROOT" && PYTHONPATH=src python3 -m pytest -q tests ) \
        || die "the test suite failed; refusing to build a package"
    ok "test suite passed"
else
    warn "python3-pytest is not installed; tests were not run"
    info "install it with: apt-get install -y python3-pytest"
fi

# ---------------------------------------------------------------------------
step "Staging the file tree"
# ---------------------------------------------------------------------------

# Debian's python3 adds /usr/lib/python3/dist-packages to sys.path for every
# python3 minor version, which is exactly what an arch-independent pure-Python
# package wants.
DISTPKG="$STAGE/usr/lib/python3/dist-packages"
install -d "$DISTPKG"
cp -a "$ROOT/src/sssd_smartcard" "$DISTPKG/"
find "$DISTPKG" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$DISTPKG" -name '*.py[co]' -delete 2>/dev/null || true
find "$DISTPKG" -type d -exec chmod 0755 {} +
find "$DISTPKG" -type f -exec chmod 0644 {} +
ok "python package -> /usr/lib/python3/dist-packages/sssd_smartcard"

# The entry point, as setuptools would generate it.
install -d "$STAGE/usr/bin"
cat >"$STAGE/usr/bin/$PKGNAME" <<'PYEOF'
#!/usr/bin/python3
"""Entry point for sssd-smartcard."""
import sys

from sssd_smartcard.cli import main

if __name__ == "__main__":
    sys.exit(main())
PYEOF
chmod 0755 "$STAGE/usr/bin/$PKGNAME"
ok "CLI -> /usr/bin/$PKGNAME"

install -D -m 0755 "$ROOT/scripts/sssd-smartcard-setup.sh" \
    "$STAGE/usr/sbin/sssd-smartcard-setup"
ok "setup script -> /usr/sbin/sssd-smartcard-setup"

install -D -m 0755 "$ROOT/scripts/ad-prepare.sh" \
    "$STAGE/usr/sbin/ad-prepare"
ok "DNS/hostname script -> /usr/sbin/ad-prepare"

install -D -m 0755 "$ROOT/scripts/install-desktop.sh" \
    "$STAGE/usr/sbin/sssd-smartcard-install-desktop"
ok "desktop installer -> /usr/sbin/sssd-smartcard-install-desktop"

install -D -m 0755 "$ROOT/scripts/ad-reset.sh" "$STAGE/usr/sbin/ad-reset"
ok "domain reset -> /usr/sbin/ad-reset"

install -D -m 0755 "$ROOT/scripts/sssd-smartcard-capture.sh" \
    "$STAGE/usr/sbin/sssd-smartcard-capture"
ok "capture/replay -> /usr/sbin/sssd-smartcard-capture"

# Shared environment-file helpers the scripts source at runtime.
install -D -m 0644 "$ROOT/scripts/lib/env.sh" \
    "$STAGE/usr/share/sssd-smartcard/lib/env.sh"
install -D -m 0755 "$ROOT/scripts/lib/env.py" \
    "$STAGE/usr/share/sssd-smartcard/lib/env.py"
install -D -m 0755 "$ROOT/scripts/lib/capture.py" \
    "$STAGE/usr/share/sssd-smartcard/lib/capture.py"
ok "environment helpers -> /usr/share/sssd-smartcard/lib"

# Examples under /usr/share, not /etc: no conffiles means dpkg never prompts
# about a modified example on upgrade. Administrator profiles go in /etc and
# are searched first.
install -d "$STAGE/usr/share/$PKGNAME/profiles"
install -m 0644 "$ROOT"/profiles/*.yaml "$STAGE/usr/share/$PKGNAME/profiles/"
install -d -m 0755 "$STAGE/etc/sssd-smartcard/profiles"
install -d -m 0700 "$STAGE/var/lib/$PKGNAME"
ok "$(ls -1 "$STAGE/usr/share/$PKGNAME/profiles" | wc -l | tr -d ' ') example profiles -> /usr/share/$PKGNAME/profiles"

# Manual pages, gzipped without a timestamp so builds are reproducible.
install -d "$STAGE/usr/share/man/man8"
for page in "$ROOT"/man/*.8; do
    [[ -f "$page" ]] || continue
    gzip -9nc "$page" >"$STAGE/usr/share/man/man8/$(basename "$page").gz"
    chmod 0644 "$STAGE/usr/share/man/man8/$(basename "$page").gz"
done
ok "man pages -> /usr/share/man/man8 ($(ls -1 "$STAGE/usr/share/man/man8" | tr '\n' ' '))"

# Documentation. changelog.Debian.gz and copyright are required by policy.
DOC="$STAGE/usr/share/doc/$PKGNAME"
install -d "$DOC"
install -m 0644 "$ROOT/README.md" "$DOC/README.md"
install -m 0644 "$ROOT/docs/sssd-reference.md" "$DOC/sssd-reference.md"
install -m 0644 "$ROOT/DEPLOY.md" "$DOC/DEPLOY.md"
install -m 0644 "$ROOT/docs/COMMANDS.md" "$DOC/COMMANDS.md"
install -m 0644 "$ROOT/docs/HOW-IT-WORKS.md" "$DOC/HOW-IT-WORKS.md"
install -m 0644 "$ROOT/docs/STEP-BY-STEP.md" "$DOC/STEP-BY-STEP.md"
install -m 0644 "$ROOT/docs/STEP-BY-STEP.pl.md" "$DOC/STEP-BY-STEP.pl.md"
install -m 0644 "$ROOT/debian/copyright" "$DOC/copyright"
gzip -9nc "$CHANGELOG" >"$DOC/changelog.Debian.gz"
chmod 0644 "$DOC/changelog.Debian.gz"

install -d "$DOC/lab/provision"
install -m 0644 "$ROOT/lab/Vagrantfile" "$ROOT/lab/README.md" "$DOC/lab/"
install -m 0755 "$ROOT/lab/run-tests.sh" "$DOC/lab/"
install -m 0755 "$ROOT/lab/provision/dc.sh" "$ROOT/lab/provision/client.sh" \
    "$DOC/lab/provision/"
ok "documentation and test lab -> /usr/share/doc/$PKGNAME"

# ---------------------------------------------------------------------------
step "Generating DEBIAN/control"
# ---------------------------------------------------------------------------
# Take the binary package stanza out of debian/control verbatim, so Depends,
# Recommends, Suggests and the description have exactly one source of truth.
# Then drop the debhelper substitution variables, which only dh can expand.
INSTALLED_SIZE="$(du -ks --exclude=DEBIAN "$STAGE" | cut -f1)"

DEB_VERSION="$VERSION" DEB_ARCH="$DEB_ARCH" DEB_MAINT="$MAINTAINER" \
DEB_SIZE="$INSTALLED_SIZE" python3 - "$CONTROL_IN" >"$STAGE/DEBIAN/control" <<'PY'
"""Turn debian/control's binary stanza into a DEBIAN/control for dpkg-deb.

Parsing deb822 properly matters here: a relationship field is a comma separated
list, and naively stripping line-end commas (to clean up after removing the
debhelper substitution variables) silently produces
``Depends: python3 (>= 3.10)\n python3-cryptography``, which dpkg-deb rejects
as a syntax error.
"""

import os
import re
import sys

#: Fields belonging to the source package, which dpkg-deb must not see.
SOURCE_ONLY = {"Source", "Build-Depends", "Build-Depends-Indep",
               "Standards-Version", "Rules-Requires-Root", "Homepage",
               "Vcs-Git", "Vcs-Browser", "Testsuite", "Uploaders"}

#: Comma separated lists that need re-joining after items are dropped.
RELATION_FIELDS = {"Depends", "Pre-Depends", "Recommends", "Suggests",
                   "Enhances", "Breaks", "Conflicts", "Provides", "Replaces"}

#: Field order dpkg and policy expect to see near the top.
ORDER = ["Package", "Version", "Architecture", "Section", "Priority",
         "Maintainer", "Installed-Size", "Depends", "Pre-Depends",
         "Recommends", "Suggests", "Enhances", "Breaks", "Conflicts",
         "Provides", "Replaces", "Description"]


def parse_stanzas(text):
    """Yield ``[(field, value)]`` per blank-line separated stanza."""
    for block in re.split(r"\n\s*\n", text):
        if not block.strip():
            continue
        fields, current = [], None
        for line in block.split("\n"):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if line[0] in " \t" and current is not None:
                # Continuation of the previous field.
                fields[-1] = (fields[-1][0], fields[-1][1] + "\n" + line)
                continue
            name, _, value = line.partition(":")
            current = name.strip()
            fields.append((current, value.strip()))
        yield fields


with open(sys.argv[1], encoding="utf-8") as handle:
    stanzas = list(parse_stanzas(handle.read()))

binary = next(s for s in stanzas if any(name == "Package" for name, _ in s))

overrides = {
    "Version": os.environ["DEB_VERSION"],
    "Architecture": os.environ["DEB_ARCH"],
    "Maintainer": os.environ["DEB_MAINT"],
    "Installed-Size": os.environ["DEB_SIZE"],
    "Section": "admin",
    "Priority": "optional",
}

result = {}
for name, value in binary:
    if name in SOURCE_ONLY:
        continue
    if name in RELATION_FIELDS:
        items = []
        for item in value.replace("\n", " ").split(","):
            item = " ".join(item.split())
            # Only dh can expand ${python3:Depends} and ${misc:Depends}.
            if not item or "${" in item:
                continue
            if item not in items:
                items.append(item)
        if not items:
            continue
        value = ",\n ".join(items)
    result[name] = value

result.update(overrides)

lines = []
for name in ORDER:
    if name in result:
        lines.append(f"{name}: {result.pop(name)}")
# Anything the order list did not mention keeps its relative position at the end.
for name, value in result.items():
    lines.append(f"{name}: {value}")

print("\n".join(lines))
PY

chmod 0644 "$STAGE/DEBIAN/control"
ok "DEBIAN/control generated from debian/control"
sed 's/^/       /' "$STAGE/DEBIAN/control" | head -20

# ---------------------------------------------------------------------------
step "Maintainer scripts and md5sums"
# ---------------------------------------------------------------------------
for script in postinst postrm; do
    [[ -f "$ROOT/debian/$script" ]] || continue
    # #DEBHELPER# is a dh placeholder; without dh there is nothing to put there.
    sed '/^#DEBHELPER#$/d' "$ROOT/debian/$script" >"$STAGE/DEBIAN/$script"
    chmod 0755 "$STAGE/DEBIAN/$script"
    sh -n "$STAGE/DEBIAN/$script" || die "DEBIAN/$script is not valid shell"
    ok "DEBIAN/$script"
done

( cd "$STAGE" && find . -type f ! -path './DEBIAN/*' -printf '%P\0' \
    | sort -z | xargs -0 md5sum >DEBIAN/md5sums )
chmod 0644 "$STAGE/DEBIAN/md5sums"
ok "DEBIAN/md5sums ($(wc -l <"$STAGE/DEBIAN/md5sums" | tr -d ' ') files)"

# ---------------------------------------------------------------------------
step "Building the package"
# ---------------------------------------------------------------------------
mkdir -p "$DIST"
dpkg-deb "${ROOT_OWNER_ARGS[@]}" --build "$STAGE" "$DEB" >/dev/null \
    || die "dpkg-deb failed"
ok "built $DEB ($(( $(wc -c <"$DEB") / 1024 )) KiB)"

if command -v sha256sum >/dev/null 2>&1; then
    ( cd "$DIST" && sha256sum "$(basename "$DEB")" >"$(basename "$DEB").sha256" )
    info "sha256: $(cut -d' ' -f1 <"$DEB.sha256")"
fi

# ---------------------------------------------------------------------------
step "Verifying the package"
# ---------------------------------------------------------------------------
dpkg-deb --info "$DEB" >/dev/null || die "dpkg-deb --info rejected the package"
ok "dpkg-deb --info accepts it"

# Every path the package claims to ship must really be there. The listing is
# taken once into a file: piping dpkg-deb into `grep -q` makes grep exit early,
# dpkg-deb die of SIGPIPE, and pipefail report a failure that is not one.
CONTENTS="$BUILD_ROOT/contents.txt"
dpkg-deb --contents "$DEB" >"$CONTENTS"
for path in \
    ./usr/bin/sssd-smartcard \
    ./usr/sbin/sssd-smartcard-setup \
    ./usr/sbin/ad-prepare \
    ./usr/sbin/sssd-smartcard-install-desktop \
    ./usr/sbin/ad-reset \
    ./usr/share/sssd-smartcard/lib/env.sh \
    ./usr/share/sssd-smartcard/lib/env.py \
    ./usr/lib/python3/dist-packages/sssd_smartcard/cli.py \
    ./usr/lib/python3/dist-packages/sssd_smartcard/platform.py \
    ./usr/share/sssd-smartcard/profiles/AD-PIV-UPN.yaml \
    ./usr/share/man/man8/sssd-smartcard.8.gz \
    ./usr/share/man/man8/sssd-smartcard-setup.8.gz \
    ./usr/share/doc/sssd-smartcard/copyright \
    ./usr/share/doc/sssd-smartcard/changelog.Debian.gz \
    ./usr/share/doc/sssd-smartcard/HOW-IT-WORKS.md
do
    grep -q "[[:space:]]${path}\$" "$CONTENTS" \
        || die "the package is missing $path"
done
ok "all expected paths are present"

# Modes, which is the thing a drvfs staging directory silently destroys.
check_mode() {
    local want="$1" path="$2" got
    got="$(awk -v p="$path" '$NF == p { print $1 }' "$CONTENTS" | head -1)"
    [[ -n "$got" ]] || die "$path is not in the package"
    [[ "$got" == "$want" ]] || die "$path has mode $got, expected $want"
}
check_mode "-rwxr-xr-x" "./usr/bin/sssd-smartcard"
check_mode "-rwxr-xr-x" "./usr/sbin/sssd-smartcard-setup"
check_mode "-rw-r--r--" "./usr/lib/python3/dist-packages/sssd_smartcard/cli.py"
check_mode "drwx------" "./var/lib/sssd-smartcard/"
ok "file modes are correct (executables 0755, modules 0644, state dir 0700)"

# Ownership must be root:root, not the building user.
if grep -vq " root/root " "$CONTENTS" 2>/dev/null; then
    BAD_OWNER="$(awk '$2 != "root/root" { print $NF; exit }' "$CONTENTS")"
    [[ -z "$BAD_OWNER" ]] || die "$BAD_OWNER is not owned by root:root"
fi
ok "everything is owned by root:root"

# Unpack into a throwaway root and actually run the thing.
if command -v python3 >/dev/null 2>&1; then
    CHECK="$(mktemp -d "${TMPDIR:-/tmp}/sssd-smartcard-check.XXXXXX")"
    CHECK_ROOT="$CHECK"
    dpkg-deb -x "$DEB" "$CHECK"
    if PYTHONPATH="$CHECK/usr/lib/python3/dist-packages" \
            python3 -c 'from sssd_smartcard.cli import main; import sssd_smartcard; print(sssd_smartcard.__version__)' \
            >"$CHECK/ver" 2>"$CHECK/err"; then
        ok "the packaged module imports and reports $(cat "$CHECK/ver")"
    else
        die "the packaged module does not import: $(cat "$CHECK/err")"
    fi
    if PYTHONPATH="$CHECK/usr/lib/python3/dist-packages" \
            SSSD_SMARTCARD_PROFILES="$CHECK/usr/share/sssd-smartcard/profiles" \
            python3 -m sssd_smartcard profile validate --no-color >"$CHECK/val" 2>&1; then
        ok "the packaged example profiles all validate"
    else
        warn "profile validate reported problems from the packaged tree:"
        sed 's/^/       /' "$CHECK/val" | head -12
    fi
fi

if command -v lintian >/dev/null 2>&1; then
    step "lintian"
    lintian --no-tag-display-limit "$DEB" 2>&1 | sed 's/^/       /' || true
else
    info "lintian is not installed; skipping the policy check"
    info "install it for a fuller review: apt-get install -y lintian"
fi

# ---------------------------------------------------------------------------
cat <<EOF

${C_BOLD}Done.${C_RESET} $DEB

  Install:    sudo apt install $DEB
              (apt pulls in the Recommends: sssd, opensc, pcscd and friends)
  Or:         sudo dpkg -i $DEB && sudo apt-get -f install
  Inspect:    dpkg-deb --info $DEB
              dpkg-deb --contents $DEB
  Remove:     sudo apt remove sssd-smartcard
  Purge:      sudo apt purge sssd-smartcard

  Then:       sssd-smartcard cert inspect --from-card
              sudo sssd-smartcard-setup --dry-run --test-user user@domain-a.local
              man 8 sssd-smartcard-setup
EOF
