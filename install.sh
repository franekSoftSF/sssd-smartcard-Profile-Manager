#!/usr/bin/env bash
#
# install.sh -- install sssd-smartcard from a release archive.
#
# Deliberately boring: it uses the distribution's own python3, cryptography and
# PyYAML packages, so nothing is fetched from the internet and nothing lands in
# a pip environment that a system upgrade will later break.

set -Eeuo pipefail

PROGRAM="${0##*/}"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PREFIX="/usr/local"
LIB_DIR="/opt/sssd-smartcard"
CONF_DIR="/etc/sssd-smartcard"
DOC_DIR=""
STATE_DIR="/var/lib/sssd-smartcard"
SHARE_DIR="/usr/share/sssd-smartcard"
DO_DEPS=1
UNINSTALL=0
DRY_RUN=0

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[90m'
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
else
    C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""
fi
pass() { printf '%s[ OK ]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
info() { printf '       %s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }
warn() { printf '%s[WARN]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
die()  { printf '%s[FAIL]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

run() {
    if (( DRY_RUN )); then
        printf '%s  would run:%s %s\n' "$C_DIM" "$C_RESET" "$*"
        return 0
    fi
    "$@"
}

usage() {
    cat <<EOF
$PROGRAM -- install sssd-smartcard

USAGE
  sudo ./$PROGRAM [options]

OPTIONS
  --prefix DIR     Where to put the executables (default $PREFIX)
  --lib-dir DIR    Where to put the Python package (default $LIB_DIR)
  --conf-dir DIR   Where to put the example profiles (default $CONF_DIR)
  --no-deps        Do not install python3-cryptography / python3-yaml
  --dry-run        Print what would happen and change nothing
  --uninstall      Remove everything this script installed
  -h, --help       This text

WHAT IT INSTALLS (the same programs as the .deb)
  \$PREFIX/bin/sssd-smartcard                      the CLI
  \$PREFIX/sbin/sssd-smartcard-setup               guided setup, in stages
  \$PREFIX/sbin/sssd-smartcard-capture             capture a working host, replay it here
  \$PREFIX/sbin/ad-prepare                         DNS and hostname before a join
  \$PREFIX/sbin/ad-reset                           remove one domain from the host
  \$PREFIX/sbin/sssd-smartcard-install-desktop     minimal desktop for greeter tests
  $SHARE_DIR/lib/                 helpers the scripts share
  \$LIB_DIR/src/sssd_smartcard/                    the Python package
  \$CONF_DIR/profiles/                             example profiles
  \$STATE_DIR/                                     generated profiles and backups (mode 0700)
EOF
}

while (( $# )); do
    case "$1" in
        --prefix)    PREFIX="${2:?--prefix needs a path}"; shift ;;
        --lib-dir)   LIB_DIR="${2:?--lib-dir needs a path}"; shift ;;
        --conf-dir)  CONF_DIR="${2:?--conf-dir needs a path}"; shift ;;
        --no-deps)   DO_DEPS=0 ;;
        --dry-run)   DRY_RUN=1 ;;
        --uninstall) UNINSTALL=1 ;;
        -h|--help)   usage; exit 0 ;;
        *) printf 'unknown option: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

DOC_DIR="$PREFIX/share/doc/sssd-smartcard"
BIN="$PREFIX/bin/sssd-smartcard"

# The shell programs, source -> name. Installed under $PREFIX/sbin like the
# package installs them under /usr/sbin; every one of them finds lib/ in
# $SHARE_DIR (a fixed path the scripts search, whatever the prefix).
declare -A PROGRAMS=(
    [scripts/sssd-smartcard-setup.sh]=sssd-smartcard-setup
    [scripts/sssd-smartcard-capture.sh]=sssd-smartcard-capture
    [scripts/ad-prepare.sh]=ad-prepare
    [scripts/ad-reset.sh]=ad-reset
    [scripts/install-desktop.sh]=sssd-smartcard-install-desktop
)

[[ "$(id -u)" == "0" ]] || die "run this as root (sudo ./$PROGRAM)"

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
if (( UNINSTALL )); then
    printf '%s%s: uninstalling%s\n' "$C_BOLD" "$PROGRAM" "$C_RESET"
    for path in "$BIN" "${PROGRAMS[@]/#/$PREFIX/sbin/}" "$LIB_DIR" "$DOC_DIR" "$SHARE_DIR/lib"; do
        if [[ -e "$path" ]]; then
            run rm -rf "$path"
            pass "removed $path"
        fi
    done
    if [[ -d "$CONF_DIR" ]]; then
        warn "left $CONF_DIR in place (it may hold profiles you wrote)"
    fi
    if [[ -d "$STATE_DIR" ]]; then
        warn "left $STATE_DIR in place (it holds configuration backups)"
    fi
    info "sssd.conf, the CA bundle and PAM were never touched by this installer"
    exit 0
fi

printf '%s%s: installing sssd-smartcard%s\n' "$C_BOLD" "$PROGRAM" "$C_RESET"

# ---------------------------------------------------------------------------
# Sanity
# ---------------------------------------------------------------------------
[[ -d "$SOURCE_DIR/src/sssd_smartcard" ]] \
    || die "$SOURCE_DIR does not look like a release archive (no src/sssd_smartcard)"

command -v python3 >/dev/null 2>&1 || die "python3 is required"
PYVER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
pass "python3 $PYVER"
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' \
    || die "python 3.10 or newer is required (found $PYVER)"

# ---------------------------------------------------------------------------
# Dependencies, from distribution packages
# ---------------------------------------------------------------------------
distro_family() {
    local id="" like=""
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        id="${ID:-}"; like="${ID_LIKE:-}"
    fi
    case "$id" in
        ubuntu|debian|linuxmint|pop) echo debian; return ;;
        rhel|centos|fedora|rocky|almalinux|ol) echo rhel; return ;;
        opensuse*|sles) echo suse; return ;;
    esac
    case " $like " in
        *" debian "*) echo debian ;;
        *" rhel "*|*" fedora "*) echo rhel ;;
        *" suse "*) echo suse ;;
        *) echo unknown ;;
    esac
}

missing_python_modules() {
    local missing=()
    python3 -c 'import cryptography' 2>/dev/null || missing+=("cryptography")
    python3 -c 'import yaml' 2>/dev/null || missing+=("yaml")
    printf '%s\n' "${missing[@]+"${missing[@]}"}"
}

if (( DO_DEPS )); then
    mapfile -t MISSING < <(missing_python_modules)
    if (( ${#MISSING[@]} == 0 )); then
        pass "python dependencies present (cryptography, PyYAML)"
    else
        FAMILY="$(distro_family)"
        info "missing python modules: ${MISSING[*]}"
        case "$FAMILY" in
            debian)
                run env DEBIAN_FRONTEND=noninteractive apt-get update -qq || true
                run env DEBIAN_FRONTEND=noninteractive apt-get install -y \
                    python3-cryptography python3-yaml \
                    || die "could not install python3-cryptography / python3-yaml"
                ;;
            rhel)
                PKG="$(command -v dnf >/dev/null 2>&1 && echo dnf || echo yum)"
                run "$PKG" install -y python3-cryptography python3-pyyaml \
                    || die "could not install python3-cryptography / python3-pyyaml"
                ;;
            suse)
                run zypper --non-interactive install python3-cryptography python3-PyYAML \
                    || die "could not install the python dependencies"
                ;;
            *)
                die "unknown distribution: install python3 cryptography and PyYAML yourself, then re-run with --no-deps"
                ;;
        esac
        if (( ! DRY_RUN )); then
            mapfile -t MISSING < <(missing_python_modules)
            (( ${#MISSING[@]} == 0 )) || die "still missing: ${MISSING[*]}"
        fi
        pass "python dependencies installed"
    fi
else
    info "--no-deps: dependency check skipped"
fi

# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------
run install -d -m 0755 "$LIB_DIR" "$PREFIX/bin" "$PREFIX/sbin" "$DOC_DIR" "$CONF_DIR/profiles"
run install -d -m 0700 "$STATE_DIR"

if (( ! DRY_RUN )); then
    rm -rf "$LIB_DIR/src"
fi
run cp -a "$SOURCE_DIR/src" "$LIB_DIR/src"
# Byte-compilation is optional; a failure must not fail the install.
run python3 -m compileall -q "$LIB_DIR/src/sssd_smartcard" >/dev/null 2>&1 || true
pass "python package -> $LIB_DIR/src"

if (( DRY_RUN )); then
    info "would write $BIN"
else
    cat >"$BIN" <<EOF
#!/usr/bin/env bash
# sssd-smartcard launcher, written by install.sh
exec env PYTHONPATH="$LIB_DIR/src\${PYTHONPATH:+:\$PYTHONPATH}" \\
    python3 -m sssd_smartcard "\$@"
EOF
    chmod 0755 "$BIN"
fi
pass "CLI -> $BIN"

for src in "${!PROGRAMS[@]}"; do
    if [[ -f "$SOURCE_DIR/$src" ]]; then
        run install -m 0755 "$SOURCE_DIR/$src" "$PREFIX/sbin/${PROGRAMS[$src]}"
        pass "${PROGRAMS[$src]} -> $PREFIX/sbin/${PROGRAMS[$src]}"
    else
        warn "missing from the archive: $src"
    fi
done
run install -d -m 0755 "$SHARE_DIR/lib"
for f in env.sh env.py capture.py; do
    mode=0644; [[ "$f" == *.py ]] && mode=0755
    [[ -f "$SOURCE_DIR/scripts/lib/$f" ]] && run install -m "$mode" "$SOURCE_DIR/scripts/lib/$f" "$SHARE_DIR/lib/$f"
done
pass "shared helpers -> $SHARE_DIR/lib"

for f in README.md DEPLOY.md docs/STEP-BY-STEP.md docs/STEP-BY-STEP.pl.md docs/sssd-reference.md docs/COMMANDS.md; do
    [[ -f "$SOURCE_DIR/$f" ]] && run install -m 0644 "$SOURCE_DIR/$f" "$DOC_DIR/$(basename "$f")"
done
[[ -d "$SOURCE_DIR/lab" ]] && run cp -a "$SOURCE_DIR/lab" "$DOC_DIR/lab" || true
pass "documentation -> $DOC_DIR"

if [[ -d "$SOURCE_DIR/profiles" ]]; then
    shopt -s nullglob
    for p in "$SOURCE_DIR"/profiles/*.yaml "$SOURCE_DIR"/profiles/*.yml; do
        dest="$CONF_DIR/profiles/$(basename "$p")"
        if [[ -e "$dest" ]]; then
            info "keeping your $dest"
        else
            run install -m 0644 "$p" "$dest"
        fi
    done
    shopt -u nullglob
    pass "example profiles -> $CONF_DIR/profiles"
fi

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
if (( ! DRY_RUN )); then
    if ! "$BIN" --version >/dev/null 2>&1; then
        die "the installed CLI does not run: $BIN --version failed"
    fi
    pass "installed: $("$BIN" --version)"
    if ! "$BIN" profile list >/dev/null 2>&1; then
        warn "'sssd-smartcard profile list' failed; the install may be incomplete"
    fi
fi

cat <<EOF

${C_BOLD}Installed.${C_RESET} Next:

  # See exactly what would be configured, change nothing:
  sudo sssd-smartcard-setup --dry-run \\
       --test-user jan.kowalski@domain-a.local \\
       --ca /root/pki/root-ca.pem --ca /root/pki/issuing-ca.pem

  # Inspect a card and let the tool derive the configuration:
  sssd-smartcard cert inspect --from-card

  # Diagnose an existing setup:
  sudo sssd-smartcard doctor --user jan.kowalski@domain-a.local

Docs: $DOC_DIR/README.md
EOF
