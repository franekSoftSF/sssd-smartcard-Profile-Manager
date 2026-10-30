#!/usr/bin/env bash
#
# sssd-smartcard-capture -- take the Smart Card configuration of a working
# machine, and reproduce it on a new one.
#
#   --from [user@]host   collect on another machine over SSH (sudo there)
#   --local              collect on this machine
#   --show CAPTURE       what a capture contains, in one page
#   --replay CAPTURE     reproduce it here (a plan by default; --yes applies)
#
# Rules, the same as everywhere else in this project:
#
#   1. Collecting is read-only. Nothing on the source machine is changed, and
#      only a temporary directory is left behind until the copy is verified.
#   2. Secrets are never collected: no keytab, no SSSD cache, no private keys,
#      no SSH host keys, and the values of options whose names say "password"
#      are blanked. Certificates and CRLs are public and are collected.
#   3. The replay never copies a file over blindly. It drives
#      sssd-smartcard-setup -- backups, validation and rollback included -- and
#      lists whatever it did not reproduce, with the diff command for each.
#   4. The domain join is not copied. A keytab belongs to one machine; the new
#      host joins under its own name (ad-prepare, then setup's join stage).

set -Eeuo pipefail

if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
    printf 'this script needs bash 4.4 or newer (found %s)\n' "${BASH_VERSION}" >&2
    exit 1
fi

VERSION="0.3.5"
PROGRAM="${0##*/}"
SELF="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
STATE_DIR="/var/lib/sssd-smartcard"

MODE=""
TARGET=""
SSH_PORT=""
SSH_KEY=""
OUT=""
ROOT="/"
CAPTURE=""
ASSUME_YES=0
DO_PAM=0
FORCE=0

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[90m'
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'
else
    C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""
fi
pass() { printf '%s[ OK ]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
info() { printf '%s[INFO]%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
fail() { printf '%s[FAIL]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
note() { printf '       %s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }
die()  { fail "$*"; exit 1; }
heading() { printf '\n%s=== %s ===%s\n' "$C_BOLD" "$*" "$C_RESET"; }

usage() {
    cat <<EOF
$PROGRAM $VERSION -- capture a working Smart Card setup and reproduce it

USAGE
  $PROGRAM --from [user@]host [-p PORT] [-i KEY] [--out FILE]
  sudo $PROGRAM --local [--out FILE]
  $PROGRAM --show CAPTURE
  sudo $PROGRAM --replay CAPTURE [--yes] [--pam] [--force]

COLLECT
  --from HOST       Collect on HOST over SSH. One SSH login is reused for every
                    step; sudo on HOST asks for its password once. HOST needs
                    only bash, tar and sudo -- not this tool.
  -p, --port PORT   SSH port.
  -i, --identity F  SSH private key (or rely on ssh-agent / ~/.ssh/config).
  --local           Collect on this machine (as root).
  --out FILE        Archive to write (default ./sssd-smartcard-capture-<host>-<date>.tar.gz).

READ
  --show CAPTURE    Summary of a capture (archive or directory): domain, CA,
                    CRL, certmap, PAM mode, SSH, sudo, and the replay command.

REPRODUCE (on the new host, after it has joined the domain)
  --replay CAPTURE  Plan: what sssd-smartcard-setup would do, run with --dry-run.
  --yes             Apply it.
  --pam             Let setup change PAM (pam-auth-update, /etc/pam.d/sudo).
  --force           Replay into a different domain than the one captured.

NEVER COLLECTED
  /etc/krb5.keytab, /var/lib/sss (cache), *.key, SSH host keys, /etc/shadow,
  and the values of sssd.conf options named *password*, *authtok*, *secret*.

THE WHOLE MOVE, OLD HOST -> NEW DEBIAN 13
  $PROGRAM --from admin@old-host --out old.tar.gz      # anywhere with ssh
  sudo $PROGRAM --replay old.tar.gz                    # new host: writes the
                                                       # environment file, says what next
  sudo ad-prepare --yes
  sudo sssd-smartcard-setup --only packages,join,identity --yes
  sudo $PROGRAM --replay old.tar.gz                    # the plan
  sudo $PROGRAM --replay old.tar.gz --yes --pam        # apply
EOF
}

while (( $# )); do
    case "$1" in
        --from) MODE=from; TARGET="${2:?--from needs [user@]host}"; shift ;;
        --local) MODE=local ;;
        --show) MODE=show; CAPTURE="${2:?--show needs a capture}"; shift ;;
        --replay) MODE=replay; CAPTURE="${2:?--replay needs a capture}"; shift ;;
        -p|--port) SSH_PORT="${2:?--port needs a number}"; shift ;;
        -i|--identity) SSH_KEY="${2:?--identity needs a file}"; shift ;;
        --out) OUT="${2:?--out needs a path}"; shift ;;
        --root) ROOT="${2:?--root needs a directory}"; shift ;;   # tests: read files from ROOT
        --yes|-y) ASSUME_YES=1 ;;
        --pam) DO_PAM=1 ;;
        --force) FORCE=1 ;;
        -h|--help) usage; exit 0 ;;
        --version) printf '%s %s\n' "$PROGRAM" "$VERSION"; exit 0 ;;
        *) printf 'unknown option: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done
[[ -n "$MODE" ]] || { usage >&2; exit 2; }

# capture.py: next to this script in a checkout, or the installed location.
capture_py() {
    local c
    for c in "${SELF%/*}/lib/capture.py" /usr/share/sssd-smartcard/lib/capture.py; do
        [[ -r "$c" ]] && { printf '%s\n' "$c"; return 0; }
    done
    return 1
}

# ===========================================================================
# Collect (runs on the machine being captured; bash + coreutils + tar only)
# ===========================================================================

#: Files and directories worth having. Globs are expanded under ROOT.
COLLECT_PATHS=(
    /etc/os-release /etc/hostname /etc/hosts /etc/resolv.conf /etc/nsswitch.conf
    /etc/realmd.conf
    /etc/sssd/sssd.conf '/etc/sssd/conf.d/*'
    '/etc/sssd/pki/*.pem' '/etc/sssd/pki/*.crl' '/etc/sssd/pki/*.crt'
    '/etc/sssd-smartcard/*.json' '/etc/sssd-smartcard/profiles/*'
    '/var/lib/sssd-smartcard/*.yaml' /var/lib/sssd-smartcard/crl-sources.json
    /var/lib/sssd-smartcard/setup-state
    /etc/krb5.conf '/etc/krb5.conf.d/*'
    /etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-session
    /etc/pam.d/common-session-noninteractive /etc/pam.d/common-password
    /etc/pam.d/sudo /etc/pam.d/sudo-i /etc/pam.d/login /etc/pam.d/sshd /etc/pam.d/su
    /etc/pam.d/gdm-smartcard /etc/pam.d/gdm-password /etc/pam.d/lightdm
    /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/smartcard-auth
    /etc/sudoers '/etc/sudoers.d/*'
    /etc/ssh/sshd_config '/etc/ssh/sshd_config.d/*'
    '/etc/systemd/system/sssd-smartcard-*' '/etc/systemd/system/sssd*.service.d/*'
    '/etc/pkcs11/modules/*' /etc/opensc.conf /etc/opensc/opensc.conf
    '/etc/polkit-1/rules.d/*'
    /etc/dconf/profile/gdm '/etc/dconf/db/gdm.d/*' '/etc/dconf/db/local.d/*'
)

#: Never, whatever the globs above match.
REFUSE_PATTERN='(\.keytab$|/var/lib/sss/|\.key$|ssh_host_.*_key|/shadow|secrets\.tdb$)'

# redact < in > out: blank the values of options whose NAMES say they are
# secrets. Exit 10 when something was blanked. POSIX awk (Debian ships mawk).
# krb5_store_password_if_offline is a boolean and says whether credentials are
# cached, so it stays (the same exception as `sssd-smartcard debug bundle`).
redact() {
    awk '
        {
            lower = tolower($0)
            if (match(lower, /^[ \t]*[a-z0-9_]*(authtok|password|passwd|secret|passphrase)[a-z0-9_]*[ \t]*=/)) {
                key = substr(lower, 1, RLENGTH - 1)
                gsub(/[ \t]/, "", key)
                if (key != "krb5_store_password_if_offline") {
                    print substr($0, 1, RLENGTH) " <removed by sssd-smartcard-capture>"
                    blanked = 1
                    next
                }
            }
            print
        }
        END { exit blanked ? 10 : 0 }
    '
}

collect() {
    local dest="$1" path real rel f
    mkdir -p "$dest/files" "$dest/commands"
    chmod 700 "$dest"
    : >"$dest/MANIFEST.txt"
    shopt -s nullglob
    for path in "${COLLECT_PATHS[@]}"; do
        # shellcheck disable=SC2206  # the glob is meant to expand
        local matches=( ${ROOT%/}$path )
        for real in "${matches[@]}"; do
            [[ -f "$real" ]] || continue
            rel="${real#"${ROOT%/}"}"
            if [[ "$rel" =~ $REFUSE_PATTERN ]]; then
                printf 'refused %s\n' "$rel" >>"$dest/MANIFEST.txt"
                continue
            fi
            mkdir -p "$dest/files$(dirname "$rel")"
            f="$dest/files$rel"
            case "$rel" in
                /etc/sssd/sssd.conf|/etc/sssd/conf.d/*)
                    # Keep the option, blank the value: a replay must know a
                    # secret was there without ever carrying it.
                    local rc=0
                    redact <"$real" >"$f" || rc=$?
                    if (( rc == 10 )); then
                        printf 'redacted %s (secret option values)\n' "$rel" >>"$dest/MANIFEST.txt"
                    elif (( rc != 0 )); then
                        return 1
                    fi
                    ;;
                *) cp -p "$real" "$f" ;;
            esac
        done
    done
    shopt -u nullglob
    local p
    for p in /etc/krb5.keytab /var/lib/sss/db /etc/ssh/ssh_host_*_key /etc/shadow; do
        printf 'refused %s (never collected)\n' "$p" >>"$dest/MANIFEST.txt"
    done

    # Read-only commands. Only on the live system: with --root the files are
    # someone else's and the commands would describe this machine instead.
    if [[ "$ROOT" == "/" ]]; then
        cmd() {
            local name="$1"; shift
            command -v "$1" >/dev/null 2>&1 || return 0
            timeout 30 "$@" >"$dest/commands/$name.txt" 2>&1 || true
        }
        cmd sssd-version sssd --version
        cmd sssd-smartcard-version sssd-smartcard --version
        cmd realm-list realm list
        cmd sssctl-domain-list sssctl domain-list
        cmd sssctl-config-check sssctl config-check
        cmd sshd-T sshd -T
        [[ -x /usr/sbin/sshd ]] && ! command -v sshd >/dev/null 2>&1 && cmd sshd-T /usr/sbin/sshd -T
        cmd resolvectl-status resolvectl status
        cmd hostnamectl hostnamectl
        cmd timers systemctl list-timers --all --no-pager
        cmd units systemctl list-unit-files --no-pager 'sssd*' 'pcscd*' 'ssh*'
        cmd packages dpkg-query -W -f '${Package} ${Version} ${Status}\n' \
            sssd sssd-ad sssd-tools libpam-sss libnss-sss realmd adcli opensc opensc-pkcs11 \
            pcscd pcsc-tools p11-kit krb5-user krb5-pkinit libpam-ssh-agent-auth pamtester \
            sudo openssh-server sssd-smartcard
        cmd pam-auth-update-seen cat /var/lib/pam/seen
        cmd debug-status sssd-smartcard debug status
        # Who the sudo rules name, as SSSD resolves them now.
        local g
        for g in $(sed -nE 's/^%([^%#[:space:]][^[:space:]]*).*/\1/p' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sort -u); do
            getent group "${g//\\ / }" >>"$dest/commands/sudo-groups.txt" 2>&1 || \
                printf '%s: does not resolve\n' "$g" >>"$dest/commands/sudo-groups.txt"
        done
    fi

    {
        printf 'host=%s\n' "$(hostname -s 2>/dev/null || cat "${ROOT%/}/etc/hostname" 2>/dev/null || echo unknown)"
        printf 'fqdn=%s\n' "$(hostname -f 2>/dev/null || true)"
        printf 'date=%s\n' "$(date -Iseconds)"
        printf 'version=%s\n' "$VERSION"
        printf 'root=%s\n' "$ROOT"
    } >"$dest/host.txt"

    (cd "$dest" && find files commands host.txt -type f -print0 | sort -z \
        | xargs -0 sha256sum >>MANIFEST.txt)
}

default_out() {
    printf 'sssd-smartcard-capture-%s-%s.tar.gz' "$1" "$(date +%Y%m%d-%H%M%S)"
}

# Add SUMMARY.md and facts.json to an archive, when capture.py is at hand.
annotate() {
    local archive="$1" py tmp
    py="$(capture_py)" || return 0
    command -v python3 >/dev/null 2>&1 || return 0
    tmp="$(mktemp -d)"
    tar -xzf "$archive" -C "$tmp"
    local dir
    dir="$tmp/$(ls "$tmp" | sed -n 1p)"
    python3 "$py" summary "$dir" >"$dir/SUMMARY.md" 2>/dev/null || rm -f "$dir/SUMMARY.md"
    python3 "$py" facts "$dir" >"$dir/facts.json" 2>/dev/null || rm -f "$dir/facts.json"
    tar -czf "$archive" -C "$tmp" "$(basename "$dir")"
    rm -rf "$tmp"
}

mode_local() {
    if [[ "$ROOT" == "/" && "$(id -u)" != "0" ]]; then
        die "collecting needs root: sssd.conf and the sudoers files are readable by root only (sudo $PROGRAM --local)"
    fi
    local host name
    host="$(hostname -s 2>/dev/null || echo host)"
    [[ -n "$OUT" ]] || OUT="$(default_out "$host")"
    name="sssd-smartcard-capture-$host"
    # A global, not a local: the EXIT trap runs after this function returned.
    LOCAL_TMP="$(mktemp -d)"
    trap 'rm -rf "$LOCAL_TMP"' EXIT
    collect "$LOCAL_TMP/$name"
    # umask 077: the archive holds the sudoers and PAM files.
    (umask 077; tar -czf "$OUT" -C "$LOCAL_TMP" "$name")
    annotate "$OUT" || true
    pass "capture written: $OUT ($(grep -cE '^[0-9a-f]{64} ' "$LOCAL_TMP/$name/MANIFEST.txt") files)"
    grep -E '^(refused|redacted) ' "$LOCAL_TMP/$name/MANIFEST.txt" | sed 's/^/       /' || true
}

# ===========================================================================
# --from: run the collector on another machine over SSH
# ===========================================================================
SSH_CTL=""
SSH_OPTS=()
REMOTE_TMP=""
# Globals, not locals: the EXIT trap runs after mode_from has returned.
cleanup_from() {
    if [[ -n "$REMOTE_TMP" ]]; then
        ssh "${SSH_OPTS[@]}" "$TARGET" "rm -rf '$REMOTE_TMP'" >/dev/null 2>&1 || true
    fi
    if [[ -n "$SSH_CTL" ]]; then
        ssh "${SSH_OPTS[@]}" -O exit "$TARGET" >/dev/null 2>&1 || true
        rm -rf "$SSH_CTL"
    fi
}

mode_from() {
    command -v ssh >/dev/null 2>&1 || die "ssh is not installed"
    SSH_CTL="$(mktemp -d)"
    SSH_OPTS=(-o ControlMaster=auto -o "ControlPath=$SSH_CTL/cm" -o ControlPersist=300)
    [[ -n "$SSH_PORT" ]] && SSH_OPTS+=(-p "$SSH_PORT")
    [[ -n "$SSH_KEY" ]] && SSH_OPTS+=(-i "$SSH_KEY")
    trap cleanup_from EXIT
    local -a opts=("${SSH_OPTS[@]}")
    local remote_tmp=""

    heading "Connecting to $TARGET"
    ssh "${opts[@]}" "$TARGET" true || die "cannot log in to $TARGET"
    pass "logged in (the connection is reused for every step)"

    remote_tmp="$(ssh "${opts[@]}" "$TARGET" 'mktemp -d /tmp/sssd-smartcard-capture.XXXXXX')" \
        || die "could not create a temporary directory on $TARGET"
    REMOTE_TMP="$remote_tmp"
    ssh "${opts[@]}" "$TARGET" "cat > '$remote_tmp/capture.sh'" <"$SELF" \
        || die "could not copy the collector to $TARGET"

    heading "Collecting on $TARGET (read-only)"
    note "sudo on $TARGET may ask for a password"
    # -t: sudo needs a terminal for its prompt. The archive is fetched
    # separately, so the terminal never carries binary data.
    ssh -t "${opts[@]}" "$TARGET" "
        if [ \"\$(id -u)\" = 0 ]; then S=; else S=sudo; fi
        \$S bash '$remote_tmp/capture.sh' --local --out '$remote_tmp/capture.tar.gz' \
            && \$S chown \"\$(id -u):\$(id -g)\" '$remote_tmp/capture.tar.gz'
    " || die "collecting on $TARGET failed"

    local host
    host="$(ssh "${opts[@]}" "$TARGET" 'hostname -s' 2>/dev/null || echo "${TARGET#*@}")"
    host="${host//[^A-Za-z0-9._-]/}"
    [[ -n "$OUT" ]] || OUT="$(default_out "$host")"

    local remote_sum local_sum
    remote_sum="$(ssh "${opts[@]}" "$TARGET" "sha256sum '$remote_tmp/capture.tar.gz'" | awk '{print $1}')"
    (umask 077; ssh "${opts[@]}" "$TARGET" "cat '$remote_tmp/capture.tar.gz'" >"$OUT") \
        || die "could not download the capture"
    local_sum="$(sha256sum "$OUT" | awk '{print $1}')"
    [[ -n "$remote_sum" && "$remote_sum" == "$local_sum" ]] \
        || die "the download does not match the remote file (sha256 $local_sum vs $remote_sum)"
    pass "downloaded and verified: $OUT"

    annotate "$OUT" || true
    note "the temporary directory on $TARGET is removed; nothing else there was changed"
    printf '\n'
    printf 'Next: %s --show %s\n' "$PROGRAM" "$OUT"
}

# ===========================================================================
# Reading a capture
# ===========================================================================
CAPTURE_DIR=""
open_capture() {
    if [[ -d "$CAPTURE" ]]; then
        CAPTURE_DIR="$(cd "$CAPTURE" && pwd)"
    elif [[ -f "$CAPTURE" ]]; then
        local base
        if [[ "$(id -u)" == "0" ]]; then
            base="$STATE_DIR/captures"
            mkdir -p "$base"; chmod 700 "$STATE_DIR" "$base"
        else
            base="$(mktemp -d)"
        fi
        local name
        # sed, not head: head closing the pipe early kills tar with SIGPIPE,
        # which pipefail turns into a silent exit 141.
        name="$(tar -tzf "$CAPTURE" | sed -n 1p | cut -d/ -f1)"
        [[ -n "$name" && "$name" != "." && "$name" != ".." ]] || die "$CAPTURE: not a capture archive"
        rm -rf "${base:?}/$name"
        tar -xzf "$CAPTURE" -C "$base"
        CAPTURE_DIR="$base/$name"
    else
        die "$CAPTURE: no such file or directory"
    fi
    [[ -d "$CAPTURE_DIR/files" ]] || die "$CAPTURE: not a capture (no files/ inside)"
    # Verify what was collected against the manifest written at collection time.
    if [[ -f "$CAPTURE_DIR/MANIFEST.txt" ]]; then
        if (cd "$CAPTURE_DIR" && grep -E '^[0-9a-f]{64} ' MANIFEST.txt | sha256sum -c --quiet - >/dev/null 2>&1); then
            pass "capture verified against its manifest"
        else
            die "$CAPTURE: files do not match MANIFEST.txt -- the capture was changed or damaged"
        fi
    fi
}

PY=""
need_py() {
    command -v python3 >/dev/null 2>&1 || die "python3 is needed to read a capture"
    PY="$(capture_py)" || die "capture.py not found (install sssd-smartcard on this machine)"
}

mode_show() {
    need_py
    open_capture
    python3 "$PY" summary "$CAPTURE_DIR"
}

# ===========================================================================
# --replay: reproduce on this host through sssd-smartcard-setup
# ===========================================================================
find_setup() {
    local c
    for c in "$(command -v sssd-smartcard-setup 2>/dev/null || true)" \
             "${SELF%/*}/sssd-smartcard-setup.sh"; do
        [[ -n "$c" && -x "$c" ]] && { printf '%s\n' "$c"; return 0; }
    done
    return 1
}

mode_replay() {
    [[ "$(id -u)" == "0" ]] || die "replaying changes system configuration: run it with sudo"
    need_py
    open_capture
    local setup
    setup="$(find_setup)" || die "sssd-smartcard-setup not found: install sssd-smartcard first"

    heading "Captured"
    python3 "$PY" summary "$CAPTURE_DIR" | sed -n '1,30p' | grep '^|' | sed 's/^/  /' || true

    local cap_domain
    cap_domain="$(python3 - "$PY" "$CAPTURE_DIR" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("capture", sys.argv[1])
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
print(mod.facts(mod.Capture(sys.argv[2]))["domain"])
PY
)"

    # --- 1. The environment file: written once, never overwritten -----------
    heading "Environment file"
    local envfile=/etc/sssd-smartcard/environment.json host
    host="$(hostname -s)"
    if [[ -e "$envfile" ]]; then
        pass "$envfile exists; kept as it is"
        python3 "$PY" env "$CAPTURE_DIR" "$host" >"$envfile.from-capture"
        note "what the capture suggests is in $envfile.from-capture (compare: diff -u $envfile $envfile.from-capture)"
    else
        mkdir -p /etc/sssd-smartcard
        python3 "$PY" env "$CAPTURE_DIR" "$host" >"$envfile"
        chmod 0644 "$envfile"
        pass "wrote $envfile (host name: $host, everything else from the capture)"
        sed 's/^/       /' "$envfile"
    fi

    # --- 2. Domain membership: this host's own --------------------------------
    heading "Domain membership"
    local joined
    joined="$(realm list --name-only 2>/dev/null | sed -n 1p || true)"
    if [[ -z "$joined" ]]; then
        warn "this host has not joined a domain yet; the capture cannot do that for it"
        note "A keytab belongs to one machine, so the join is done here, under this host's name."
        note "Check hostname and join_user in $envfile first, then:"
        note "    sudo ad-prepare --yes"
        note "    sudo sssd-smartcard-setup --only packages,join,identity --yes"
        note "    sudo $PROGRAM --replay $CAPTURE"
        exit 3
    fi
    if [[ -n "$cap_domain" && "${joined,,}" != "${cap_domain,,}" ]]; then
        if (( FORCE )); then
            warn "joined to $joined, the capture is from $cap_domain (--force: continuing)"
        else
            die "joined to $joined, but the capture is from $cap_domain (a certmap rule pins its domain's issuer; --force to continue)"
        fi
    else
        pass "joined to $joined"
    fi

    # --- 3. Remembered CRL URLs, so the CRL can be fetched without a card ----
    local sources="$CAPTURE_DIR/files$STATE_DIR/crl-sources.json"
    if [[ -f "$sources" ]]; then
        heading "CRL sources"
        if [[ -f "$STATE_DIR/crl-sources.json" ]] && cmp -s "$sources" "$STATE_DIR/crl-sources.json"; then
            pass "$STATE_DIR/crl-sources.json already the same"
        elif (( ASSUME_YES )); then
            mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
            [[ -f "$STATE_DIR/crl-sources.json" ]] && cp -a "$STATE_DIR/crl-sources.json" "$STATE_DIR/crl-sources.json.bak-$(date +%Y%m%d-%H%M%S)"
            install -m 0600 "$sources" "$STATE_DIR/crl-sources.json"
            pass "CRL URLs copied: the CRL is fetched without a card"
        else
            info "would copy the remembered CRL URLs to $STATE_DIR/crl-sources.json"
            note "(until then, the dry run below may ask for the card to find them)"
        fi
    fi

    # --- 4. sssd-smartcard-setup with the captured choices ---------------------
    heading "sssd-smartcard-setup"
    local -a args
    mapfile -t args < <(python3 "$PY" setup-args "$CAPTURE_DIR")
    (( DO_PAM )) && args+=(--pam)
    if (( ASSUME_YES )); then
        args+=(--yes)
    else
        args+=(--dry-run)
    fi
    note "$setup ${args[*]}"
    local rc=0
    "$setup" "${args[@]}" || rc=$?

    # --- 5. What was not reproduced -------------------------------------------
    heading "Not reproduced automatically -- review"
    local items
    items="$(python3 "$PY" review "$CAPTURE_DIR" /)"
    if [[ -z "$items" ]]; then
        pass "every other captured file is identical here"
    else
        local state path captured
        while IFS=$'\t' read -r state path captured; do
            if [[ "$state" == "missing here" ]]; then
                warn "$path: not on this host"
                note "    less $captured"
            else
                warn "$path: differs"
                note "    diff -u $path $captured"
            fi
        done <<<"$items"
    fi

    heading "sssd.conf, captured vs. here (host-specific and debug options left out)"
    local diffs
    diffs="$(python3 "$PY" sssd-diff "$CAPTURE_DIR/files/etc/sssd/sssd.conf" /etc/sssd/sssd.conf 2>/dev/null || true)"
    if [[ -z "$diffs" ]]; then
        pass "no differences"
    else
        printf '%s\n' "$diffs" | sed 's/^/       /'
        note "Options the profile does not manage are not copied: set them with care,"
        note "then: sssctl config-check && systemctl restart sssd"
    fi

    printf '\n'
    if (( ! ASSUME_YES )); then
        info "that was the plan; nothing was changed. Apply with: sudo $PROGRAM --replay $CAPTURE --yes"
        (( DO_PAM )) || note "add --pam to let setup change PAM as well"
    fi
    return "$rc"
}

case "$MODE" in
    local)  mode_local ;;
    from)   mode_from ;;
    show)   mode_show ;;
    replay) mode_replay ;;
esac
