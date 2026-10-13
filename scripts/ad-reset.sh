#!/usr/bin/env bash
#
# ad-reset.sh -- remove every trace of one Active Directory domain from a test
# machine, so the next domain starts from nothing.
#
# Reusing a machine for a second domain without this leaves traces in thirteen
# places, and the ones that bite are not the obvious ones. The SSSD cache keeps
# the old users, their UIDs and SIDs, and happily answers lookups for them. The
# machine keytab still holds the old host principal. krb5.conf still names the
# old realm, the old KDC hostname and the old CA as a PKINIT anchor. The
# certmap rule still pins the old issuer DN, so a certificate from the new PKI
# silently fails to match and login falls through to a password -- which looks
# like a Smart Card problem and is not.
#
# Order matters here. `realm leave` runs first, while the old domain controller
# is still reachable, because that is what deletes the machine account in AD
# rather than leaving an orphan. SSSD is stopped before its caches are removed,
# since a running daemon rewrites them. Everything is backed up first.
#
# What this deliberately leaves alone:
#   * the PAM configuration. `pam_sss.so` with no domain configured simply
#     falls through, nothing in it names a domain, and rewriting PAM is how an
#     administrator gets locked out of a machine.
#   * local accounts, SSH keys and sudo.
#   * DNS and the hostname. Those belong to the *next* domain, and ad-prepare
#     sets them; removing them here would only strand the machine.
#
set -Eeuo pipefail

PROGRAM=${0##*/}
VERSION="0.2.2"

if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
    echo "$PROGRAM needs bash 4.4 or newer (found ${BASH_VERSION})" >&2
    exit 1
fi

# --- settings ---------------------------------------------------------------
DOMAIN=""
REALM=""
DRY_RUN=1
CHECK_ONLY=0
LOCAL_ONLY=0
REMOVE_HOMES=0
KEEP_BACKUPS=0
LOG_FILE="/var/log/${PROGRAM%.sh}.log"
BACKUP_ROOT="/var/lib/sssd-smartcard/backups"
BACKUP_DIR=""
SSSD_CONF="/etc/sssd/sssd.conf"
KRB5_CONF="/etc/krb5.conf"
FAILED_STAGE=""

# --- environment file -------------------------------------------------------
# The domain and its details are described once in JSON rather than retyped on
# every command line; a flag given here still wins over the file.
ENV_PATH=""
for _candidate in \
        "${BASH_SOURCE[0]%/*}/lib/env.sh" \
        /usr/share/sssd-smartcard/lib/env.sh; do
    if [[ -r "$_candidate" ]]; then
        # shellcheck source=/dev/null
        source "$_candidate"
        break
    fi
done
unset _candidate

# --- output -----------------------------------------------------------------
if [[ -t 1 ]] && [[ -z ${NO_COLOR:-} ]]; then
    C_RESET=$'\033[0m'; C_DIM=$'\033[2m'; C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BOLD=$'\033[1m'
else
    C_RESET=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BOLD=""
fi

log()   { [[ -n "$LOG_FILE" ]] || return 0
          { printf '%s\n' "$*" >>"$LOG_FILE"; } 2>/dev/null || true; }
say()   { printf '%s\n' "$*"; log "$*"; }
pass()  { printf '%s[ OK ]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; log "[OK] $*"; }
warn()  { printf '%s[WARN]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; log "[WARN] $*"; }
fail()  { printf '%s[FAIL]%s %s\n' "$C_RED" "$C_RESET" "$*"; log "[FAIL] $*"; }
skip()  { printf '%s[SKIP] %s%s\n' "$C_DIM" "$*" "$C_RESET"; log "[SKIP] $*"; }
note()  { printf '%s   %s%s\n' "$C_DIM" "$*" "$C_RESET"; log "[note] $*"; }
gone()  { printf '%s   - %s%s\n' "$C_DIM" "$*" "$C_RESET"; log "[removed] $*"; }
head1() { printf '\n%s%s%s\n' "$C_BOLD" "$*" "$C_RESET"; log "== $* =="; }
die()   { fail "$*"; exit 1; }

on_err() {
    local rc=$?
    fail "aborted in stage '${FAILED_STAGE:-unknown}' (exit $rc)"
    [[ -n "$BACKUP_DIR" ]] && note "backups: $BACKUP_DIR"
    note "log: $LOG_FILE"
    note "SSSD may be stopped: systemctl start sssd"
    exit "$rc"
}
trap on_err ERR

usage() {
    cat <<EOF
$PROGRAM $VERSION -- wipe one AD domain off a test machine.

USAGE
  sudo $PROGRAM --check                      # what is still here
  sudo $PROGRAM --domain old.example.com --dry-run
  sudo $PROGRAM --domain old.example.com --yes

OPTIONS
  --env FILE         Read the domain from a JSON environment file. Without it,
                     /etc/sssd-smartcard/environment.json is used when present.
  --domain FQDN      Domain to remove. Overrides the file. Default: the joined
                     domain, detected.
  --check            Report every remaining trace and exit. Changes nothing.
  --dry-run          Show what would be removed (the default without --yes).
  --yes              Actually remove it.
  --local-only       Skip 'realm leave'. Use when the old DC is gone; the
                     machine account is then left orphaned in AD.
  --remove-homes     Also delete /home/<user>@<domain> directories.
                     Off by default: that is user data.
  --keep-backups     Keep /var/lib/sssd-smartcard/backups (removed otherwise).
  --log FILE         Log file (default: $LOG_FILE).
  -h, --help         This text.
  --version          Print the version.

WHAT IT TOUCHES
  realm leave, sssd.conf domain and certmap sections, certificate_verification,
  /etc/sssd/pki, the SSSD caches under /var/lib/sss, /etc/krb5.keytab, the
  realm and pkinit lines in krb5.conf, this tool's profiles and state, the CRL
  refresh timer, and Kerberos ticket caches.

WHAT IT LEAVES
  PAM, local accounts, SSH, sudo, DNS and the hostname. DNS and the hostname
  belong to the next domain -- set them with ad-prepare.

AFTERWARDS
  sudo ad-prepare --domain new.example.com --dns <new DC> --hostname <name> --yes
EOF
}

have() { command -v "$1" >/dev/null 2>&1; }

ensure_backup_dir() {
    [[ -n "$BACKUP_DIR" ]] && return 0
    BACKUP_DIR="$BACKUP_ROOT/reset-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    chmod 0700 "$BACKUP_DIR"
    return 0
}

save() {
    local path=$1
    [[ -e "$path" ]] || return 0
    ensure_backup_dir
    cp -a "$path" "$BACKUP_DIR/${path//\//_}" 2>/dev/null || true
    printf '%s\n' "$path" >>"$BACKUP_DIR/manifest"
}

# Remove an ini section and its body, by exact header match.
drop_section() {
    local file=$1 section=$2 tmp
    grep -qxF "[$section]" "$file" 2>/dev/null || return 0
    tmp=$(mktemp)
    awk -v want="[$section]" '
        /^\[/ { inside = ($0 == want) }
        !inside { print }
    ' "$file" >"$tmp"
    cat "$tmp" >"$file"
    rm -f "$tmp"
    gone "[$section] from ${file##*/}"
}

drop_key() {
    local file=$1 key=$2 tmp
    grep -qE "^[[:space:]]*$key[[:space:]]*=" "$file" 2>/dev/null || return 0
    tmp=$(mktemp)
    grep -vE "^[[:space:]]*$key[[:space:]]*=" "$file" >"$tmp"
    cat "$tmp" >"$file"
    rm -f "$tmp"
    gone "$key from ${file##*/}"
}

rm_path() {
    local path=$1
    [[ -e "$path" ]] || return 0
    save "$path"
    rm -rf "$path"
    gone "$path"
}

detect_domain() {
    local out="${TMPDIR:-/tmp}/$PROGRAM.realm.$$"
    if have realm && realm list --name-only >"$out" 2>/dev/null; then
        DOMAIN=$(awk 'NF {print; exit}' "$out")
    fi
    rm -f "$out"
    if [[ -z "$DOMAIN" ]] && [[ -r "$SSSD_CONF" ]]; then
        DOMAIN=$(awk -F'/' '/^\[domain\// {sub(/\]$/,"",$2); print $2; exit}' "$SSSD_CONF")
    fi
    [[ -n "$DOMAIN" ]] || return 1
    return 0
}

# --- the trace report -------------------------------------------------------
# Used by --check and again after a removal, so "it is gone" is a finding and
# not an assumption.
report_traces() {
    local quiet=${1:-0}
    local found=0
    local d=${DOMAIN,,} r=${REALM^^}

    if have realm; then
        local out="${TMPDIR:-/tmp}/$PROGRAM.rl.$$"
        realm list --name-only >"$out" 2>/dev/null || true
        if grep -qiF "$d" "$out" 2>/dev/null; then
            (( quiet )) || fail "still joined to $DOMAIN (realm list)"
            found=1
        else
            (( quiet )) || pass "not joined to $DOMAIN"
        fi
        rm -f "$out"
    fi

    local f
    for f in "$SSSD_CONF" "$KRB5_CONF" /etc/hosts; do
        [[ -r "$f" ]] || continue
        local n
        n=$(grep -icF "$d" "$f" 2>/dev/null || true)
        n=${n:-0}
        if (( n > 0 )); then
            (( quiet )) || fail "$f mentions $DOMAIN ($n line(s))"
            (( quiet )) || grep -inF "$d" "$f" 2>/dev/null | sed -e 's/^/       /' || true
            found=1
        else
            (( quiet )) || pass "$f is clean"
        fi
    done

    # Caches, keytab and state, matched by name.
    local -a suspects=()
    local p
    while IFS= read -r p; do suspects+=("$p"); done < <(
        {
            find /var/lib/sss -iname "*${d}*" 2>/dev/null || true
            find /var/lib/sss -iname "*${r}*" 2>/dev/null || true
            find /etc/sssd/pki -type f 2>/dev/null || true
            find /etc/sssd-smartcard/profiles -name '*.yaml' 2>/dev/null || true
            find /var/lib/sssd-smartcard -maxdepth 1 \
                 \( -name 'crl-sources.json' -o -name 'effective-profile.yaml' \
                    -o -name 'setup-state' \) 2>/dev/null || true
            ls /etc/systemd/system/sssd-smartcard-crl.* 2>/dev/null || true
            ls /tmp/krb5cc_* 2>/dev/null || true
        } | sort -u
    )
    if [[ -e /etc/krb5.keytab ]]; then
        if have klist && klist -k /etc/krb5.keytab 2>/dev/null | grep -qiF "$d"; then
            suspects+=("/etc/krb5.keytab")
        fi
    fi

    if (( ${#suspects[@]} )); then
        (( quiet )) || fail "${#suspects[@]} file(s) left over:"
        (( quiet )) || printf '       %s\n' "${suspects[@]}"
        found=1
    else
        (( quiet )) || pass "no leftover caches, keytab, profiles or state"
    fi

    # Home directories are user data. They are a trace, but keeping them is a
    # deliberate choice, so they only count as a failure when their removal was
    # asked for and did not happen.
    local homes=()
    local h
    while IFS= read -r h; do [[ -n "$h" ]] && homes+=("$h"); done < <(
        ls -d /home/*@"${d}" 2>/dev/null || true)
    if (( ${#homes[@]} )); then
        if (( REMOVE_HOMES )); then
            (( quiet )) || fail "home directories remain: ${homes[*]}"
            found=1
        else
            (( quiet )) || warn "home directories kept (user data): ${homes[*]}"
            (( quiet )) || note "remove them with --remove-homes"
        fi
    fi

    # A cache that still answers is the most misleading leftover of all.
    if have getent && [[ -n "$d" ]]; then
        local probe="${TMPDIR:-/tmp}/$PROGRAM.ge.$$"
        getent passwd >"$probe" 2>/dev/null || true
        local users
        users=$(grep -icF "@$d" "$probe" 2>/dev/null || true)
        rm -f "$probe"
        if (( ${users:-0} > 0 )); then
            (( quiet )) || fail "NSS still returns ${users} user(s) from $DOMAIN"
            found=1
        fi
    fi

    return $found
}

# --- stages -----------------------------------------------------------------
stage_preflight() {
    FAILED_STAGE="preflight"
    head1 "Preflight"

    (( EUID == 0 )) || die "must run as root (try: sudo $PROGRAM ...)"
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE=""

    if [[ -z "$DOMAIN" ]]; then
        detect_domain || die "could not detect a joined domain; pass --domain"
        pass "detected domain: $DOMAIN"
    fi
    DOMAIN=${DOMAIN,,}
    REALM=${DOMAIN^^}
    pass "realm: $REALM"

    # Sessions belonging to the domain. Removing the cache under a live session
    # leaves it half working in a way that is hard to interpret.
    local sessions="${TMPDIR:-/tmp}/$PROGRAM.sess.$$"
    if have loginctl; then
        loginctl list-sessions --no-legend >"$sessions" 2>/dev/null || true
        local n
        n=$(grep -icF "@$DOMAIN" "$sessions" 2>/dev/null || true)
        if (( ${n:-0} > 0 )); then
            warn "${n} session(s) belong to $DOMAIN:"
            grep -iF "@$DOMAIN" "$sessions" | sed -e 's/^/       /' || true
            note "log them out first, or they will keep running against a removed cache"
        else
            pass "no logged-in users from $DOMAIN"
        fi
    fi
    rm -f "$sessions"
}

stage_leave() {
    FAILED_STAGE="leave"
    head1 "Leaving the domain"

    if (( LOCAL_ONLY )); then
        skip "realm leave (--local-only); the machine account stays in AD"
        note "delete UBUNTU-...\$ by hand in AD, or it lingers as an orphan"
        return 0
    fi
    if ! have realm; then
        warn "realm is not installed; skipping the domain leave"
        return 0
    fi

    local out="${TMPDIR:-/tmp}/$PROGRAM.rl2.$$"
    realm list --name-only >"$out" 2>/dev/null || true
    if ! grep -qiF "$DOMAIN" "$out" 2>/dev/null; then
        rm -f "$out"
        pass "not joined; nothing to leave"
        return 0
    fi
    rm -f "$out"

    if (( DRY_RUN )); then
        note "would run: realm leave $DOMAIN"
        note "that deletes this machine's account in AD -- do it while the DC is"
        note "still reachable, or the account is orphaned"
        return 0
    fi

    if realm leave "$DOMAIN" 2>&1 | sed -e 's/^/       /'; then
        pass "left $DOMAIN"
    else
        warn "realm leave failed (the DC may be unreachable)"
        note "continuing with local cleanup; the machine account stays in AD and"
        note "should be deleted there by hand"
    fi
}

stage_services() {
    FAILED_STAGE="services"
    head1 "Services"

    if (( DRY_RUN )); then
        note "would stop sssd and remove the CRL refresh timer"
        return 0
    fi

    # The CRL timer points at this domain's bundle and CRL file.
    local unit
    for unit in sssd-smartcard-crl.timer sssd-smartcard-crl.service; do
        if [[ -e "/etc/systemd/system/$unit" ]]; then
            systemctl disable --now "$unit" >/dev/null 2>&1 || true
            rm_path "/etc/systemd/system/$unit"
        fi
    done
    systemctl daemon-reload 2>/dev/null || true

    # Stopped before the caches go, because a running sssd rewrites them.
    if systemctl is-active sssd >/dev/null 2>&1; then
        systemctl stop sssd 2>/dev/null || true
        pass "sssd stopped"
    else
        pass "sssd was not running"
    fi
}

stage_config() {
    FAILED_STAGE="config"
    head1 "Configuration"

    if (( DRY_RUN )); then
        [[ -r "$SSSD_CONF" ]] && grep -nF "$DOMAIN" "$SSSD_CONF" |
            sed -e 's/^/   would remove: /' || true
        grep -nE "default_realm|pkinit_|includedir" "$KRB5_CONF" 2>/dev/null |
            sed -e 's/^/   would remove: /' || true
        return 0
    fi

    if [[ -r "$SSSD_CONF" ]]; then
        save "$SSSD_CONF"
        local section
        while IFS= read -r section; do
            drop_section "$SSSD_CONF" "$section"
        done < <(grep -oE "^\[(domain|certmap)/[^]]*\]" "$SSSD_CONF" 2>/dev/null |
                 grep -iF "$DOMAIN" | tr -d '[]' || true)
        # certificate_verification names this domain's CRL file.
        drop_key "$SSSD_CONF" "certificate_verification"
        drop_key "$SSSD_CONF" "pam_cert_verification"
        # The domains= line in [sssd] lists the domain by name.
        if grep -qE "^[[:space:]]*domains[[:space:]]*=" "$SSSD_CONF"; then
            drop_key "$SSSD_CONF" "domains"
        fi
        chmod 0600 "$SSSD_CONF"
        pass "$SSSD_CONF cleaned (mode 0600)"
    fi

    if [[ -r "$KRB5_CONF" ]]; then
        save "$KRB5_CONF"
        drop_key "$KRB5_CONF" "default_realm"
        drop_key "$KRB5_CONF" "pkinit_eku_checking"
        drop_key "$KRB5_CONF" "pkinit_kdc_hostname"
        drop_key "$KRB5_CONF" "pkinit_anchors"
        # includedir points into the SSSD snippets, which go away with the
        # caches; leaving the line makes krb5 warn on every command.
        local tmp
        tmp=$(mktemp)
        grep -v "^includedir /var/lib/sss/pubconf/krb5.include.d/" "$KRB5_CONF" >"$tmp"
        cat "$tmp" >"$KRB5_CONF"
        rm -f "$tmp"
        pass "$KRB5_CONF cleaned"
    fi
}

stage_data() {
    FAILED_STAGE="data"
    head1 "Caches, keytab and state"

    if (( DRY_RUN )); then
        note "would remove: /var/lib/sss/{db,mc,gpo_cache,keytabs,secrets,pubconf}"
        note "would remove: /etc/krb5.keytab, /etc/sssd/pki/*, /tmp/krb5cc_*"
        note "would remove: this tool's profiles and state"
        (( REMOVE_HOMES )) && note "would remove: /home/*@$DOMAIN"
        (( REMOVE_HOMES )) || note "keeping /home/*@$DOMAIN (pass --remove-homes)"
        return 0
    fi

    # The cache is the leftover that misleads: it answers lookups for the old
    # domain's users long after the domain is gone.
    local p
    # pipes holds sockets named after the domain. Removing it with sssd stopped
    # is safe: sssd recreates the directory when it starts.
    for p in db mc gpo_cache keytabs secrets pubconf deskprofile pipes; do
        rm_path "/var/lib/sss/$p"
    done
    rm_path /etc/krb5.keytab
    for p in /etc/sssd/pki/sssd_auth_ca_db.pem /etc/sssd/pki/revocation.crl.pem; do
        rm_path "$p"
    done
    for p in /var/lib/sssd-smartcard/crl-sources.json \
             /var/lib/sssd-smartcard/effective-profile.yaml \
             /var/lib/sssd-smartcard/setup-state; do
        rm_path "$p"
    done
    while IFS= read -r p; do rm_path "$p"; done < <(
        find /etc/sssd-smartcard/profiles -name '*.yaml' 2>/dev/null || true)
    while IFS= read -r p; do rm_path "$p"; done < <(
        ls /tmp/krb5cc_* 2>/dev/null || true)

    if (( REMOVE_HOMES )); then
        while IFS= read -r p; do rm_path "$p"; done < <(
            ls -d /home/*@"$DOMAIN" 2>/dev/null || true)
    else
        local homes
        homes=$(ls -d /home/*@"$DOMAIN" 2>/dev/null | tr '\n' ' ' || true)
        [[ -n "$homes" ]] && note "kept (user data): $homes"
    fi

    if (( ! KEEP_BACKUPS )); then
        # Keep this run's own backups; drop the earlier ones, which hold the
        # old domain's configuration.
        local d
        while IFS= read -r d; do
            [[ "$d" == "$BACKUP_DIR" ]] && continue
            rm -rf "$d"
            gone "$d"
        done < <(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null || true)
    else
        note "earlier backups kept (--keep-backups); they contain the old domain"
    fi
}

stage_verify() {
    FAILED_STAGE="verify"
    head1 "Verification"

    if (( DRY_RUN )); then
        skip "verification (dry run)"
        return 0
    fi

    local rc=0
    report_traces 0 || rc=1

    # Local login must still work. This is the check that matters most: a reset
    # that leaves nobody able to log in is worse than a dirty machine.
    if grep -q "pam_unix.so" /etc/pam.d/common-auth 2>/dev/null; then
        pass "pam_unix is still in common-auth (local login intact)"
    else
        fail "pam_unix.so is missing from common-auth -- local login may be broken"
        rc=1
    fi
    local locals
    locals=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd 2>/dev/null |
             tr '\n' ' ' || true)
    pass "local accounts: ${locals:-none}"

    if (( rc == 0 )); then
        pass "nothing from $DOMAIN remains"
    fi
    return $rc
}

# --- argument parsing -------------------------------------------------------
while (( $# )); do
    case $1 in
        --domain)        DOMAIN="${2:?--domain needs a value}"; shift ;;
        --check)         CHECK_ONLY=1; DRY_RUN=1 ;;
        --dry-run)       DRY_RUN=1 ;;
        --yes)           DRY_RUN=0 ;;
        --local-only)    LOCAL_ONLY=1 ;;
        --remove-homes)  REMOVE_HOMES=1 ;;
        --keep-backups)  KEEP_BACKUPS=1 ;;
        --log)           LOG_FILE="${2:?--log needs a path}"; shift ;;
        --env)           ENV_PATH="${2:?--env needs a path}"; shift ;;
        -h|--help)       usage; exit 0 ;;
        --version)       printf '%s %s\n' "$PROGRAM" "$VERSION"; exit 0 ;;
        *)               die "unknown option: $1 (try --help)" ;;
    esac
    shift
done

if [[ -n "$ENV_PATH" ]]; then
    env_load "$ENV_PATH" || die "could not read $ENV_PATH"
elif [[ -r "$(env_default_path)" ]]; then
    env_load "$(env_default_path)" || true
fi
# The file names the domain being removed, unless the command line does.
[[ -z "$DOMAIN" ]] && DOMAIN=${ENV_DOMAIN:-}

say "$PROGRAM $VERSION"
stage_preflight

if (( CHECK_ONLY )); then
    head1 "Traces of $DOMAIN"
    TRACE_RC=0
    report_traces 0 || TRACE_RC=$?
    say ""
    if (( TRACE_RC == 0 )); then
        pass "this machine carries nothing from $DOMAIN"
    else
        fail "traces remain; remove them with: sudo $PROGRAM --domain $DOMAIN --yes"
    fi
    exit $TRACE_RC
fi

(( DRY_RUN )) && note "dry run: nothing will be removed (add --yes to proceed)"

stage_leave
stage_services
stage_config
stage_data

VERIFY_RC=0
stage_verify || VERIFY_RC=$?

head1 "Result"
if (( DRY_RUN )); then
    say "  dry run: nothing was removed"
    say "  Re-run with --yes to proceed."
    exit 0
fi

[[ -n "$BACKUP_DIR" ]] && say "  Backups: $BACKUP_DIR"
say "  Log:     $LOG_FILE"
say ""
note "sssd is left stopped on purpose: with no domain configured it has nothing"
note "to serve, and the next join starts it again."
say ""
say "Next, for the new domain:"
say "  sudo ad-prepare --domain new.example.com --dns <new DC> --hostname <name> --yes"
say "  sudo sssd-smartcard-setup --only packages,join,identity \\"
say "       --realm NEW.EXAMPLE.COM --join-user administrator \\"
say "       --test-user someone@new.example.com --yes"

exit $VERIFY_RC
