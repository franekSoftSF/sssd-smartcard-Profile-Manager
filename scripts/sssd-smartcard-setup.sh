#!/usr/bin/env bash
#
# sssd-smartcard-setup -- guided setup for SSSD Smart Card / PIV authentication.
#
# Design rules, learned from setup scripts that fail halfway and leave a host
# that neither logs in with a card nor with a password:
#
#   1. Stages are ordered by dependency and each one VERIFIES itself. A stage
#      that cannot prove it worked stops the run instead of letting the next
#      stage build on sand.
#   2. Identity resolution is a hard gate. If `id user@domain` does not work,
#      no amount of certmap configuration will help, so we refuse to continue.
#   3. Every file is backed up before it is touched, and a failure rolls back.
#   4. PAM is never edited implicitly. It is the one file that can lock you out
#      of the machine, so it needs --pam and it is applied last, after a card
#      login has been proven to work at the SSSD level.
#   5. Everything is idempotent and resumable. Re-running is always safe.
#   6. --dry-run prints every command without running any of them.
#
# Usage: sssd-smartcard-setup.sh [options]   (--help for the full list)

# -E (errtrace) matters: without it the ERR trap is not inherited by shell
# functions, so a failure inside a stage would skip the rollback entirely.
set -Eeuo pipefail

# Empty-array expansion under `set -u` needs bash 4.4 or newer.
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
    printf 'this script needs bash 4.4 or newer (found %s)\n' "${BASH_VERSION}" >&2
    exit 1
fi

VERSION="0.3.1"
PROGRAM="${0##*/}"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DRY_RUN=0
ASSUME_YES=0
NON_INTERACTIVE=0
DO_PACKAGES=1
DO_JOIN=0
DO_CA=1
DO_CERTMAP=1
DO_GPO=0
DO_ADSYS=0
DO_AUTOENROLL=0
DO_PAM=0
DO_VERIFY=1
# -1 = not said on the command line: the environment file decides ("crl").
DO_CRL=-1
DO_SSH=0
DO_SUDO_AGENT=0
DO_MKHOMEDIR=0
SUDO_GROUP=""
REQUIRE_SMARTCARD=0
CHECK_ONLY=0
FORCE=0

REALM=""
JOIN_USER=""
SSSD_DOMAIN=""
ACCOUNT_DOMAIN=""
TEST_USER=""
CA_FILES=()
PROFILE_NAME=""
PROFILE_PATH=""
PROFILE_SOURCE=""
CERT_FILE=""
PKCS11_MODULE=""
GPO_ACCESS_CONTROL="permissive"
SSSD_CONF="/etc/sssd/sssd.conf"
CA_DB="/etc/sssd/pki/sssd_auth_ca_db.pem"
CRL_FILE=""         # empty: the CLI's default, /etc/sssd/pki/revocation.crl.pem
SSHD_DROPIN="/etc/ssh/sshd_config.d/60-sssd-smartcard.conf"
SSS_SSH_HELPER="/usr/bin/sss_ssh_authorizedkeys"
SUDOERS_GROUP_FILE="/etc/sudoers.d/90-sssd-smartcard-admins"
SUDOERS_AGENT_FILE="/etc/sudoers.d/91-sssd-smartcard-ssh-agent"
STATE_DIR="/var/lib/sssd-smartcard"
BACKUP_ROOT="$STATE_DIR/backups"
LOG_FILE=""
ENV_PATH=""

# --- environment file -------------------------------------------------------
# The domain and its details are described once in JSON; a flag given on the
# command line still wins over the file.
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
ONLY_STAGES=""
SKIP_STAGES=""

# Populated by detect_distro
DISTRO_ID=""; DISTRO_LIKE=""; DISTRO_VERSION=""; DISTRO_PRETTY=""
DISTRO_FAMILY="unknown"; PKG_MANAGER=""; SUPPORTS_ADSYS=0

CLI=""              # how to invoke the sssd-smartcard python CLI
RUN_STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="$BACKUP_ROOT/$RUN_STAMP"
ROLLBACK_NEEDED=0
declare -a BACKED_UP_FILES=()
declare -a CREATED_FILES=()
declare -a DRYRUN_TEMPFILES=()
declare -a WARNINGS=()
declare -a NEXT_STEPS=()
FAILED_STAGE=""

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[90m'
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_CYAN=$'\033[36m'
else
    C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""
fi

say()   { printf '%s\n' "$*"; [[ -n "$LOG_FILE" ]] && printf '%s\n' "$*" >>"$LOG_FILE" || true; }
pass()  { say "${C_GREEN}[ OK ]${C_RESET} $*"; }
fail()  { say "${C_RED}[FAIL]${C_RESET} $*"; }
warn()  { say "${C_YELLOW}[WARN]${C_RESET} $*"; WARNINGS+=("$*"); }
info()  { say "${C_CYAN}[INFO]${C_RESET} $*"; }
skip()  { say "${C_DIM}[SKIP]${C_RESET} $*"; }
note()  { say "       ${C_DIM}$*${C_RESET}"; }

stage_header() {
    say ""
    say "${C_BOLD}=== $* ===${C_RESET}"
}

die() {
    fail "$*"
    exit 1
}

# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------

# run <description> <command...>
# Honours --dry-run. Returns the command's exit status.
run() {
    local desc="$1"; shift
    if (( DRY_RUN )); then
        say "${C_DIM}  would run:${C_RESET} $*"
        return 0
    fi
    note "running: $*"
    if [[ -n "$LOG_FILE" ]]; then
        "$@" >>"$LOG_FILE" 2>&1
    else
        "$@" >/dev/null 2>&1
    fi
}

# run_visible <command...> -- output goes to the terminal (for interactive tools)
run_visible() {
    if (( DRY_RUN )); then
        say "${C_DIM}  would run:${C_RESET} $*"
        return 0
    fi
    note "running: $*"
    "$@"
}

# capture <command...> -- echo stdout, never fail the script
capture() {
    "$@" 2>/dev/null || true
}

confirm() {
    local prompt="$1"
    (( ASSUME_YES )) && return 0
    if (( NON_INTERACTIVE )); then
        warn "refusing without confirmation in non-interactive mode: $prompt"
        return 1
    fi
    local reply=""
    printf '%s [y/N] ' "$prompt" >&2
    read -r reply </dev/tty || reply=""
    [[ "$reply" == [yY] || "$reply" == [yY][eE][sS] ]]
}

# ---------------------------------------------------------------------------
# Backup and rollback
# ---------------------------------------------------------------------------

backup_file() {
    local path="$1"
    (( DRY_RUN )) && { say "${C_DIM}  would back up:${C_RESET} $path"; return 0; }
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
    if [[ -e "$path" ]]; then
        local target="$BACKUP_DIR/$(echo "${path#/}" | tr '/' '_')"
        cp -a "$path" "$target"
        BACKED_UP_FILES+=("$path:$target")
        note "backed up $path -> $target"
    else
        CREATED_FILES+=("$path")
        note "$path does not exist yet; a rollback would remove it"
    fi
    ROLLBACK_NEEDED=1
}

rollback() {
    (( ROLLBACK_NEEDED )) || return 0
    (( DRY_RUN )) && return 0
    say ""
    warn "rolling back changes made by this run"
    local entry path target
    for (( idx=${#BACKED_UP_FILES[@]}-1 ; idx>=0 ; idx-- )); do
        entry="${BACKED_UP_FILES[idx]}"
        path="${entry%%:*}"; target="${entry#*:}"
        if cp -a "$target" "$path"; then
            note "restored $path"
        else
            fail "could not restore $path from $target -- do it by hand"
        fi
    done
    if (( ${#CREATED_FILES[@]} )); then
        for path in "${CREATED_FILES[@]}"; do
            [[ -e "$path" ]] && rm -f "$path" && note "removed $path (did not exist before)"
        done
    fi
    if systemctl list-unit-files sssd.service >/dev/null 2>&1; then
        systemctl restart sssd.service >/dev/null 2>&1 \
            && note "sssd restarted on the previous configuration" \
            || fail "sssd could not be restarted after rollback -- check systemctl status sssd"
    fi
}

on_error() {
    local status=$?
    [[ $status -eq 0 ]] && return 0
    say ""
    fail "stage '${FAILED_STAGE:-unknown}' failed (exit $status)"
    rollback
    say ""
    say "Log: ${LOG_FILE:-<none>}"
    say "Backups: $BACKUP_DIR"
    exit "$status"
}
trap on_error ERR

# ---------------------------------------------------------------------------
# State (resumability)
# ---------------------------------------------------------------------------
state_file() { printf '%s/setup-state' "$STATE_DIR"; }

mark_done() {
    (( DRY_RUN )) && return 0
    mkdir -p "$STATE_DIR"
    printf '%s %s\n' "$(date -Iseconds)" "$1" >>"$(state_file)"
}

was_done() {
    [[ -f "$(state_file)" ]] && grep -qw "$1" "$(state_file)"
}

# ---------------------------------------------------------------------------
# Distribution detection
# ---------------------------------------------------------------------------
detect_distro() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO_ID="${ID:-}"
        DISTRO_LIKE="${ID_LIKE:-}"
        DISTRO_VERSION="${VERSION_ID:-}"
        DISTRO_PRETTY="${PRETTY_NAME:-}"
    fi
    case "$DISTRO_ID" in
        ubuntu|debian|linuxmint|pop|elementary) DISTRO_FAMILY="debian" ;;
        rhel|centos|fedora|rocky|almalinux|ol)  DISTRO_FAMILY="rhel" ;;
        opensuse*|sles)                          DISTRO_FAMILY="suse" ;;
        *)
            case " $DISTRO_LIKE " in
                *" debian "*) DISTRO_FAMILY="debian" ;;
                *" rhel "*|*" fedora "*|*" centos "*) DISTRO_FAMILY="rhel" ;;
                *" suse "*) DISTRO_FAMILY="suse" ;;
                *) DISTRO_FAMILY="unknown" ;;
            esac
            ;;
    esac
    case "$DISTRO_FAMILY" in
        debian) PKG_MANAGER="apt-get"; export DEBIAN_FRONTEND=noninteractive ;;
        rhel)   PKG_MANAGER="$(command -v dnf >/dev/null 2>&1 && echo dnf || echo yum)" ;;
        suse)   PKG_MANAGER="zypper" ;;
    esac
    [[ "$DISTRO_ID" == "ubuntu" ]] && SUPPORTS_ADSYS=1
    return 0
}

# Ubuntu >= 23.10 and Debian >= 13 ship the sss-smart-card-* pam-auth-update
# profiles (Debian 13: measured in a debian:13 container, libpam-sss 2.10.1).
# Their presence on disk settles it either way once libpam-sss is installed.
has_smartcard_pam_profiles() {
    [[ -f /usr/share/pam-configs/sss-smart-card-optional ]] && return 0
    if [[ "$DISTRO_ID" == "debian" ]]; then
        local major="${DISTRO_VERSION%%.*}"
        [[ "$major" =~ ^[0-9]+$ ]] && (( major >= 13 )) && return 0
        return 1
    fi
    [[ "$DISTRO_ID" == "ubuntu" ]] || return 1
    local major minor
    major="${DISTRO_VERSION%%.*}"
    minor="${DISTRO_VERSION#*.}"; minor="${minor%%.*}"
    [[ "$major" =~ ^[0-9]+$ ]] || return 1
    (( major > 23 )) && return 0
    (( major == 23 )) && [[ "$minor" =~ ^[0-9]+$ ]] && (( minor >= 10 )) && return 0
    return 1
}

pam_strategy() {
    case "$DISTRO_FAMILY" in
        rhel) echo authselect ;;
        debian) has_smartcard_pam_profiles && echo pam-auth-update || echo manual ;;
        *) echo unknown ;;
    esac
}

# ---------------------------------------------------------------------------
# Package installation
# ---------------------------------------------------------------------------
packages_for() {
    local group="$1"
    case "$DISTRO_FAMILY:$group" in
        debian:core)       echo "sssd sssd-ad sssd-tools libpam-sss libnss-sss" ;;
        debian:join)       echo "realmd adcli samba-common samba-common-bin" ;;
        debian:smartcard)  echo "opensc opensc-pkcs11 pcscd pcsc-tools p11-kit" ;;
        debian:kerberos)   echo "krb5-user" ;;
        debian:gpo)        echo "adsys" ;;
        debian:autoenroll) echo "certmonger cepces" ;;
        debian:diagnostics) echo "pamtester openssl" ;;
        debian:sudo)       echo "sudo" ;;
        debian:sudo_agent) echo "libpam-ssh-agent-auth" ;;
        rhel:core)         echo "sssd sssd-ad sssd-tools authselect oddjob oddjob-mkhomedir" ;;
        rhel:join)         echo "realmd adcli samba-common-tools" ;;
        rhel:smartcard)    echo "opensc pcsc-lite pcsc-lite-ccid p11-kit" ;;
        rhel:kerberos)     echo "krb5-workstation" ;;
        rhel:gpo)          echo "" ;;
        rhel:autoenroll)   echo "certmonger cepces" ;;
        rhel:diagnostics)  echo "pamtester openssl" ;;
        rhel:sudo)         echo "sudo" ;;
        rhel:sudo_agent)   echo "pam_ssh_agent_auth" ;;
        suse:core)         echo "sssd sssd-ad sssd-tools pam_sss" ;;
        suse:join)         echo "realmd adcli samba-client" ;;
        suse:smartcard)    echo "opensc pcsc-lite p11-kit" ;;
        suse:kerberos)     echo "krb5-client" ;;
        *)                 echo "" ;;
    esac
}

package_installed() {
    case "$DISTRO_FAMILY" in
        debian) dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "ok installed" ;;
        rhel)   rpm -q "$1" >/dev/null 2>&1 ;;
        suse)   rpm -q "$1" >/dev/null 2>&1 ;;
        *)      return 1 ;;
    esac
}

pkg_refreshed=0
refresh_package_index() {
    (( pkg_refreshed )) && return 0
    pkg_refreshed=1
    case "$DISTRO_FAMILY" in
        debian) run "refresh apt index" apt-get update -qq || warn "apt-get update failed; continuing with the cached index" ;;
        *) : ;;
    esac
}

# install_packages <group> [optional]
# With "optional", a package that cannot be installed is a warning, not an error.
install_packages() {
    local group="$1" mode="${2:-required}"
    local wanted missing=() pkg
    wanted="$(packages_for "$group")"
    [[ -z "$wanted" ]] && { skip "no $group packages needed on $DISTRO_PRETTY"; return 0; }

    for pkg in $wanted; do
        package_installed "$pkg" || missing+=("$pkg")
    done
    if (( ${#missing[@]} == 0 )); then
        pass "$group packages already installed: $wanted"
        return 0
    fi
    info "$group packages to install: ${missing[*]}"
    refresh_package_index

    local rc=0
    case "$DISTRO_FAMILY" in
        debian)
            run "install ${missing[*]}" apt-get install -y "${missing[@]}" || rc=$?
            ;;
        rhel)
            run "install ${missing[*]}" "$PKG_MANAGER" install -y "${missing[@]}" || rc=$?
            ;;
        suse)
            run "install ${missing[*]}" zypper --non-interactive install "${missing[@]}" || rc=$?
            ;;
        *)
            warn "unknown distribution; install these by hand: ${missing[*]}"
            return 0
            ;;
    esac

    if (( rc != 0 )); then
        if [[ "$mode" == "optional" ]]; then
            warn "could not install ${missing[*]} (group $group). This group is optional; continuing."
            warn "On Ubuntu, cepces may live in universe -- check: apt-cache policy cepces"
            return 0
        fi
        die "failed to install ${missing[*]}. See $LOG_FILE"
    fi
    (( DRY_RUN )) || pass "$group packages installed"
}

# ---------------------------------------------------------------------------
# Python CLI discovery
# ---------------------------------------------------------------------------
find_cli() {
    if command -v sssd-smartcard >/dev/null 2>&1; then
        CLI="sssd-smartcard"
        return 0
    fi
    local here src
    here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    for src in "$here/../src" "$here/../lib/sssd-smartcard/src" "/opt/sssd-smartcard/src"; do
        if [[ -d "$src/sssd_smartcard" ]]; then
            CLI="env PYTHONPATH=$src python3 -m sssd_smartcard"
            return 0
        fi
    done
    return 1
}

cli() {
    # shellcheck disable=SC2086
    $CLI "$@"
}

# ---------------------------------------------------------------------------
# Stages
# ---------------------------------------------------------------------------

stage_enabled() {
    local name="$1"
    if [[ -n "$ONLY_STAGES" ]]; then
        [[ ",$ONLY_STAGES," == *",$name,"* ]] || return 1
    fi
    if [[ -n "$SKIP_STAGES" ]]; then
        [[ ",$SKIP_STAGES," == *",$name,"* ]] && return 1
    fi
    return 0
}

stage_preflight() {
    FAILED_STAGE="preflight"
    stage_header "Stage 1/12: preflight"

    if [[ "$(id -u)" != "0" ]]; then
        die "this script configures system services and must run as root (try: sudo $PROGRAM ...)"
    fi
    pass "running as root"

    detect_distro
    if [[ "$DISTRO_FAMILY" == "unknown" ]]; then
        warn "unrecognised distribution: ${DISTRO_PRETTY:-$DISTRO_ID}. Package installation and PAM configuration will be skipped."
    else
        pass "distribution: ${DISTRO_PRETTY:-$DISTRO_ID} (family $DISTRO_FAMILY, packages via $PKG_MANAGER)"
    fi
    info "PAM strategy for this distribution: $(pam_strategy)"
    if [[ "$DISTRO_FAMILY" == "debian" && "$(pam_strategy)" == "manual" ]]; then
        note "this release has no sss-smart-card-* pam-auth-update profile"
    fi

    if find_cli; then
        pass "sssd-smartcard CLI: $CLI"
    else
        die "the sssd-smartcard Python CLI was not found. Run install.sh from the release archive first."
    fi

    mkdir -p "$STATE_DIR"
    chmod 700 "$STATE_DIR"
    if [[ -z "$LOG_FILE" ]]; then
        LOG_FILE="/var/log/sssd-smartcard-setup-$RUN_STAMP.log"
    fi
    if (( ! DRY_RUN )); then
        : >"$LOG_FILE"
        chmod 600 "$LOG_FILE"
    fi
    pass "log file: $LOG_FILE"

    if [[ -z "$SSSD_DOMAIN" && -r "$SSSD_CONF" ]]; then
        SSSD_DOMAIN="$(sed -n 's/^[[:space:]]*domains[[:space:]]*=[[:space:]]*\([^,]*\).*/\1/p' "$SSSD_CONF" | head -1 | tr -d '[:space:]')"
        [[ -n "$SSSD_DOMAIN" ]] && info "SSSD domain from $SSSD_CONF: $SSSD_DOMAIN"
    fi

    mark_done preflight
}

stage_packages() {
    FAILED_STAGE="packages"
    stage_header "Stage 2/12: packages"
    if (( ! DO_PACKAGES )); then skip "package installation disabled (--no-packages)"; return 0; fi
    if [[ "$DISTRO_FAMILY" == "unknown" ]]; then skip "unknown distribution"; return 0; fi

    install_packages core
    install_packages kerberos
    install_packages smartcard
    install_packages diagnostics optional
    (( DO_JOIN )) && install_packages join

    # Services the card path needs before anything else can be tested.
    if systemctl list-unit-files pcscd.socket >/dev/null 2>&1; then
        run "enable pcscd" systemctl enable --now pcscd.socket \
            || warn "could not enable pcscd.socket; a reader will not be detected"
    fi
    run "enable sssd" systemctl enable sssd.service \
        || warn "could not enable sssd.service"
    mark_done packages
}

stage_join() {
    FAILED_STAGE="join"
    stage_header "Stage 3/12: domain membership"

    local joined=""
    joined="$(capture realm list --name-only)"
    if [[ -n "$joined" ]]; then
        pass "host is joined to: $(echo "$joined" | tr '\n' ' ')"
        [[ -z "$SSSD_DOMAIN" ]] && SSSD_DOMAIN="$(echo "$joined" | head -1)"
    elif (( DO_JOIN )); then
        if [[ -z "$REALM" || -z "$JOIN_USER" ]]; then
            fail "joining needs a realm and an account to join with"
            [[ -n "$REALM" ]] || note "realm: not set -- pass --realm, or put it in"
            [[ -n "$REALM" ]] || note "  the environment file as \"realm\" (or let it"
            [[ -n "$REALM" ]] || note "  be derived from \"domain\")"
            [[ -n "$JOIN_USER" ]] || note "join user: not set -- pass --join-user, or"
            [[ -n "$JOIN_USER" ]] || note "  put it in the environment file as \"join_user\""
            die "cannot join without both"
        fi
        (( ${JOIN_IMPLIED:-0} )) && info "--only join implies joining; --dry-run still applies"
        info "joining $REALM as $JOIN_USER"
        note "realm will prompt for the password; this script never reads or stores it"
        backup_file "$SSSD_CONF"
        run_visible realm join --user="$JOIN_USER" "$REALM" \
            || die "realm join failed. Check DNS, time sync and credentials, then re-run."
        pass "joined $REALM"
    else
        fail "this host is not joined to any domain"
        note "Smart Card logon needs a working domain membership first."
        # Name the values this run is actually holding. The old text printed an
        # example realm from the manual, which had to be edited to be usable.
        if [[ -n "$REALM" ]]; then
            note "to join now, add the join stage:"
            note "    $PROGRAM --only packages,join,identity --yes"
            note "which would join $REALM${JOIN_USER:+ as $JOIN_USER}"
            [[ -n "$JOIN_USER" ]] || note "    (and needs --join-user, or join_user in the environment file)"
        else
            note "no realm is known. Either join the domain yourself, or:"
            note "    sudo ad-prepare --init-env --domain <domain>   # writes the realm"
            note "    $PROGRAM --only packages,join,identity --yes"
        fi
        die "cannot continue without domain membership"
    fi

    [[ -n "$SSSD_DOMAIN" ]] || die "could not determine the SSSD domain; pass --sssd-domain"
    info "SSSD domain (owns the certmap section): $SSSD_DOMAIN"
    mark_done join
}

stage_identity() {
    FAILED_STAGE="identity"
    stage_header "Stage 4/12: identity lookup through the domain (hard gate)"

    if ! systemctl is-active --quiet sssd.service; then
        run "start sssd" systemctl start sssd.service || true
    fi

    local domains=""
    domains="$(capture sssctl domain-list)"
    if [[ -n "$domains" ]]; then
        pass "SSSD knows these domains: $(echo "$domains" | tr '\n' ' ')"
    else
        warn "sssctl domain-list returned nothing"
    fi

    if [[ -n "$ACCOUNT_DOMAIN" ]]; then
        if echo "$domains" | grep -qix "$ACCOUNT_DOMAIN"; then
            pass "account domain $ACCOUNT_DOMAIN is known to SSSD"
        else
            fail "SSSD does not know the account domain $ACCOUNT_DOMAIN"
            note "The accounts live in a trusted domain that SSSD cannot see."
            note "Identity lookup through the trusted domain failed."
            note "Fix AD/SSSD/trust configuration before enabling Smart Card authentication."
            (( FORCE )) || die "refusing to configure Smart Card auth on a broken trust (--force overrides)"
            warn "continuing anyway because --force was given"
        fi
    fi

    if [[ -z "$TEST_USER" ]]; then
        warn "no --test-user given, so identity resolution was not proven"
        note "Strongly recommended: --test-user user@${ACCOUNT_DOMAIN:-$SSSD_DOMAIN}"
        note "A certmap rule that maps to a user SSSD cannot resolve will fail at login with a confusing error."
    else
        if id "$TEST_USER" >/dev/null 2>&1; then
            pass "id $TEST_USER -> $(capture id "$TEST_USER" | head -1)"
        else
            fail "id $TEST_USER failed"
            note "getent: $(capture getent passwd "$TEST_USER")"
            note "sssctl: $(capture sssctl user-checks "$TEST_USER" | head -3 | tr '\n' ' ')"
            note ""
            note "Identity lookup through the trusted domain failed."
            note "Fix AD/SSSD/trust configuration before enabling Smart Card authentication."
            (( FORCE )) || die "refusing to continue (--force overrides)"
            warn "continuing anyway because --force was given"
        fi
    fi
    mark_done identity
}

stage_ca() {
    FAILED_STAGE="ca"
    stage_header "Stage 5/12: CA trust bundle"
    if (( ! DO_CA )); then skip "CA import disabled (--no-ca)"; return 0; fi

    if (( ${#CA_FILES[@]} == 0 )); then
        if [[ -s "$CA_DB" ]]; then
            info "no --ca given; keeping the existing bundle"
            cli ca show --bundle "$CA_DB" 2>&1 | sed 's/^/       /' || true
        else
            fail "no CA certificates given and $CA_DB is empty or missing"
            note "SSSD verifies card certificates against this PEM file only."
            note "Pass the issuing chain: --ca root-ca.pem --ca issuing-ca.pem"
            (( FORCE )) || die "cannot verify any card certificate without a trust anchor"
        fi
        return 0
    fi

    local f
    for f in "${CA_FILES[@]}"; do
        [[ -r "$f" ]] || die "CA file not readable: $f"
    done

    info "reviewing the CA certificates before importing them"
    cli ca show "${CA_FILES[@]}" 2>&1 | sed 's/^/       /'

    backup_file "$CA_DB"
    if (( DRY_RUN )); then
        cli ca import "${CA_FILES[@]}" --bundle "$CA_DB" --dry-run 2>&1 | sed 's/^/       /'
    else
        cli ca import "${CA_FILES[@]}" --bundle "$CA_DB" --backup-dir "$BACKUP_DIR" 2>&1 \
            | sed 's/^/       /' || die "CA import failed"
        pass "CA trust bundle updated: $CA_DB"
    fi
    mark_done ca
}

stage_card() {
    FAILED_STAGE="card"
    stage_header "Stage 7/12: Smart Card and certificate"

    local module_arg=()
    [[ -n "$PKCS11_MODULE" ]] && module_arg=(--module "$PKCS11_MODULE")

    if [[ -n "$CERT_FILE" ]]; then
        info "using the certificate from $CERT_FILE (no card required)"
        cli cert inspect --file "$CERT_FILE" --no-config 2>&1 | sed 's/^/       /' \
            || die "could not read $CERT_FILE"
    else
        if ! cli card detect "${module_arg[@]}" 2>&1 | sed 's/^/       /'; then
            if [[ -n "$PROFILE_PATH" ]]; then
                # A given profile (e.g. from sssd-smartcard-capture --replay)
                # needs no certificate to derive it; the card is only proof.
                warn "no usable Smart Card found; continuing with the given profile $PROFILE_PATH"
                note "Prove the card path later: sssd-smartcard doctor --user <user>"
                mark_done card
                return 0
            fi
            fail "no usable Smart Card found"
            note "Check: systemctl status pcscd; opensc-tool --list-readers"
            note "Or work from an exported certificate instead: --cert-file user.pem"
            (( FORCE )) || die "cannot derive a profile without a certificate"
        fi
    fi

    # SSSD's own helper is the authority on whether it can read the card.
    local p11child=""
    for p11child in /usr/libexec/sssd/p11_child /usr/lib/x86_64-linux-gnu/sssd/p11_child /usr/lib/sssd/p11_child; do
        [[ -x "$p11child" ]] && break || p11child=""
    done
    if [[ -n "$p11child" && -z "$CERT_FILE" && -s "$CA_DB" ]]; then
        info "asking SSSD's own p11_child to read the card"
        if (( DRY_RUN )); then
            say "${C_DIM}  would run:${C_RESET} $p11child --pre -d 10 --debug-fd=2 --ca_db=$CA_DB"
        elif "$p11child" --pre -d 10 --debug-fd=2 --ca_db="$CA_DB" >>"$LOG_FILE" 2>&1; then
            pass "p11_child read and verified a certificate from the card"
        else
            warn "p11_child could not verify a card certificate -- see $LOG_FILE"
            note "This is the exact code path SSSD uses at login, so fix it before going further."
            note "Usually: the issuing CA is missing from $CA_DB, or the chain is incomplete."
            note "Try: validation.partial_chain / certificate_verification = partial_chain"
        fi
    fi
    mark_done card
}

stage_certmap() {
    FAILED_STAGE="certmap"
    stage_header "Stage 8/12: certmap rule and sssd.conf"
    if (( ! DO_CERTMAP )); then skip "certmap configuration disabled (--no-certmap)"; return 0; fi

    if [[ -z "$PROFILE_PATH" ]]; then
        PROFILE_PATH="$STATE_DIR/generated-profile.yaml"
        local -a gen=(cert autoconfig --save-profile "$PROFILE_PATH" --config "$SSSD_CONF")
        [[ -n "$CERT_FILE" ]] && gen+=(--file "$CERT_FILE") || gen+=(--from-card)
        [[ -n "$PKCS11_MODULE" ]] && gen+=(--module "$PKCS11_MODULE")
        [[ -n "$SSSD_DOMAIN" ]] && gen+=(--sssd-domain "$SSSD_DOMAIN")
        [[ -n "$ACCOUNT_DOMAIN" ]] && gen+=(--domain "$ACCOUNT_DOMAIN")
        [[ -n "$PROFILE_NAME" ]] && gen+=(--profile-name "$PROFILE_NAME")
        (( REQUIRE_SMARTCARD )) && gen+=(--require-smartcard)

        info "deriving a profile from the certificate"
        if (( DRY_RUN )); then
            say "${C_DIM}  would run:${C_RESET} $CLI ${gen[*]}"
            skip "dry run: no profile generated, so no diff can be shown"
            return 0
        fi
        cli "${gen[@]}" 2>&1 | sed 's/^/       /' || die "could not derive a profile from the certificate"
        [[ -s "$PROFILE_PATH" ]] || die "profile was not written to $PROFILE_PATH"
        pass "profile written to $PROFILE_PATH"
    else
        [[ -r "$PROFILE_PATH" ]] || die "profile not readable: $PROFILE_PATH"
        info "using the supplied profile $PROFILE_PATH"
    fi

    # Fold the GPO intent in before applying, so sssd.conf is written once with
    # one backup and one rollback point. This works on a COPY: rewriting the
    # operator's own profile would be an unannounced edit of a file they wrote.
    if (( DO_GPO )); then
        build_effective_profile "$PROFILE_PATH"
        PROFILE_SOURCE="$PROFILE_PATH"
        PROFILE_PATH="$EFFECTIVE_PROFILE"
        info "effective profile (yours + GPO): $PROFILE_PATH"
        info "your own profile is left untouched: $PROFILE_SOURCE"
    fi

    # `config apply` prints the same plan before it writes anything, so only
    # show the diff separately when it is the basis for a prompt, or when a dry
    # run means apply is never reached. Otherwise it appears twice.
    if (( DRY_RUN )) || ! (( ASSUME_YES )); then
        info "changes that would be made to $SSSD_CONF"
        cli config diff "$PROFILE_PATH" --config "$SSSD_CONF" 2>&1 | sed 's/^/       /' || true
    fi

    if (( DRY_RUN )); then
        skip "dry run: sssd.conf not modified"
        return 0
    fi
    if ! confirm "Apply this configuration to $SSSD_CONF?"; then
        die "aborted by operator"
    fi

    backup_file "$SSSD_CONF"
    cli config apply "$PROFILE_PATH" --config "$SSSD_CONF" --yes \
        --backup-dir "$BACKUP_DIR" 2>&1 | sed 's/^/       /' \
        || die "config apply failed (it rolled sssd.conf back itself)"
    pass "sssd.conf updated and SSSD restarted"
    mark_done certmap
}

# Produce a copy of the profile with the gpo: block folded in, and put its path
# in EFFECTIVE_PROFILE.
#
# Two reasons this works on a copy rather than in place:
#   * --gpo would otherwise silently rewrite a profile the operator authored,
#     with no backup of the original;
#   * the copy is made in a dry run too, so the diff that gets shown is the real
#     one. A dry run that under-reports its own changes is worse than useless.
EFFECTIVE_PROFILE=""
build_effective_profile() {
    local src="$1" dest
    if (( DRY_RUN )); then
        dest="$(mktemp "${TMPDIR:-/tmp}/sssd-smartcard-effective.XXXXXX")"
        DRYRUN_TEMPFILES+=("$dest")
    else
        mkdir -p "$STATE_DIR"
        chmod 700 "$STATE_DIR"
        dest="$STATE_DIR/effective-profile.yaml"
    fi
    cp -f "$src" "$dest"

    info "folding in GPO settings (access control: $GPO_ACCESS_CONTROL)"
    ADSYS=$(( DO_ADSYS )) AUTOENROLL=$(( DO_AUTOENROLL )) \
    ACCESS="$GPO_ACCESS_CONTROL" PROFILE="$dest" python3 - <<'PY'
import os
import yaml

path = os.environ["PROFILE"]
with open(path, encoding="utf-8") as handle:
    data = yaml.safe_load(handle)

gpo = data.setdefault("gpo", {})
gpo["manage"] = True
gpo["access_control"] = os.environ["ACCESS"]
if os.environ["ADSYS"] == "1":
    gpo["adsys"] = True
if os.environ["AUTOENROLL"] == "1":
    gpo["adsys"] = True
    gpo["cert_autoenroll"] = True

with open(path, "w", encoding="utf-8") as handle:
    yaml.safe_dump(data, handle, sort_keys=False, allow_unicode=True)
PY
    EFFECTIVE_PROFILE="$dest"
}

stage_gpo() {
    FAILED_STAGE="gpo"
    stage_header "Stage 9/12: Group Policy"
    if (( ! DO_GPO )); then skip "GPO configuration disabled (pass --gpo to enable)"; return 0; fi

    # ad_gpo_access_control was already written by stage_certmap through the
    # profile. Report on it and explain the default.
    info "SSSD logon-rights evaluation: ad_gpo_access_control = $GPO_ACCESS_CONTROL"
    if [[ "$GPO_ACCESS_CONTROL" == "permissive" ]]; then
        note "permissive evaluates GPOs and logs what it would deny, without denying it."
        note "Read the log, then re-run with --gpo-enforcing once it is clean."
    else
        warn "enforcing denies login to any user the domain's GPOs do not grant InteractiveLogonRight"
    fi
    note "sssd-ad(5) documents the DEFAULT as enforcing, so an unconfigured joined host already enforces."

    if (( DO_ADSYS )); then
        if (( ! SUPPORTS_ADSYS )); then
            warn "adsys is packaged by Canonical for Ubuntu only; skipping on ${DISTRO_PRETTY:-$DISTRO_ID}"
            note "On the RHEL family, GPO support means ad_gpo_access_control, configured above."
        else
            install_packages gpo optional
            if package_installed adsys; then
                pass "adsys installed"
                note "dconf policy management is available to everyone."
                note "Other adsys features need an Ubuntu Pro subscription (free for up to 5 machines)."
                if (( DRY_RUN )); then
                    say "${C_DIM}  would run:${C_RESET} adsysctl update -m"
                else
                    if run "refresh machine GPO" adsysctl update -m; then
                        pass "adsysctl update -m succeeded"
                    else
                        warn "adsysctl update -m failed -- see $LOG_FILE and: adsysctl service status"
                        note "A machine GPO refresh needs a valid machine ticket; check: klist -k"
                    fi
                fi
                NEXT_STEPS+=("Generate the policy templates for your AD: adsysctl policy admx lts-only")
            fi
        fi
    fi

    if (( DO_AUTOENROLL )); then
        if (( ! SUPPORTS_ADSYS )); then
            warn "certificate auto-enrolment here is driven by adsys, which is Ubuntu only"
        else
            install_packages autoenroll optional
            if package_installed certmonger && package_installed cepces; then
                pass "certmonger and cepces installed"
            else
                warn "certmonger and/or cepces are not installed; auto-enrolment will not run"
                note "Check availability: apt-cache policy certmonger cepces"
            fi
            NEXT_STEPS+=("Enable auto-enrolment in the GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies > Certificate Services Client - Auto-Enrollment -> Configuration Model: Enabled")
            NEXT_STEPS+=("Debug the enrolment script with: adsysctl policy debug cert-autoenroll-script")
        fi
    fi
    mark_done gpo
}

# Revocation: one current CRL per CA in the bundle, and a timer that keeps it
# current. Before the card and certmap stages, so a profile that names crl_file
# never goes live pointing at a file that is not there yet (SSSD fails closed).
stage_revocation() {
    FAILED_STAGE="revocation"
    stage_header "Stage 6/12: revocation (CRL and refresh timer)"
    if (( DO_CRL != 1 )); then
        skip "CRL not managed (pass --crl, or set \"crl\": true in the environment file)"
        return 0
    fi
    if [[ ! -s "$CA_DB" ]]; then
        (( DRY_RUN )) && { skip "dry run: no CA bundle yet, so no CRL set can be built"; return 0; }
        fail "no CA bundle at $CA_DB: a CRL is needed for every CA in it"
        return 1
    fi

    local crl_path="${CRL_FILE:-/etc/sssd/pki/revocation.crl.pem}"
    local -a upd=(ca crl update --bundle "$CA_DB" --crl-file "$crl_path")
    # A CA's CRL URL is advertised only by the certificates it signed, so the
    # first run needs an end-entity certificate. Later runs (and the timer) use
    # the URLs remembered in $STATE_DIR/crl-sources.json.
    if [[ -n "$CERT_FILE" ]]; then
        upd+=(--file "$CERT_FILE")
    elif [[ -s "$STATE_DIR/crl-sources.json" ]]; then
        info "CRL URLs remembered in $STATE_DIR/crl-sources.json"
    else
        upd+=(--from-card)
        [[ -n "$PKCS11_MODULE" ]] && upd+=(--module "$PKCS11_MODULE")
    fi

    if (( DRY_RUN )); then
        cli "${upd[@]}" --dry-run 2>&1 | sed 's/^/       /' || warn "the CRL set is not complete yet"
        say "${C_DIM}  would run:${C_RESET} $CLI ca crl timer --install --bundle $CA_DB --crl-file $crl_path"
        return 0
    fi

    backup_file "$crl_path"
    backup_file /etc/systemd/system/sssd-smartcard-crl.service
    backup_file /etc/systemd/system/sssd-smartcard-crl.timer
    cli "${upd[@]}" --backup-dir "$BACKUP_DIR" 2>&1 | sed 's/^/       /' \
        || { fail "no complete, current CRL set -- SSSD would reject every card"; return 1; }
    pass "CRL set installed: $crl_path"
    cli ca crl timer --install --bundle "$CA_DB" --crl-file "$crl_path" \
        --backup-dir "$BACKUP_DIR" 2>&1 | sed 's/^/       /' \
        || { fail "could not install the CRL refresh timer"; return 1; }
    pass "sssd-smartcard-crl.timer refreshes it"
    mark_done revocation
}

# The reload command for whichever unit name this distribution gives sshd.
sshd_reload() {
    local unit
    for unit in ssh.service sshd.service; do
        if systemctl list-unit-files "$unit" 2>/dev/null | grep -q "^$unit"; then
            run "reload $unit" systemctl reload "$unit" && return 0
            run "restart $unit" systemctl restart "$unit" && return 0
            return 1
        fi
    done
    warn "no ssh.service or sshd.service unit found; reload sshd by hand"
    return 0
}

# SSH with the card: sshd asks SSSD for the public key derived from the
# certificate in AD, so the same CA bundle, CRL and certmap rule decide -- and
# one revocation closes console, SSH and sudo together.
stage_ssh() {
    FAILED_STAGE="ssh"
    stage_header "Stage 10/12: SSH with the card (AuthorizedKeysCommand)"
    if (( ! DO_SSH )); then
        skip "sshd not configured (pass --ssh, or set \"ssh\": true in the environment file)"
        return 0
    fi

    local sshd_bin
    sshd_bin="$(command -v sshd 2>/dev/null || true)"
    [[ -z "$sshd_bin" && -x /usr/sbin/sshd ]] && sshd_bin=/usr/sbin/sshd
    if [[ -z "$sshd_bin" ]]; then
        warn "OpenSSH server is not installed; nothing to configure (apt-get install openssh-server)"
        return 0
    fi
    if [[ ! -x "$SSS_SSH_HELPER" ]]; then
        (( DRY_RUN )) && { skip "dry run: $SSS_SSH_HELPER is not installed yet"; return 0; }
        fail "$SSS_SSH_HELPER is missing (it ships with SSSD itself: sssd-common / sssd)"
        return 1
    fi
    if ! grep -Eqi '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config 2>/dev/null; then
        fail "/etc/ssh/sshd_config does not include /etc/ssh/sshd_config.d/; a drop-in would be ignored"
        note "Add near the top:  Include /etc/ssh/sshd_config.d/*.conf"
        return 1
    fi

    # sshd takes the FIRST value it reads, so a command already set elsewhere
    # would silently win over a new drop-in.
    local current
    current="$("$sshd_bin" -T 2>/dev/null | awk '$1 == "authorizedkeyscommand" {print $2}' | head -1)"
    if [[ "$current" == "$SSS_SSH_HELPER" ]]; then
        pass "sshd already asks SSSD for keys ($SSS_SSH_HELPER)"
    elif [[ -n "$current" && "$current" != "none" ]]; then
        fail "sshd already uses AuthorizedKeysCommand $current"
        note "Only one command is allowed; decide which one stays, then re-run."
        return 1
    else
        local body
        body="# Written by sssd-smartcard-setup: SSH keys come from the certificate in AD,
# derived by SSSD -- the same CA bundle, CRL and certmap rule as the console.
AuthorizedKeysCommand $SSS_SSH_HELPER
AuthorizedKeysCommandUser nobody"
        if (( DRY_RUN )); then
            say "${C_DIM}  would write:${C_RESET} $SSHD_DROPIN"
            printf '%s\n' "$body" | sed 's/^/         /'
            say "${C_DIM}  would run:${C_RESET} $sshd_bin -t && systemctl reload ssh"
        else
            backup_file "$SSHD_DROPIN"
            printf '%s\n' "$body" >"$SSHD_DROPIN"
            chmod 0644 "$SSHD_DROPIN"
            # Never leave sshd holding a file it cannot parse.
            "$sshd_bin" -t >>"$LOG_FILE" 2>&1 \
                || { fail "sshd -t rejected the configuration (see $LOG_FILE)"; return 1; }
            current="$("$sshd_bin" -T 2>/dev/null | awk '$1 == "authorizedkeyscommand" {print $2}' | head -1)"
            [[ "$current" == "$SSS_SSH_HELPER" ]] \
                || { fail "sshd -T reports AuthorizedKeysCommand '${current:-none}' -- another file wins"; return 1; }
            sshd_reload || { fail "sshd could not be reloaded"; return 1; }
            pass "sshd asks SSSD for the keys: $SSHD_DROPIN"
        fi
    fi

    # The SSH responder is socket-activated unless sssd.conf lists it in
    # services= (then sssd itself starts it and the socket must stay off).
    if grep -Eq '^[[:space:]]*services[[:space:]]*=.*\bssh\b' "$SSSD_CONF" 2>/dev/null; then
        pass "SSSD ssh responder listed in services="
    elif systemctl list-unit-files sssd-ssh.socket >/dev/null 2>&1; then
        run "enable sssd-ssh.socket" systemctl enable --now sssd-ssh.socket \
            || warn "could not enable sssd-ssh.socket; sss_ssh_authorizedkeys will return nothing"
    fi
    NEXT_STEPS+=("Keys SSSD derives for a user: $SSS_SSH_HELPER ${TEST_USER:-<user>}")
    mark_done ssh
}

# write_sudoers <file> <content>
# Through a staging file whose name contains a dot (sudo skips those), checked
# with visudo before it goes live.
write_sudoers() {
    local dest="$1" body="$2" staging
    staging="$(dirname "$dest")/.$(basename "$dest").new"
    if [[ -f "$dest" ]] && [[ "$(cat "$dest")" == "$body" ]]; then
        pass "$dest already in place"
        return 0
    fi
    if (( DRY_RUN )); then
        say "${C_DIM}  would write:${C_RESET} $dest (mode 0440, checked with visudo first)"
        printf '%s\n' "$body" | sed 's/^/         /'
        return 0
    fi
    backup_file "$dest"
    printf '%s\n' "$body" >"$staging"
    chmod 0440 "$staging"
    if ! visudo -c -f "$staging" >>"$LOG_FILE" 2>&1; then
        rm -f "$staging"
        fail "visudo rejected the rule for $dest (see $LOG_FILE)"
        return 1
    fi
    install -m 0440 -o root -g root "$staging" "$dest"
    rm -f "$staging"
    pass "wrote $dest"
}

# Where the PAM module for sudo over a forwarded agent is, if installed.
pam_ssh_agent_module() {
    local dir
    for dir in /lib/x86_64-linux-gnu/security /usr/lib/x86_64-linux-gnu/security \
               /lib/aarch64-linux-gnu/security /usr/lib/aarch64-linux-gnu/security \
               /usr/lib64/security /lib64/security /lib/security /usr/lib/security; do
        [[ -f "$dir/pam_ssh_agent_auth.so" ]] && { printf '%s\n' "$dir/pam_ssh_agent_auth.so"; return 0; }
    done
    return 1
}

# sudo: WHO in Active Directory (one group), WHAT on the host. Optionally the
# card over SSH, through the forwarded agent and the same key SSSD derives.
stage_sudo() {
    FAILED_STAGE="sudo"
    stage_header "Stage 11/12: sudo (AD group, card over SSH)"
    if [[ -z "$SUDO_GROUP" ]] && (( ! DO_SUDO_AGENT )); then
        skip "sudo not configured (pass --sudo-group G and/or --sudo-agent, or set sudo_group / sudo_agent)"
        return 0
    fi
    (( DO_PACKAGES )) && install_packages sudo
    if ! command -v visudo >/dev/null 2>&1; then
        (( DRY_RUN )) && { skip "dry run: sudo is not installed yet"; return 0; }
        fail "sudo is not installed"
        return 1
    fi

    if [[ -n "$SUDO_GROUP" ]]; then
        # A group SSSD cannot resolve gives a rule that matches nobody -- and
        # sudo still asks for a password first, so it looks like it works.
        if getent group "$SUDO_GROUP" >/dev/null 2>&1; then
            pass "group resolves: $(getent group "$SUDO_GROUP" | cut -d: -f1,3)"
        elif (( FORCE )); then
            warn "group $SUDO_GROUP does not resolve; writing the rule anyway (--force)"
        else
            fail "group $SUDO_GROUP does not resolve (getent group). Check the name and domain."
            note "With use_fully_qualified_names the name is group@domain, unquoted."
            return 1
        fi
        # No quotes: %"group@domain" is rejected as 'empty group' (measured).
        # Only a space needs escaping.
        write_sudoers "$SUDOERS_GROUP_FILE" "%${SUDO_GROUP// /\\ } ALL=(ALL:ALL) ALL"
    fi

    if (( DO_SUDO_AGENT )); then
        (( DO_PACKAGES )) && install_packages sudo_agent
        # Without it, env_reset strips the variable, the module finds no agent
        # and sudo falls through to a password with nothing said.
        write_sudoers "$SUDOERS_AGENT_FILE" 'Defaults env_keep += "SSH_AUTH_SOCK"'

        local line="auth    sufficient  pam_ssh_agent_auth.so authorized_keys_command=$SSS_SSH_HELPER"
        if grep -q 'pam_ssh_agent_auth\.so' /etc/pam.d/sudo 2>/dev/null; then
            pass "/etc/pam.d/sudo already uses pam_ssh_agent_auth"
            grep -q 'authorized_keys_command=' /etc/pam.d/sudo \
                || warn "/etc/pam.d/sudo uses pam_ssh_agent_auth without authorized_keys_command: a key file outlives revoking the certificate"
        elif (( ! DO_PAM )); then
            skip "/etc/pam.d/sudo not modified (pass --pam to apply)"
            NEXT_STEPS+=("In /etc/pam.d/sudo, before '@include common-auth': $line")
        elif ! pam_ssh_agent_module >/dev/null && (( ! DRY_RUN )); then
            fail "pam_ssh_agent_auth.so is not installed (package libpam-ssh-agent-auth)"
            return 1
        elif (( DRY_RUN )); then
            say "${C_DIM}  would insert into /etc/pam.d/sudo, before the first auth line:${C_RESET}"
            say "         $line"
        else
            backup_file /etc/pam.d/sudo
            # Before the first auth entry (Debian: '@include common-auth'),
            # so 'sufficient' can short-circuit the password prompt.
            awk -v line="$line" '
                !done && ($0 ~ /^@include[ \t]+common-auth/ || $1 == "auth") { print line; done = 1 }
                { print }
                END { if (!done) print line }
            ' /etc/pam.d/sudo >/etc/pam.d/.sudo.sssd-smartcard.new
            chmod --reference=/etc/pam.d/sudo /etc/pam.d/.sudo.sssd-smartcard.new
            mv -f /etc/pam.d/.sudo.sssd-smartcard.new /etc/pam.d/sudo
            pass "/etc/pam.d/sudo: sudo accepts the card through the forwarded agent"
        fi
        NEXT_STEPS+=("Over SSH with agent forwarding: sudo -k && sudo -l  (no prompt = the card was used)")
    fi

    if (( ! DRY_RUN )); then
        visudo -c >>"$LOG_FILE" 2>&1 || { fail "visudo -c reports an error in the sudoers files"; return 1; }
        pass "visudo -c: all sudoers files parse"
    fi
    [[ -n "$TEST_USER" ]] && NEXT_STEPS+=("Rules for the test user, without authenticating: sudo -l -U $TEST_USER")
    mark_done sudo
}

stage_pam() {
    FAILED_STAGE="pam"
    stage_header "Stage 12/12: PAM"

    local strategy mode
    strategy="$(pam_strategy)"
    mode="optional"; (( REQUIRE_SMARTCARD )) && mode="required"

    local -a commands=()
    case "$strategy" in
        authselect)
            commands=("authselect enable-feature with-smartcard")
            (( REQUIRE_SMARTCARD )) && commands+=("authselect enable-feature with-smartcard-required")
            (( DO_MKHOMEDIR )) && commands+=("authselect enable-feature with-mkhomedir")
            ;;
        pam-auth-update)
            if (( REQUIRE_SMARTCARD )); then
                commands=("pam-auth-update --disable sss-smart-card-optional --enable sss-smart-card-required")
            else
                commands=("pam-auth-update --disable sss-smart-card-required --enable sss-smart-card-optional")
            fi
            # A first card login otherwise lands in a home that does not exist
            # (GNOME: a black screen).
            (( DO_MKHOMEDIR )) && commands+=("pam-auth-update --enable mkhomedir")
            ;;
        manual)
            local line
            if (( REQUIRE_SMARTCARD )); then
                line="auth [success=done default=die] pam_sss.so allow_missing_name require_cert_auth"
            else
                line="auth [success=ok default=ignore] pam_sss.so allow_missing_name try_cert_auth"
            fi
            fail "this distribution has no supported non-interactive PAM mechanism"
            note "Add this line to /etc/pam.d/common-auth by hand, above the pam_unix.so line:"
            note "    $line"
            note "This script will not edit PAM: a wrong line here locks you out of the machine."
            NEXT_STEPS+=("Add to /etc/pam.d/common-auth: $line")
            return 0
            ;;
        *)
            warn "unknown distribution; configure pam_sss with try_cert_auth or require_cert_auth yourself"
            return 0
            ;;
    esac

    info "current PAM state"
    cli pam check 2>&1 | sed 's/^/       /' || true

    if (( ! DO_PAM )); then
        skip "PAM not modified (pass --pam to apply)"
        note "Run this once a card login is proven to work at the SSSD level:"
        local c
        for c in "${commands[@]}"; do
            note "    $c"
            NEXT_STEPS+=("$c")
        done
        return 0
    fi

    if (( REQUIRE_SMARTCARD )); then
        say ""
        warn "You are about to make the Smart Card the ONLY way to authenticate."
        note "If the card, reader, PIN or certmap rule is wrong, nobody can log in --"
        note "including you. Keep an open root session in another terminal."
        if ! confirm "Really enable Smart Card only login?"; then
            skip "left PAM alone"
            return 0
        fi
    fi

    local c
    for c in "${commands[@]}"; do
        # shellcheck disable=SC2086
        if (( DRY_RUN )); then
            say "${C_DIM}  would run:${C_RESET} $c"
        else
            run "$c" env DEBIAN_FRONTEND=noninteractive $c || die "'$c' failed. PAM was not fully configured; check $LOG_FILE"
        fi
    done
    (( DRY_RUN )) || pass "PAM configured for Smart Card ($mode)"
    mark_done pam
}

stage_verify() {
    FAILED_STAGE="verify"
    stage_header "Verification"
    if (( ! DO_VERIFY )); then skip "verification disabled (--no-verify)"; return 0; fi
    if (( DRY_RUN )); then skip "dry run"; return 0; fi

    local rc=0

    if command -v sssctl >/dev/null 2>&1; then
        if sssctl config-check >>"$LOG_FILE" 2>&1; then
            pass "sssctl config-check"
        else
            fail "sssctl config-check reported problems"
            capture sssctl config-check | sed 's/^/       /'
            rc=1
        fi
    fi

    if systemctl is-active --quiet sssd.service; then
        pass "sssd.service is active"
    else
        fail "sssd.service is not active"
        rc=1
    fi

    if [[ -n "$PROFILE_PATH" && -r "$PROFILE_PATH" ]]; then
        local -a mt=(mapping test "$PROFILE_PATH")
        [[ -n "$CERT_FILE" ]] && mt+=(--file "$CERT_FILE") || mt+=(--from-card)
        [[ -n "$PKCS11_MODULE" ]] && mt+=(--module "$PKCS11_MODULE")
        info "end-to-end mapping test"
        if cli "${mt[@]}" 2>&1 | sed 's/^/       /'; then
            pass "certificate maps to a user SSSD can resolve"
        else
            fail "the mapping test did not fully succeed"
            rc=1
        fi
    fi

    info "Kerberos readiness"
    local -a kt=(krb5 test)
    # Give it the certificate, or it has no principal to reason about and the
    # PKINIT readiness checks are all skipped.
    if [[ -n "$CERT_FILE" ]]; then
        kt+=(--file "$CERT_FILE")
    else
        kt+=(--from-card)
        [[ -n "$PKCS11_MODULE" ]] && kt+=(--module "$PKCS11_MODULE")
    fi
    cli "${kt[@]}" 2>&1 | sed 's/^/       /' || true
    NEXT_STEPS+=("Prove the KDC issues a ticket for the card: sssd-smartcard krb5 test --from-card --pkinit")

    info "full diagnostic"
    local -a doc=(doctor)
    [[ -n "$TEST_USER" ]] && doc+=(--user "$TEST_USER")
    cli "${doc[@]}" 2>&1 | sed 's/^/       /' || rc=1

    if command -v pamtester >/dev/null 2>&1; then
        NEXT_STEPS+=("Test the PAM stack without logging out: pamtester -v login ${TEST_USER:-<user>} authenticate")
    fi
    return "$rc"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary() {
    say ""
    say "${C_BOLD}=== Summary ===${C_RESET}"
    say "  distribution : ${DISTRO_PRETTY:-$DISTRO_ID} (family $DISTRO_FAMILY)"
    say "  sssd.conf    : $SSSD_CONF"
    say "  CA bundle    : $CA_DB"
    if [[ -n "$PROFILE_SOURCE" ]]; then
        say "  profile      : $PROFILE_SOURCE (yours, unmodified)"
        say "  effective    : $PROFILE_PATH (yours + GPO)"
    elif [[ -n "$PROFILE_PATH" ]]; then
        say "  profile      : $PROFILE_PATH"
    fi
    say "  log          : ${LOG_FILE:-<none>}"
    (( ROLLBACK_NEEDED )) && say "  backups      : $BACKUP_DIR"

    if (( ${#WARNINGS[@]} )); then
        say ""
        say "${C_YELLOW}Warnings (${#WARNINGS[@]}):${C_RESET}"
        local w
        for w in "${WARNINGS[@]}"; do say "  ! $w"; done
    fi
    if (( ${#NEXT_STEPS[@]} )); then
        say ""
        say "${C_BOLD}Next steps:${C_RESET}"
        local s
        for s in "${NEXT_STEPS[@]}"; do say "  * $s"; done
    fi
    say ""
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
$PROGRAM $VERSION -- guided setup for SSSD Smart Card / PIV authentication

USAGE
  $PROGRAM [options]

MODES
  --dry-run              Print every command without running any of them.
  --check                Diagnose only: run doctor and stop. Changes nothing.
  --yes                  Do not ask for confirmation.
  --non-interactive      Never prompt; refuse anything that would need a prompt.
  --force                Continue past failed gates (broken trust, no CA, no card).

DOMAIN
  --env FILE             Read the realm, join user, test user, CA paths and
                         the GPO and Smart Card switches from a JSON
                         environment file. Without it,
                         /etc/sssd-smartcard/environment.json is used when it
                         exists. Flags below override the file. Write one with:
                         ad-prepare --init-env --domain <domain>
  --realm REALM          Kerberos realm, e.g. DOMAIN-B.LOCAL
  --join                 Join the realm if the host is not a member yet.
  --join-user USER       Account used for the join (password is prompted by realm).
  --sssd-domain DOMAIN   SSSD domain that owns the [certmap/...] section.
                         Defaults to the first entry of [sssd] domains.
  --account-domain DOM   Domain the user accounts live in, when it differs
                         (the trusted domain in a one-way trust).
  --test-user USER       User to prove identity resolution with, e.g.
                         jan.kowalski@domain-a.local. Strongly recommended.

CERTIFICATES
  --ca FILE              CA certificate to import into the trust bundle.
                         Repeatable; pass the whole chain.
  --ca-db PATH           Trust bundle path (default $CA_DB).
  --cert-file FILE       Work from an exported certificate instead of a card.
  --module PATH          PKCS#11 module to use.
  --profile FILE         Use this profile instead of deriving one.
  --profile-name NAME    Name for the derived profile.

MODE OF LOGIN
  --require-smartcard    Smart Card only. Refuses without confirmation.

GROUP POLICY
  --gpo                  Manage ad_gpo_access_control (permissive by default).
  --gpo-enforcing        Set ad_gpo_access_control = enforcing. Implies --gpo.
  --adsys                Install and refresh Canonical's GPO client (Ubuntu).
  --cert-autoenroll      Install certmonger + cepces for AD CS auto-enrolment.
                         Implies --adsys.

REVOCATION, SSH AND SUDO
  --crl / --no-crl       Install one current CRL per CA and the refresh timer.
                         Default: "crl" in the environment file.
  --crl-file PATH        Where the CRL goes (default /etc/sssd/pki/revocation.crl.pem).
  --ssh                  sshd takes keys from SSSD (AuthorizedKeysCommand
                         $SSS_SSH_HELPER).
  --sudo-group GROUP     sudo for this AD group: %GROUP ALL=(ALL:ALL) ALL,
                         e.g. linux-admins@ad.example.com. Must resolve.
  --sudo-agent           sudo with the card over SSH: pam_ssh_agent_auth
                         against the same SSSD key (PAM part needs --pam).

PAM
  --pam                  Actually apply the PAM change. Without it, the correct
                         command for this distribution is only printed.
  --mkhomedir            Also create home directories at first login.

SKIPPING
  --no-packages          Do not install anything.
  --no-ca                Do not touch the CA bundle.
  --no-certmap           Do not touch sssd.conf.
  --no-verify            Skip the verification stage.
  --only STAGES          Comma separated: preflight,packages,join,identity,ca,
                         revocation,card,certmap,gpo,ssh,sudo,pam,verify
  --skip STAGES          Same list, but skipped.

OTHER
  --config PATH          sssd.conf location (default $SSSD_CONF).
  --log FILE             Log file location.
  -h, --help             This text.
  --version              Print the version.

EXAMPLES
  # See exactly what would happen, change nothing:
  sudo $PROGRAM --dry-run --test-user jan.kowalski@domain-a.local \\
       --ca /root/pki/root-ca.pem --ca /root/pki/issuing-ca.pem

  # One-way trust: host in DOMAIN B, accounts in DOMAIN A
  sudo $PROGRAM --sssd-domain domain-b.local --account-domain domain-a.local \\
       --test-user jan.kowalski@domain-a.local \\
       --ca /root/pki/root-ca.pem --ca /root/pki/issuing-ca.pem --gpo

  # Full Ubuntu deployment including GPO and auto-enrolment
  sudo $PROGRAM --realm DOMAIN-B.LOCAL --test-user jan.kowalski@domain-a.local \\
       --ca /root/pki/chain.pem --gpo --adsys --cert-autoenroll --pam --yes

  # Everything, from the environment file (Debian 13 / Ubuntu 24.04):
  sudo $PROGRAM --crl --ssh --sudo-group linux-admins@ad.example.com \\
       --sudo-agent --mkhomedir --pam --yes

  # Diagnose an existing installation
  sudo $PROGRAM --check --test-user jan.kowalski@domain-a.local
EOF
}

while (( $# )); do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --check) CHECK_ONLY=1 ;;
        --yes|-y) ASSUME_YES=1 ;;
        --non-interactive) NON_INTERACTIVE=1 ;;
        --force) FORCE=1 ;;
        --env) ENV_PATH="${2:?--env needs a path}"; shift ;;
        --realm) REALM="${2:?--realm needs a value}"; shift ;;
        --join) DO_JOIN=1 ;;
        --join-user) JOIN_USER="${2:?--join-user needs a value}"; shift ;;
        --sssd-domain) SSSD_DOMAIN="${2:?--sssd-domain needs a value}"; shift ;;
        --account-domain) ACCOUNT_DOMAIN="${2:?--account-domain needs a value}"; shift ;;
        --test-user) TEST_USER="${2:?--test-user needs a value}"; shift ;;
        --ca) CA_FILES+=("${2:?--ca needs a path}"); shift ;;
        --ca-db) CA_DB="${2:?--ca-db needs a path}"; shift ;;
        --cert-file) CERT_FILE="${2:?--cert-file needs a path}"; shift ;;
        --module) PKCS11_MODULE="${2:?--module needs a path}"; shift ;;
        --profile) PROFILE_PATH="${2:?--profile needs a path}"; shift ;;
        --profile-name) PROFILE_NAME="${2:?--profile-name needs a value}"; shift ;;
        --require-smartcard) REQUIRE_SMARTCARD=1 ;;
        --gpo) DO_GPO=1 ;;
        --gpo-enforcing) DO_GPO=1; GPO_ACCESS_CONTROL="enforcing" ;;
        --adsys) DO_GPO=1; DO_ADSYS=1 ;;
        --cert-autoenroll) DO_GPO=1; DO_ADSYS=1; DO_AUTOENROLL=1 ;;
        --pam) DO_PAM=1 ;;
        --mkhomedir) DO_MKHOMEDIR=1 ;;
        --crl) DO_CRL=1 ;;
        --no-crl) DO_CRL=0 ;;
        --crl-file) CRL_FILE="${2:?--crl-file needs a path}"; shift ;;
        --ssh) DO_SSH=1 ;;
        --sudo-group) SUDO_GROUP="${2:?--sudo-group needs a group}"; shift ;;
        --sudo-agent) DO_SUDO_AGENT=1 ;;
        --no-packages) DO_PACKAGES=0 ;;
        --no-ca) DO_CA=0 ;;
        --no-certmap) DO_CERTMAP=0 ;;
        --no-verify) DO_VERIFY=0 ;;
        --only) ONLY_STAGES="${2:?--only needs a list}"; shift ;;
        --skip) SKIP_STAGES="${2:?--skip needs a list}"; shift ;;
        --config) SSSD_CONF="${2:?--config needs a path}"; shift ;;
        --log) LOG_FILE="${2:?--log needs a path}"; shift ;;
        -h|--help) usage; exit 0 ;;
        --version) printf '%s %s\n' "$PROGRAM" "$VERSION"; exit 0 ;;
        *) printf 'unknown option: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
say "${C_BOLD}$PROGRAM $VERSION${C_RESET}"
(( DRY_RUN )) && say "${C_YELLOW}dry run: nothing will be changed${C_RESET}"

# Selecting the join stage by name is a statement of intent, so it does not
# also need --join. The flag stays for the all-stages run, where the operator
# did not single joining out. A dry run still changes nothing either way.
if [[ ",${ONLY_STAGES:-}," == *,join,* ]] && (( ! DO_JOIN )); then
    DO_JOIN=1
    JOIN_IMPLIED=1
fi

# --- the environment file ---------------------------------------------------
# Applied only where the command line said nothing, so an explicit flag always
# wins. Without this, the realm, join user, test user and CA paths had to be
# retyped even though the file already holds them.
if declare -F env_default_path >/dev/null; then
    if [[ -n "$ENV_PATH" ]]; then
        env_load "$ENV_PATH" || die "could not read $ENV_PATH"
        pass "environment: $ENV_PATH"
    elif [[ -r "$(env_default_path)" ]]; then
        env_load "$(env_default_path)" || die "could not read $(env_default_path)"
        pass "environment: $(env_default_path)"
    fi

    [[ -z "$REALM" ]]          && REALM=${ENV_REALM:-}
    [[ -z "$JOIN_USER" ]]      && JOIN_USER=${ENV_JOIN_USER:-}
    [[ -z "$TEST_USER" ]]      && TEST_USER=${ENV_TEST_USER:-}
    [[ -z "$SSSD_DOMAIN" ]]    && SSSD_DOMAIN=${ENV_SSSD_DOMAIN:-${ENV_DOMAIN:-}}
    [[ -z "$ACCOUNT_DOMAIN" ]] && ACCOUNT_DOMAIN=${ENV_ACCOUNT_DOMAIN:-}
    (( ${#CA_FILES[@]} )) || CA_FILES=("${ENV_CA[@]:-}")
    # An empty array expansion leaves one empty element behind.
    [[ ${#CA_FILES[@]} -eq 1 && -z ${CA_FILES[0]} ]] && CA_FILES=()

    (( DO_GPO ))             || DO_GPO=${ENV_GPO:-0}
    (( DO_ADSYS ))           || DO_ADSYS=${ENV_ADSYS:-0}
    (( DO_ADSYS ))           && DO_GPO=1
    (( REQUIRE_SMARTCARD ))  || REQUIRE_SMARTCARD=${ENV_SMARTCARD_REQUIRED:-0}
    (( DO_CRL >= 0 ))        || DO_CRL=${ENV_CRL:-0}
    [[ -n "$CRL_FILE" ]]     || CRL_FILE=${ENV_CRL_FILE:-}
    (( DO_SSH ))             || DO_SSH=${ENV_SSH:-0}
    [[ -n "$SUDO_GROUP" ]]   || SUDO_GROUP=${ENV_SUDO_GROUP:-}
    (( DO_SUDO_AGENT ))      || DO_SUDO_AGENT=${ENV_SUDO_AGENT:-0}
    (( DO_MKHOMEDIR ))       || DO_MKHOMEDIR=${ENV_MKHOMEDIR:-0}

    # Values the file still carries from the template would be applied
    # verbatim: a join against AD.EXAMPLE.COM as administrator. Only the
    # fields this script acts on are checked.
    if [[ -n "${ENV_FILE_LOADED:-}" ]] && declare -F env_has_placeholders >/dev/null; then
        # Only the fields the SELECTED stages consume. Checking the whole file
        # meant that --only packages,join,identity refused to run because the
        # CA paths were still examples -- paths the ca stage would use, and
        # that stage is excluded. The CA files are fetched later, by
        # `ca discover`, which is after this runs.
        declare -a NEEDED_KEYS=()
        stage_enabled join     && NEEDED_KEYS+=(realm join_user)
        stage_enabled identity && NEEDED_KEYS+=(test_user)
        stage_enabled verify   && NEEDED_KEYS+=(test_user)
        stage_enabled ca       && NEEDED_KEYS+=(ca)
        if (( ${#NEEDED_KEYS[@]} )); then
            SETUP_PLACEHOLDERS=$(env_has_placeholders "${NEEDED_KEYS[@]}" || true)
        else
            SETUP_PLACEHOLDERS=""
        fi
        if [[ -n "$SETUP_PLACEHOLDERS" ]]; then
            warn "$ENV_FILE_LOADED still holds template values:"
            printf '%s\n' "$SETUP_PLACEHOLDERS" | sed -e 's/^/       /'
            die "fill them in, or override them on the command line"
        fi
    fi
fi

# No environment file and no --crl/--no-crl: revocation stays off.
(( DO_CRL >= 0 )) || DO_CRL=0

stage_preflight

if (( CHECK_ONLY )); then
    stage_header "Diagnostic only (--check)"
    declare -a doc=(doctor)
    [[ -n "$TEST_USER" ]] && doc+=(--user "$TEST_USER")
    cli "${doc[@]}" || true
    print_summary
    exit 0
fi

# Deliberately not `stage_enabled x && stage_x || skip` -- that form swallows a
# stage failure, because the `||` branch makes the whole list succeed.
run_stage() {
    local name="$1" fn="$2"
    if stage_enabled "$name"; then
        "$fn"
    else
        skip "stage $name (excluded by --only/--skip)"
    fi
}

run_stage packages stage_packages
run_stage join     stage_join
run_stage identity stage_identity
run_stage ca         stage_ca
run_stage revocation stage_revocation
run_stage card       stage_card
run_stage certmap    stage_certmap
run_stage gpo        stage_gpo
run_stage ssh        stage_ssh
run_stage sudo       stage_sudo
run_stage pam        stage_pam

VERIFY_RC=0
if stage_enabled verify; then
    stage_verify || VERIFY_RC=$?
else
    skip "stage verify"
fi

trap - ERR

# Dry-run copies exist only to make the diff honest; they are not state.
if (( ${#DRYRUN_TEMPFILES[@]} )); then
    rm -f "${DRYRUN_TEMPFILES[@]}"
fi

print_summary

if (( VERIFY_RC != 0 )); then
    fail "setup completed but verification found problems -- see above and $LOG_FILE"
    note "Nothing was rolled back: sssd.conf is valid, but the card path is not proven."
    note "Re-run with --check after fixing, or inspect: sssd-smartcard doctor"
    exit 1
fi

pass "setup complete"
exit 0
