#!/usr/bin/env bash
#
# install-desktop.sh -- put a minimal graphical environment on a clean Ubuntu
# machine so Smart Card login can be tested at the GDM greeter.
#
# A card login at a real greeter is the only test that exercises the path users
# actually take: GDM's own PAM service, `allow_missing_name` identifying the
# user from the certificate, and the card being read by a session rather than
# by pamtester.  That needs a desktop, and installing one on a remote machine
# has two ways to go wrong that have nothing to do with graphics.
#
# First, the install takes ten minutes or more and runs over SSH.  If the
# session drops in the middle, dpkg is interrupted mid-transaction and the
# machine is left in a state that needs `dpkg --configure -a` to recover.  So
# the install is handed to systemd and runs detached: the SSH session only
# watches it.  Re-running the script attaches to an install already in flight
# instead of starting a second apt.
#
# Second, ubuntu-desktop-minimal pulls in NetworkManager, and NetworkManager
# may take over the interface that is carrying the SSH session.  Before
# anything is installed, that interface is marked unmanaged, which is
# NetworkManager's own documented mechanism and not a trick.
#
# Lessons from doing this by hand on a live host, all of which this script
# avoids:
#   * `pgrep -f 'apt-get.*ubuntu-desktop'` matches its own command line and
#     reports a phantom install.  The dpkg lock is the honest check.
#   * `apt-get install` without a disk-space check fails halfway through on a
#     default-sized VM disk.
#   * A minimized cloud image has dpkg path-excludes for documentation, so man
#     pages installed later are silently dropped.
#
set -Eeuo pipefail

PROGRAM=${0##*/}
VERSION="0.3.0"

if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
    echo "$PROGRAM needs bash 4.4 or newer (found ${BASH_VERSION})" >&2
    exit 1
fi

# --- settings ---------------------------------------------------------------
DESKTOP_PACKAGE="ubuntu-desktop-minimal"
UNIT="sssd-smartcard-desktop-install"
DRY_RUN=1
DO_REBOOT=0
FOLLOW=1
NEEDED_MB=4096
IFACE=""
IFACE_IP=""
LOG_FILE="/var/log/${PROGRAM%.sh}.log"
NM_GUARD="/etc/NetworkManager/conf.d/99-sssd-smartcard-unmanaged.conf"
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

# Only what this script is responsible for. SSSD and the Smart Card packages
# are installed by `sssd-smartcard-setup --only packages`, where they are
# version checked and where a failure is reported in the right context --
# installing them here duplicated that and made this script's scope unclear.
#
# openssh-server is included deliberately: a machine that has just gained a
# graphical login but lost remote access cannot be fixed without a console.
EXTRA_PACKAGES=(openssh-server)

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
head1() { printf '\n%s%s%s\n' "$C_BOLD" "$*" "$C_RESET"; log "== $* =="; }
die()   { fail "$*"; exit 1; }

on_err() {
    local rc=$?
    fail "aborted in stage '${FAILED_STAGE:-unknown}' (exit $rc)"
    note "log: $LOG_FILE"
    note "if an install was in flight: systemctl status $UNIT"
    exit "$rc"
}
trap on_err ERR

usage() {
    cat <<EOF
$PROGRAM $VERSION -- install a minimal desktop for Smart Card login testing.

Runs the install detached under systemd, so losing the SSH session does not
interrupt dpkg. Marks the SSH interface unmanaged first, so NetworkManager
cannot take it over when it arrives with the desktop.

USAGE
  sudo $PROGRAM --dry-run
  sudo $PROGRAM --yes
  sudo $PROGRAM --status          # attach to an install already running

OPTIONS
  --yes                  Actually install (default is --dry-run).
  --dry-run              Show what would happen and stop.
  --env FILE             Read desktop_package from a JSON environment file.
  --package NAME         Desktop package (default: $DESKTOP_PACKAGE).
                         Lighter alternatives: xubuntu-core, lubuntu-desktop.
  --status               Report on an install in flight and follow its log.
  --no-follow            Start the install and return immediately.
  --no-protect-iface     Accepted and ignored. Earlier versions marked the
                         SSH interface unmanaged in NetworkManager, which left
                         machines with no address after a reboot; nothing here
                         changes network configuration any more.
  --force-role           Install even when the environment file says this
                         machine has role: server.
  --reboot               Reboot when finished (needed for the greeter to appear
                         on a machine that booted without graphics).
  --log FILE             Log file (default: $LOG_FILE).
  -h, --help             This text.
  --version              Print the version.

AFTER IT FINISHES
  The greeter appears after a reboot, or immediately with:
      sudo systemctl isolate graphical.target

  Then, for a card login at the greeter:
      sudo pam-auth-update --enable sss-smart-card-optional
      sudo update-alternatives --display gdm-smartcard
      sudo sssd-smartcard doctor

  Keep an SSH session open until a card login has worked.
EOF
}

have() { command -v "$1" >/dev/null 2>&1; }

# `systemctl is-active` PRINTS the state and exits non-zero when it is not
# active, so the obvious `$(systemctl is-active x || echo inactive)` appends a
# second "inactive" to the one systemctl already printed. This returns exactly
# one word.
svc_state() {
    local out=""
    # read takes the first line only, which avoids quoting a newline here.
    read -r out < <(systemctl is-active "$1" 2>/dev/null || true) || true
    printf '%s' "${out:-unknown}"
}

dpkg_busy() {
    # `pgrep -f apt-get` matches this script's own pgrep and reports a phantom
    # install. The lock is what actually decides whether apt can run.
    local lock
    for lock in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock; do
        [[ -e "$lock" ]] || continue
        if have fuser && fuser "$lock" >/dev/null 2>&1; then
            return 0
        fi
    done
    return 1
}

unit_state() {
    systemctl show -p ActiveState --value "$UNIT.service" 2>/dev/null || echo "unknown"
}

unit_result() {
    systemctl show -p Result --value "$UNIT.service" 2>/dev/null || echo "unknown"
}

follow_unit() {
    say ""
    note "following the install; Ctrl-C stops watching, not the install itself"
    say ""
    # --no-pager, and no piping into head: a pipe would die of SIGPIPE under
    # pipefail while journalctl is still writing.
    journalctl -u "$UNIT.service" -f --no-pager -n 20 &
    local tail_pid=$!
    local state
    while :; do
        state=$(unit_state)
        case "$state" in
            inactive|failed) break ;;
            *) sleep 5 ;;
        esac
    done
    kill "$tail_pid" 2>/dev/null || true
    wait "$tail_pid" 2>/dev/null || true
    say ""
    if [[ "$(unit_result)" == "success" ]]; then
        pass "install finished"
        return 0
    fi
    fail "the install unit finished with result: $(unit_result)"
    note "journalctl -u $UNIT.service --no-pager | tail -40"
    return 1
}

# --- stages -----------------------------------------------------------------
stage_preflight() {
    FAILED_STAGE="preflight"
    head1 "Preflight"

    (( EUID == 0 )) || die "must run as root (try: sudo $PROGRAM ...)"
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE=""

    have systemctl || die "this script needs systemd"
    have apt-get || die "this script is for Debian/Ubuntu (apt-get not found)"

    local pretty="unknown"
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        pretty=$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-$NAME}")
    fi
    pass "system: $pretty"

    # Disk space. A desktop install that runs out halfway leaves dpkg to
    # untangle, which is exactly the state this script exists to avoid.
    local avail_mb
    avail_mb=$(df --output=avail -BM / 2>/dev/null | awk 'NR==2 {gsub("M",""); print $1}')
    avail_mb=${avail_mb:-0}
    if (( avail_mb >= NEEDED_MB )); then
        pass "free space on /: ${avail_mb} MB"
    else
        die "only ${avail_mb} MB free on /; $DESKTOP_PACKAGE needs about ${NEEDED_MB} MB"
    fi

    # The interface carrying this session, recorded so it can be compared
    # afterwards. A desktop install that silently moves the IP is the failure
    # that strands a remote machine.
    local route_out="${TMPDIR:-/tmp}/$PROGRAM.route.$$"
    if ip route show default >"$route_out" 2>/dev/null; then
        IFACE=$(awk '/^default/ {for (i=1;i<NF;i++) if ($i=="dev") {print $(i+1); exit}}' "$route_out")
    fi
    rm -f "$route_out"
    if [[ -n "$IFACE" ]]; then
        IFACE_IP=$(ip -4 -o addr show "$IFACE" 2>/dev/null |
                   awk '{split($4,a,"/"); print a[1]; exit}' || true)
        pass "network: $IFACE at ${IFACE_IP:-unknown}"
    else
        warn "could not determine the default-route interface"
    fi

    if dpkg_busy; then
        die "apt or dpkg is already running (the dpkg lock is held); wait for it to finish"
    fi
    pass "dpkg is not locked"

    if dpkg-query -W -f='${Status}' "$DESKTOP_PACKAGE" 2>/dev/null | grep -q "ok installed"; then
        pass "$DESKTOP_PACKAGE is already installed"
    else
        note "$DESKTOP_PACKAGE is not installed (this pulls roughly 1.5 GB)"
    fi

    # A minimized image excludes documentation at the dpkg level, so man pages
    # installed later vanish without a word.
    if compgen -G "/etc/dpkg/dpkg.cfg.d/*" >/dev/null 2>&1 &&
       grep -rqs "path-exclude.*doc" /etc/dpkg/dpkg.cfg.d/; then
        warn "this is a minimized image: dpkg is configured to drop documentation"
        note "man pages for anything installed now will be discarded silently"
    fi
}

stage_network_note() {
    FAILED_STAGE="network-note"
    head1 "Networking"

    # An earlier version marked the interface unmanaged in NetworkManager to
    # stop it claiming the SSH link mid-install. That was unnecessary and
    # harmful: a server rendered by systemd-networkd is not claimed by
    # NetworkManager anyway, while the desktop install switches netplan's
    # renderer TO NetworkManager -- so after a reboot nobody configured the
    # interface and the machine came back with no address. Observed on a real
    # host. Nothing here changes network configuration any more.
    if [[ -e "$NM_GUARD" ]]; then
        warn "$NM_GUARD is present and will strand this machine"
        note "left in place it stops NetworkManager configuring $IFACE once the"
        note "desktop install moves netplan's renderer over to it, and the"
        note "machine reboots with no address at all."
        if (( DRY_RUN )); then
            note "would remove it"
        else
            rm -f "$NM_GUARD"
            pass "removed; NetworkManager may manage $IFACE again"
        fi
    fi

    local renderer="systemd-networkd"
    if compgen -G "/etc/netplan/*.yaml" >/dev/null 2>&1 &&
       grep -rqs "renderer:[[:space:]]*NetworkManager" /etc/netplan/; then
        renderer="NetworkManager"
    fi
    pass "netplan renderer today: $renderer"

    if [[ "$renderer" == "systemd-networkd" ]]; then
        warn "the desktop install may add a netplan file rendered by NetworkManager"
        note "$IFACE keeps its address for the rest of this session either way."
        note "Before rebooting, confirm it is still configured:"
        note "    ip -4 addr show $IFACE && nmcli device status"
        note "Have console access when you reboot. If it comes back with no"
        note "address, 'netplan apply' on the console restores it."
    fi
}
stage_install() {
    FAILED_STAGE="install"
    head1 "Installing $DESKTOP_PACKAGE"

    # Checked here, not during argument parsing: preflight and the network
    # cleanup above must run on every machine. A host stranded by the old
    # unmanaged-interface file would otherwise be turned away before that file
    # could be removed -- the machine that most needs this script to run.
    if [[ "${ENV_ROLE:-}" == "server" ]] && (( ! FORCE_ROLE )); then
        fail "${ENV_FILE_LOADED:-the environment file} declares role: server"
        note "installing a desktop here is probably the wrong machine. If it"
        note "really is meant to have one, set role to desktop, or pass"
        note "--force-role. Anything above this line has already been done."
        exit 1
    fi

    local state
    state=$(unit_state)
    if [[ "$state" == "active" || "$state" == "activating" ]]; then
        warn "an install is already running as $UNIT.service"
        (( FOLLOW )) && follow_unit
        return $?
    fi

    if (( DRY_RUN )); then
        note "would run, detached under systemd as $UNIT:"
        note "  apt-get update"
        note "  apt-get install -y $DESKTOP_PACKAGE ${EXTRA_PACKAGES[*]}"
        note "  systemctl set-default graphical.target"
        return 0
    fi

    # Clear a finished unit of the same name so the next run can reuse it.
    if [[ "$state" == "failed" || "$state" == "inactive" ]]; then
        systemctl reset-failed "$UNIT.service" 2>/dev/null || true
    fi

    # Detached, so a dropped SSH session cannot interrupt dpkg. Everything the
    # unit does is idempotent, so re-running after a failure is safe.
    systemd-run \
        --unit="$UNIT" \
        --description="Install $DESKTOP_PACKAGE for Smart Card login testing" \
        --collect \
        --property=Type=oneshot \
        --property=TimeoutStartSec=infinity \
        --setenv=DEBIAN_FRONTEND=noninteractive \
        --setenv=NEEDRESTART_MODE=a \
        /bin/bash -c "
            set -e
            apt-get update
            apt-get install -y $DESKTOP_PACKAGE ${EXTRA_PACKAGES[*]}
            systemctl set-default graphical.target
        " >/dev/null
    pass "started as $UNIT.service (survives an SSH disconnect)"
    note "watch it later with: $PROGRAM --status"

    if (( FOLLOW )); then
        follow_unit
    else
        note "not following (--no-follow); check with: systemctl status $UNIT.service"
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

    # The network first: a desktop install that moves the IP is what strands a
    # remote machine, and it is the one failure worth checking before anything
    # about graphics.
    if [[ -z "$IFACE" ]]; then
        # --status runs verification without preflight, so there is no
        # "before" address to compare against. Say so rather than skipping a
        # check silently.
        note "no recorded address to compare against (verification without preflight)"
    else
        local now_ip
        now_ip=$(ip -4 -o addr show "$IFACE" 2>/dev/null |
                 awk '{split($4,a,"/"); print a[1]; exit}' || true)
        if [[ -z "$IFACE_IP" ]]; then
            pass "$IFACE is up at ${now_ip:-no address}"
        elif [[ "$now_ip" == "$IFACE_IP" ]]; then
            pass "$IFACE still at $now_ip"
        else
            fail "$IFACE moved from ${IFACE_IP:-unknown} to ${now_ip:-nothing}"
            note "NetworkManager probably claimed it. Check: nmcli device status"
            rc=1
        fi
    fi

    if dpkg-query -W -f='${Status}' "$DESKTOP_PACKAGE" 2>/dev/null | grep -q "ok installed"; then
        pass "$DESKTOP_PACKAGE installed"
    else
        fail "$DESKTOP_PACKAGE is not installed"
        rc=1
    fi

    local pkg missing=()
    for pkg in "${EXTRA_PACKAGES[@]}"; do
        dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "ok installed" || missing+=("$pkg")
    done
    if (( ${#missing[@]} == 0 )); then
        pass "packages present: ${EXTRA_PACKAGES[*]}"
    else
        fail "missing: ${missing[*]}"
        rc=1
    fi

    # Remote access has to survive this, or the machine needs a console.
    local ssh_state
    ssh_state=$(svc_state ssh)
    [[ "$ssh_state" == "active" ]] || ssh_state=$(svc_state sshd)
    if [[ "$ssh_state" == "active" ]]; then
        pass "the SSH server is running"
    else
        fail "the SSH server is not running ($ssh_state)"
        note "systemctl enable --now ssh"
        rc=1
    fi

    local default_target
    default_target=$(systemctl get-default 2>/dev/null || true)
    if [[ "$default_target" == "graphical.target" ]]; then
        pass "default target: graphical.target"
    else
        warn "default target is $default_target, not graphical.target"
        note "systemctl set-default graphical.target"
    fi

    local gdm_state
    gdm_state=$(svc_state gdm3)
    [[ "$gdm_state" == "active" ]] || gdm_state=$(svc_state gdm)
    if [[ "$gdm_state" == "active" ]]; then
        pass "GDM is running"
    else
        warn "GDM is not running yet ($gdm_state)"
        note "it starts at the next boot, or now: systemctl isolate graphical.target"
    fi

    # The greeter's Smart Card PAM stack is an update-alternatives symlink that
    # libpam-sss provides. Reported, not required: this script no longer
    # installs the Smart Card packages, so its absence here is expected until
    # the setup script runs.
    if [[ -e /etc/pam.d/gdm-smartcard ]]; then
        local alt
        alt=$(readlink -f /etc/pam.d/gdm-smartcard 2>/dev/null || true)
        pass "gdm-smartcard PAM stack: ${alt##*/}"
    else
        note "/etc/pam.d/gdm-smartcard does not exist yet; libpam-sss provides it"
        note "and sssd-smartcard-setup --only packages installs that"
    fi

    return $rc
}

# --- argument parsing -------------------------------------------------------
STATUS_ONLY=0
FORCE_ROLE=0
while (( $# )); do
    case $1 in
        --yes)               DRY_RUN=0 ;;
        --dry-run)           DRY_RUN=1 ;;
        --package)           DESKTOP_PACKAGE="${2:?--package needs a value}"; shift ;;
        --status)            STATUS_ONLY=1 ;;
        --no-follow)         FOLLOW=0 ;;
        --no-protect-iface)  : ;;  # accepted and ignored; see --help
        --force-role)        FORCE_ROLE=1 ;;
        --reboot)            DO_REBOOT=1 ;;
        --log)               LOG_FILE="${2:?--log needs a path}"; shift ;;
        --env)               ENV_PATH="${2:?--env needs a path}"; shift ;;
        -h|--help)           usage; exit 0 ;;
        --version)           printf '%s %s\n' "$PROGRAM" "$VERSION"; exit 0 ;;
        *)                   die "unknown option: $1 (try --help)" ;;
    esac
    shift
done

# The helper lives beside the script or in the package. Running the script on
# its own with neither must not be fatal -- it only loses the environment file.
# The previous version died with "env_default_path: command not found" before
# printing a single line.
if declare -F env_default_path >/dev/null; then
    if [[ -n "$ENV_PATH" ]]; then
        env_load "$ENV_PATH" || die "could not read $ENV_PATH"
    elif [[ -r "$(env_default_path)" ]]; then
        env_load "$(env_default_path)" || true
    fi
elif [[ -n "$ENV_PATH" ]]; then
    die "--env needs lib/env.sh, found neither beside this script nor in /usr/share/sssd-smartcard/lib"
fi
# Only desktop_package is relevant here, and only if nothing was passed.
[[ "$DESKTOP_PACKAGE" == "ubuntu-desktop-minimal" && -n "${ENV_DESKTOP_PACKAGE:-}" ]] \
    && DESKTOP_PACKAGE="$ENV_DESKTOP_PACKAGE"

if (( STATUS_ONLY )); then
    (( EUID == 0 )) || die "must run as root"
    head1 "Install status"
    say "  unit:   $UNIT.service"
    say "  state:  $(unit_state)"
    say "  result: $(unit_result)"
    case "$(unit_state)" in
        active|activating) follow_unit ;;
        *) journalctl -u "$UNIT.service" --no-pager -n 25 2>/dev/null || true ;;
    esac
    DRY_RUN=0
    stage_verify || exit $?
    exit 0
fi

# --- run --------------------------------------------------------------------
say "$PROGRAM $VERSION"
(( DRY_RUN )) && note "dry run: nothing will be installed (add --yes to proceed)"

stage_preflight
stage_network_note
stage_install

VERIFY_RC=0
stage_verify || VERIFY_RC=$?

head1 "Result"
if (( DRY_RUN )); then
    say "  dry run: nothing was installed"
    say "  Re-run with --yes to proceed."
    exit 0
fi

say "  Log: $LOG_FILE"
if (( VERIFY_RC == 0 )); then
    say ""
    pass "a minimal desktop is installed"
    say ""
    say "Next:"
    say "  sudo systemctl isolate graphical.target    # greeter now, no reboot"
    say ""
    say "  # SSSD and the Smart Card packages are installed separately:"
    say "  sudo sssd-smartcard-setup --only packages,join,identity --yes"
    say ""
    note "before rebooting, check the interface still has its address:"
    note "    ip -4 addr show $IFACE"
    note "and keep console access to the machine when you do reboot"
else
    say ""
    fail "installed, but verification did not pass -- see the findings above"
fi

if (( DO_REBOOT )); then
    say ""
    warn "rebooting in 5 seconds (--reboot); this session will drop"
    sleep 5
    systemctl reboot
fi

exit $VERIFY_RC
