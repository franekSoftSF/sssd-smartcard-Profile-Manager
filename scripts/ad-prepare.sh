#!/usr/bin/env bash
#
# ad-prepare.sh -- point a workstation at Active Directory DNS and give it the
# name the domain expects, before anything tries to join.
#
# A domain join fails for two boring reasons far more often than for
# interesting ones: the host cannot resolve the domain's SRV records, or it does
# not know its own fully qualified name.  Both are fixed here, verified here,
# and rolled back here if the fix does not hold.
#
# What this deliberately does NOT do: bounce the network interface.  Every
# obvious way to persist DNS settings -- `nmcli con up`, `netplan apply` --
# briefly drops the link, which over SSH means losing the session that is
# running this script, usually at the exact moment the configuration is half
# applied.  So the new resolver is applied at runtime through resolvectl, which
# does not touch the link, and written to the right config file for the next
# boot.  Pass --apply-now to accept the bounce.
#
# Tested behaviours this script is built around:
#   * /etc/resolv.conf is often a symlink into systemd-resolved's stub.  Writing
#     it directly appears to work and is silently reverted; the script refuses.
#   * Setting a hostname without a matching /etc/hosts line makes every later
#     sudo print "unable to resolve host" and wait on a DNS timeout first.  The
#     two are changed together.
#   * `cmd | head` under `set -o pipefail` fails with SIGPIPE when the producer
#     is still writing.  Output goes to files, never into head.
#   * `grep -c` exits non-zero when it counts zero, which turns `$(grep -c ...)`
#     into an error under `set -e`.  Counting is done with || true.
#
set -Eeuo pipefail

PROGRAM=${0##*/}
VERSION="0.2.8"

if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
    echo "$PROGRAM needs bash 4.4 or newer (found ${BASH_VERSION})" >&2
    exit 1
fi

# --- settings ---------------------------------------------------------------
DOMAIN=""
DNS_SERVERS=()
SEARCH_DOMAINS=()
NEW_HOSTNAME=""
IFACE=""
DRY_RUN=1
ASSUME_YES=0
DO_VERIFY=1
APPLY_NOW=0
CHECK_ONLY=0
ROLLBACK_DIR=""
LOG_FILE="/var/log/${PROGRAM%.sh}.log"
BACKUP_ROOT="/var/lib/sssd-smartcard/backups"
BACKUP_DIR=""
RESOLVER_BACKEND=""
NETPLAN_FILE="/etc/netplan/99-ad-dns.yaml"
NETPLAN_CHECK="${TMPDIR:-/tmp}/ad-prepare-netplan.$$"
FAILED_STAGE=""
CHANGED=0

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

# The redirect has to be inside the group: `cmd >>file 2>/dev/null` suppresses
# the command's stderr, not bash's own "Permission denied" for the redirection,
# which otherwise leaks on every call when the log is not writable.
log()   { [[ -n "$LOG_FILE" ]] || return 0
          { printf '%s\n' "$*" >>"$LOG_FILE"; } 2>/dev/null || true; }
say()   { printf '%s\n' "$*"; log "$*"; }
pass()  { printf '%s[ OK ]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; log "[OK] $*"; }
warn()  { printf '%s[WARN]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; log "[WARN] $*"; }
fail()  { printf '%s[FAIL]%s %s\n' "$C_RED" "$C_RESET" "$*"; log "[FAIL] $*"; }
skip()  { printf '%s[SKIP] %s%s\n' "$C_DIM" "$*" "$C_RESET"; log "[SKIP] $*"; }
note()  { printf '%s   %s%s\n' "$C_DIM" "$*" "$C_RESET"; log "[note] $*"; }
head1() { printf '\n%s%s%s\n' "$C_BOLD" "$*" "$C_RESET"; log "== $* =="; }

die() { fail "$*"; exit 1; }

on_err() {
    local rc=$?
    fail "aborted in stage '${FAILED_STAGE:-unknown}' (exit $rc)"
    if (( CHANGED )) && [[ -n "$BACKUP_DIR" ]]; then
        warn "changes were already written; restoring from $BACKUP_DIR"
        do_rollback "$BACKUP_DIR" || fail "rollback itself failed -- inspect $BACKUP_DIR by hand"
    fi
    note "log: $LOG_FILE"
    exit "$rc"
}
# -E so the trap also fires inside functions.
trap on_err ERR

usage() {
    cat <<EOF
$PROGRAM $VERSION -- prepare a workstation for an Active Directory join.

Sets the DNS servers and search domain to the domain controllers, gives the host
its fully qualified name, and then proves the domain is actually reachable.

USAGE
  sudo $PROGRAM --domain ad.example.com --dns 10.0.0.10 [options]
  sudo $PROGRAM --check --domain ad.example.com
  sudo $PROGRAM --rollback /var/lib/sssd-smartcard/backups/<stamp>

ENVIRONMENT FILE
  --init-env             Write the environment file and exit. With --domain it
                         discovers the domain controllers from that domain's
                         SRV records and uses them as the DNS servers, derives
                         the realm, reads this host's name and works out
                         whether it is a desktop or a server. --dns overrides
                         the discovery. --env chooses the path.
  --env FILE             Read the domain, DNS, hostname and search domains
                         from FILE. Without it, $ENV_DEFAULT_PATH is used when
                         it exists. Command-line flags override the file.

REQUIRED (unless given in the environment file)
  --domain FQDN          AD DNS domain, e.g. ad.example.com
  --dns IP[,IP...]       Domain controller DNS servers. Repeatable.

OPTIONAL
  --hostname NAME        Short name or FQDN for this host. Without it the
                         current hostname is kept and only /etc/hosts is fixed.
  --search DOM[,DOM...]  DNS search domains (default: --domain).
  --iface NAME           Interface to configure (default: the one with the
                         default route).
  --apply-now            Also restart networking so persistence takes effect
                         immediately. This can drop an SSH session.
  --check                Diagnose only. Changes nothing, ignores --yes.
  --dry-run              Show what would change (the default without --yes).
  --yes                  Actually apply.
  --no-verify            Skip the verification stage.
  --rollback DIR         Restore a backup made by an earlier run and exit.
  --log FILE             Log file (default: $LOG_FILE).
  -h, --help             This text.
  --version              Print the version.

EXAMPLES
  # Look first, change nothing:
  sudo $PROGRAM --domain ad.example.com --dns 10.0.0.10 --hostname wks01 --dry-run

  # Apply, keeping the SSH session alive (persistence lands at next boot):
  sudo $PROGRAM --domain ad.example.com --dns 10.0.0.10,10.0.0.11 \\
       --hostname wks01 --yes

  # Then join and configure SSSD with the other script:
  sudo sssd-smartcard-setup --only packages,join,identity \\
       --realm AD.EXAMPLE.COM --join-user administrator \\
       --test-user someone@ad.example.com --yes
EOF
}

# --- discovery for --init-env -----------------------------------------------
# An AD domain names its own domain controllers in SRV records, and in almost
# every deployment those are also the DNS servers. So given the domain, the
# rest of the DNS configuration is derivable -- provided the resolver in use
# right now can see the zone at all, which is the one thing this cannot assume.
discover_dns_servers() {
    local domain=$1 out ip host
    local -a found=()
    out="${TMPDIR:-/tmp}/$PROGRAM.disc.$$"

    if have dig; then
        # The domain controllers, then their addresses.
        dig +short +timeout=5 SRV "_ldap._tcp.$domain" >"$out" 2>/dev/null || true
        while read -r _ _ _ host; do
            [[ -n "${host:-}" ]] || continue
            host=${host%.}
            dig +short +timeout=5 A "$host" >"$out.a" 2>/dev/null || true
            while read -r ip; do
                [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && found+=("$ip")
            done <"$out.a"
            rm -f "$out.a"
        done <"$out"

        # Fall back to the zone's nameservers, then to the domain's own A
        # records: an AD domain usually resolves to its DCs.
        if (( ${#found[@]} == 0 )); then
            dig +short +timeout=5 NS "$domain" >"$out" 2>/dev/null || true
            while read -r host; do
                [[ -n "${host:-}" ]] || continue
                host=${host%.}
                dig +short +timeout=5 A "$host" >"$out.a" 2>/dev/null || true
                while read -r ip; do
                    [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && found+=("$ip")
                done <"$out.a"
                rm -f "$out.a"
            done <"$out"
        fi
        if (( ${#found[@]} == 0 )); then
            dig +short +timeout=5 A "$domain" >"$out" 2>/dev/null || true
            while read -r ip; do
                [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && found+=("$ip")
            done <"$out"
        fi
    fi
    rm -f "$out" "$out.a"

    # Deduplicate, keeping order.
    local -a unique=()
    for ip in "${found[@]:-}"; do
        [[ -n "$ip" ]] || continue
        local seen=0 u
        for u in "${unique[@]:-}"; do [[ "$u" == "$ip" ]] && seen=1; done
        (( seen )) || unique+=("$ip")
    done
    (( ${#unique[@]} )) || return 1
    local IFS=','
    printf '%s' "${unique[*]}"
}

discover_role() {
    # A machine already running a display manager, or defaulting to the
    # graphical target, is a desktop. Everything else is treated as a server,
    # which is the safer default: the desktop installer refuses to run on one.
    local target
    target=$(systemctl get-default 2>/dev/null || true)
    if [[ "$target" == "graphical.target" ]]; then
        printf 'desktop'
        return 0
    fi
    if systemctl is-active gdm3 >/dev/null 2>&1 ||
       systemctl is-active gdm >/dev/null 2>&1 ||
       systemctl is-active lightdm >/dev/null 2>&1; then
        printf 'desktop'
        return 0
    fi
    printf 'server'
}

# --- helpers ----------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

split_list() {
    # "a,b , c" -> one per line, blanks dropped.
    local IFS=','
    local item
    for item in $1; do
        item="${item// /}"
        [[ -n "$item" ]] && printf '%s\n' "$item"
    done
}

is_ipv4() {
    local ip=$1 octet
    [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    for octet in $ip; do (( octet <= 255 )) || return 1; done
    return 0
}

# Sets the global BACKUP_DIR. Deliberately NOT called through $(...):
# command substitution runs in a subshell, so the assignment would be lost in
# the parent, every backup_file call would mint a fresh timestamped directory,
# and a run whose backups straddled a second boundary would scatter them across
# two directories -- leaving --rollback able to restore only half the change.
ensure_backup_dir() {
    [[ -n "$BACKUP_DIR" ]] && return 0
    BACKUP_DIR="$BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    chmod 0700 "$BACKUP_DIR"
    return 0
}

backup_file() {
    local path=$1
    ensure_backup_dir
    if [[ -e "$path" ]]; then
        cp -a "$path" "$BACKUP_DIR/${path//\//_}"
        printf '%s\n' "$path" >>"$BACKUP_DIR/manifest"
        note "backed up $path"
    else
        printf '%s\n' "$path" >>"$BACKUP_DIR/absent"
        note "$path does not exist yet; rollback will remove it"
    fi
}

do_rollback() {
    local dir=$1
    [[ -d "$dir" ]] || { fail "no such backup directory: $dir"; return 1; }
    # Backup directories are timestamped per second and shared with the
    # sssd-smartcard CLI, so a plausible-looking directory may belong to a
    # different program entirely -- pointing --rollback at one used to report
    # success while restoring nothing at all.
    if [[ ! -r "$dir/manifest" && ! -r "$dir/absent" ]]; then
        fail "$dir holds no $PROGRAM backup (no manifest or absent list)"
        note "contents: $(ls -1 "$dir" 2>/dev/null | tr '
' ' ')"
        note "this directory was probably written by another tool; pick the one"
        note "whose path this script printed under 'Backups:'"
        return 1
    fi
    local path dest
    if [[ -r "$dir/manifest" ]]; then
        while IFS= read -r path; do
            dest="$dir/${path//\//_}"
            [[ -e "$dest" ]] || continue
            cp -a "$dest" "$path"
            pass "restored $path"
        done <"$dir/manifest"
    fi
    if [[ -r "$dir/absent" ]]; then
        while IFS= read -r path; do
            if [[ -e "$path" ]]; then
                rm -f "$path"
                pass "removed $path (did not exist before)"
            fi
        done <"$dir/absent"
    fi
    if have hostnamectl && [[ -r "$dir/_etc_hostname" ]]; then
        hostnamectl set-hostname "$(cat "$dir/_etc_hostname")" || true
    fi
    if have netplan && [[ -r "$dir/manifest" ]] && grep -q netplan "$dir/manifest" 2>/dev/null; then
        note "run 'netplan apply' or reboot to put the restored netplan config into effect"
    fi
    return 0
}

# --- stages -----------------------------------------------------------------
stage_preflight() {
    FAILED_STAGE="preflight"
    head1 "Preflight"

    (( EUID == 0 )) || die "must run as root (try: sudo $PROGRAM ...)"
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE=/dev/null

    [[ -n "$DOMAIN" ]] || die "--domain is required"
    [[ ${DOMAIN,,} == *.* ]] || die "--domain must be a DNS domain, e.g. ad.example.com (got '$DOMAIN')"
    DOMAIN=${DOMAIN,,}
    if (( ! CHECK_ONLY )); then
        (( ${#DNS_SERVERS[@]} )) || die "--dns is required (one or more domain controller addresses)"
    fi

    local ip
    for ip in "${DNS_SERVERS[@]}"; do
        is_ipv4 "$ip" || die "--dns: '$ip' is not an IPv4 address"
    done
    (( ${#SEARCH_DOMAINS[@]} )) || SEARCH_DOMAINS=("$DOMAIN")

    # Interface carrying the default route, unless told otherwise.
    if [[ -z "$IFACE" ]]; then
        local route_out="${TMPDIR:-/tmp}/$PROGRAM.route.$$"
        if have ip && ip route show default >"$route_out" 2>/dev/null; then
            IFACE=$(awk '/^default/ {for (i=1;i<NF;i++) if ($i=="dev") {print $(i+1); exit}}' "$route_out")
        fi
        rm -f "$route_out"
    fi
    [[ -n "$IFACE" ]] || die "could not determine the network interface; pass --iface"
    pass "interface: $IFACE"

    detect_resolver_backend
    pass "resolver persistence: $RESOLVER_BACKEND"

    [[ -n "${ENV_ROLE:-}" ]] && pass "role: $ENV_ROLE"

    # Two machines in one domain must not share a hostname: the second join
    # takes over the first machine's account in AD, and the first then fails
    # Kerberos with a KVNO mismatch that looks like nothing to do with names.
    if [[ -n "$NEW_HOSTNAME" ]] && have dig; then
        local existing="${TMPDIR:-/tmp}/$PROGRAM.host.$$"
        dig +short +timeout=5 A "${NEW_HOSTNAME%%.*}.$DOMAIN" >"$existing" 2>/dev/null || true
        local other mine
        other=$(awk '/^[0-9]+\./ {print; exit}' "$existing" 2>/dev/null || true)
        mine=$(ip -4 -o addr show "$IFACE" 2>/dev/null |
               awk '{split($4,a,"/"); print a[1]; exit}' || true)
        rm -f "$existing"
        if [[ -n "$other" && -n "$mine" && "$other" != "$mine" ]]; then
            warn "${NEW_HOSTNAME%%.*}.$DOMAIN already resolves to $other, not $mine"
            note "another machine may already use this name. Joining with it takes"
            note "over that account in AD and breaks Kerberos on the other host."
        fi
    fi

    # In --check mode no --dns is given, so test whatever the host is using
    # now: those are the servers that have to answer for the AD zone.
    if (( CHECK_ONLY )) && (( ${#DNS_SERVERS[@]} == 0 )); then
        local live
        for live in $(current_dns); do
            is_ipv4 "$live" && DNS_SERVERS+=("$live")
        done
        (( ${#DNS_SERVERS[@]} )) && pass "checking the live servers: ${DNS_SERVERS[*]}"
    fi

    local missing=()
    have hostnamectl || missing+=("hostnamectl (systemd)")
    have ip || missing+=("ip (iproute2)")
    (( ${#missing[@]} == 0 )) || die "missing required tools: ${missing[*]}"

    if ! have resolvectl && [[ "$RESOLVER_BACKEND" != "resolv.conf" ]]; then
        warn "resolvectl is not available, so the new DNS cannot be applied without"
        warn "restarting networking. --apply-now will be required."
    fi
    for tool in dig host getent nslookup; do
        have "$tool" && { pass "DNS lookup tool: $tool"; break; }
    done
}

detect_resolver_backend() {
    # systemd-resolved owns /etc/resolv.conf when it is a symlink into /run.
    local resolved_active=0
    if have systemctl && [[ "$(systemctl is-active systemd-resolved 2>/dev/null || true)" == "active" ]]; then
        resolved_active=1
    fi

    # Is this interface NetworkManager's?  On a server install NM is often
    # installed but leaves the interface unmanaged, in which case netplan plus
    # systemd-networkd is in charge and nmcli changes would do nothing.
    local nm_state=""
    if have nmcli; then
        nm_state=$(nmcli -g GENERAL.STATE device show "$IFACE" 2>/dev/null || true)
    fi

    if [[ -n "$nm_state" ]] && [[ "$nm_state" != *unmanaged* ]] && [[ -n "$nm_state" ]]; then
        RESOLVER_BACKEND="NetworkManager"
    elif have netplan && compgen -G "/etc/netplan/*.yaml" >/dev/null 2>&1; then
        RESOLVER_BACKEND="netplan"
    elif (( resolved_active )); then
        RESOLVER_BACKEND="systemd-resolved"
    elif [[ -f /etc/resolv.conf && ! -L /etc/resolv.conf ]]; then
        RESOLVER_BACKEND="resolv.conf"
    else
        RESOLVER_BACKEND="unknown"
    fi
}

current_dns() {
    if have resolvectl; then
        local out="${TMPDIR:-/tmp}/$PROGRAM.dns.$$"
        resolvectl dns "$IFACE" >"$out" 2>/dev/null || true
        sed -e 's/^.*): *//' "$out" 2>/dev/null | tr -s ' '
        rm -f "$out"
    elif [[ -r /etc/resolv.conf ]]; then
        awk '/^nameserver/ {printf "%s ", $2} END {print ""}' /etc/resolv.conf
    fi
}

stage_hostname() {
    FAILED_STAGE="hostname"
    head1 "Hostname"

    local current short fqdn
    current=$(hostnamectl --static 2>/dev/null || hostname)
    short=${NEW_HOSTNAME:-$current}
    short=${short%%.*}
    fqdn="$short.$DOMAIN"

    say "  current static hostname: $current"
    say "  target short name:       $short"
    say "  target FQDN:             $fqdn"

    # The /etc/hosts line matters as much as the hostname.  Without it, sudo
    # prints "unable to resolve host" and waits for a DNS timeout on every call.
    local hosts_line="127.0.1.1 $fqdn $short"
    local hosts_ok=0
    if grep -qE "^127\.0\.1\.1[[:space:]]+${fqdn//./\\.}([[:space:]]|$)" /etc/hosts 2>/dev/null; then
        hosts_ok=1
    fi

    if [[ "$current" == "$short" ]] && (( hosts_ok )); then
        pass "hostname and /etc/hosts are already correct"
        return 0
    fi

    if (( DRY_RUN )); then
        [[ "$current" != "$short" ]] && note "would run: hostnamectl set-hostname $short"
        (( hosts_ok )) || note "would add to /etc/hosts: $hosts_line"
        return 0
    fi

    backup_file /etc/hosts
    backup_file /etc/hostname
    CHANGED=1

    if ! (( hosts_ok )); then
        # Replace any existing 127.0.1.1 line rather than accumulating them.
        local tmp
        tmp=$(mktemp)
        awk -v line="$hosts_line" '
            BEGIN { done = 0 }
            /^127\.0\.1\.1[[:space:]]/ { if (!done) { print line; done = 1 } ; next }
            { print }
            END { if (!done) print line }
        ' /etc/hosts >"$tmp"
        cat "$tmp" >/etc/hosts
        rm -f "$tmp"
        pass "/etc/hosts: $hosts_line"
    fi

    if [[ "$current" != "$short" ]]; then
        hostnamectl set-hostname "$short"
        pass "hostname set to $short"
    fi

    local resolved
    resolved=$(hostname -f 2>/dev/null || true)
    if [[ "$resolved" == "$fqdn" ]]; then
        pass "hostname -f resolves to $fqdn"
    else
        warn "hostname -f returns '${resolved:-nothing}', expected $fqdn"
        note "harmless if DNS is not pointed at AD yet; the DNS stage comes next"
    fi
}

stage_dns() {
    FAILED_STAGE="dns"
    head1 "DNS"

    local before
    before=$(current_dns)
    say "  current servers:  ${before:-unknown}"
    say "  target servers:   ${DNS_SERVERS[*]}"
    say "  search domains:   ${SEARCH_DOMAINS[*]}"
    say "  persistence:      $RESOLVER_BACKEND"

    if [[ -L /etc/resolv.conf ]]; then
        local target
        target=$(readlink -f /etc/resolv.conf 2>/dev/null || true)
        note "/etc/resolv.conf -> $target (managed; this script will not write it directly)"
    fi

    if (( DRY_RUN )); then
        have resolvectl && note "would run: resolvectl dns $IFACE ${DNS_SERVERS[*]}"
        have resolvectl && note "would run: resolvectl domain $IFACE ${SEARCH_DOMAINS[*]}"
        case "$RESOLVER_BACKEND" in
            netplan)        note "would write $NETPLAN_FILE" ;;
            NetworkManager) note "would run: nmcli con mod <conn> ipv4.dns / ipv4.dns-search" ;;
            resolv.conf)    note "would write /etc/resolv.conf" ;;
            *)              warn "no persistence method detected; the change would not survive a reboot" ;;
        esac
        return 0
    fi

    # Runtime first, because it takes effect without touching the link.
    if have resolvectl; then
        resolvectl dns "$IFACE" "${DNS_SERVERS[@]}"
        resolvectl domain "$IFACE" "${SEARCH_DOMAINS[@]}"
        resolvectl flush-caches 2>/dev/null || true
        CHANGED=1
        pass "applied at runtime via resolvectl (no interface bounce)"
    fi

    persist_dns
}

persist_dns() {
    case "$RESOLVER_BACKEND" in
    netplan)
        backup_file "$NETPLAN_FILE"
        CHANGED=1
        {
            printf '# Written by %s on %s. Removing this file restores DHCP DNS.\n' \
                "$PROGRAM" "$(date -Is)"
            printf 'network:\n  version: 2\n  ethernets:\n    %s:\n' "$IFACE"
            printf '      nameservers:\n        addresses: [%s]\n' \
                "$(IFS=,; echo "${DNS_SERVERS[*]}")"
            printf '        search: [%s]\n' "$(IFS=,; echo "${SEARCH_DOMAINS[*]}")"
            # Without this, a DHCP-supplied resolver silently wins again.
            printf '      dhcp4-overrides:\n        use-dns: false\n'
        } >"$NETPLAN_FILE"
        chmod 0600 "$NETPLAN_FILE"
        pass "wrote $NETPLAN_FILE (mode 0600)"

        # Writing valid-looking YAML is not the same as netplan accepting it.
        # `netplan generate` parses every file in /etc/netplan and renders the
        # backend configuration without touching the running network, so it is
        # the cheapest way to find out that this file would break networking at
        # the next boot -- which is exactly when nobody is watching. A failure
        # here trips the ERR trap and rolls the file back.
        if netplan generate >"$NETPLAN_CHECK" 2>&1; then
            pass "netplan generate accepts the configuration"
            rm -f "$NETPLAN_CHECK"
        else
            fail "netplan rejected $NETPLAN_FILE:"
            sed -e 's/^/       /' "$NETPLAN_CHECK" || true
            rm -f "$NETPLAN_CHECK"
            return 1
        fi

        if (( APPLY_NOW )); then
            warn "running 'netplan apply' -- this may drop an SSH session"
            netplan apply
            pass "netplan applied"
        else
            note "takes effect at next boot; the runtime setting above is already live"
            note "to apply the persisted config now: netplan apply  (may drop SSH)"
        fi
        ;;
    NetworkManager)
        local conn
        conn=$(nmcli -g GENERAL.CONNECTION device show "$IFACE" 2>/dev/null || true)
        if [[ -z "$conn" || "$conn" == "--" ]]; then
            warn "no NetworkManager connection is active on $IFACE; cannot persist"
            return 0
        fi
        CHANGED=1
        nmcli con mod "$conn" ipv4.dns "$(IFS=,; echo "${DNS_SERVERS[*]}")"
        nmcli con mod "$conn" ipv4.dns-search "$(IFS=,; echo "${SEARCH_DOMAINS[*]}")"
        nmcli con mod "$conn" ipv4.ignore-auto-dns yes
        pass "persisted in NetworkManager connection '$conn'"
        if (( APPLY_NOW )); then
            warn "reactivating '$conn' -- this may drop an SSH session"
            nmcli con up "$conn" >/dev/null
            pass "connection reactivated"
        else
            note "takes effect at next boot or 'nmcli con up $conn' (may drop SSH)"
        fi
        ;;
    resolv.conf)
        backup_file /etc/resolv.conf
        CHANGED=1
        {
            printf '# Written by %s on %s\n' "$PROGRAM" "$(date -Is)"
            local ip dom
            for ip in "${DNS_SERVERS[@]}"; do printf 'nameserver %s\n' "$ip"; done
            printf 'search %s\n' "${SEARCH_DOMAINS[*]}"
            for dom in "${SEARCH_DOMAINS[@]}"; do printf 'domain %s\n' "$dom"; break; done
        } >/etc/resolv.conf
        pass "wrote /etc/resolv.conf"
        ;;
    systemd-resolved)
        warn "systemd-resolved is active but no netplan or NetworkManager config was found"
        note "the runtime setting is live; to persist it, add the servers to the"
        note "configuration of whatever brings up $IFACE"
        ;;
    *)
        warn "unknown resolver management; the runtime change will not survive a reboot"
        ;;
    esac
}

stage_verify() {
    FAILED_STAGE="verify"
    head1 "Verification"

    if (( DRY_RUN )); then
        skip "verification (dry run -- nothing was changed to verify)"
        return 0
    fi

    local rc=0
    local tmp="${TMPDIR:-/tmp}/$PROGRAM.verify.$$"
    mkdir -p "$tmp"

    # SRV records are what a join actually looks up.
    local srv found
    for srv in "_ldap._tcp.$DOMAIN" "_kerberos._tcp.$DOMAIN"; do
        found=0
        # Output to a file: piping into head trips SIGPIPE under pipefail.
        if have dig; then
            dig +short +timeout=5 SRV "$srv" >"$tmp/srv" 2>/dev/null || true
        elif have host; then
            host -t SRV "$srv" >"$tmp/srv" 2>/dev/null || true
        else
            nslookup -type=SRV "$srv" >"$tmp/srv" 2>/dev/null || true
        fi
        # grep -c exits 1 on zero matches, which would abort under set -e.
        local n
        n=$(grep -c . "$tmp/srv" 2>/dev/null || true)
        n=${n:-0}
        if (( n > 0 )); then
            pass "$srv resolves ($n record(s))"
            found=1
        fi
        if (( ! found )); then
            fail "$srv does not resolve"
            note "the DNS servers given do not serve this AD zone, or the domain name is wrong"
            rc=1
        fi
    done

    # Does each configured server actually answer for this zone? A server
    # that is reachable but not authoritative for the AD zone looks fine in
    # resolvectl and fails every join.
    if (( ${#DNS_SERVERS[@]} )) && have dig; then
        local server
        for server in "${DNS_SERVERS[@]}"; do
            dig "@$server" +short +timeout=5 SOA "$DOMAIN" >"$tmp/soa" 2>/dev/null || true
            local soa_n
            soa_n=$(grep -c . "$tmp/soa" 2>/dev/null || true)
            if (( ${soa_n:-0} > 0 )); then
                pass "$server answers for $DOMAIN"
            else
                fail "$server does not answer for $DOMAIN"
                note "it is reachable but not serving the AD zone -- wrong server,"
                note "or the zone is not published to it"
                rc=1
            fi
        done
    fi

    # The host's own name must resolve, because Kerberos host principals and
    # GPO targeting are both built from it. Before a join the DC has usually
    # not created the record yet, so this is a warning, not a failure.
    local fqdn_now
    fqdn_now=$(hostname -f 2>/dev/null || true)
    if [[ "$fqdn_now" == *.* ]]; then
        local resolved_ip=""
        if have dig; then
            dig +short +timeout=5 A "$fqdn_now" >"$tmp/own" 2>/dev/null || true
            resolved_ip=$(awk '/^[0-9]+\./ {print; exit}' "$tmp/own" 2>/dev/null || true)
        elif have getent; then
            getent hosts "$fqdn_now" >"$tmp/own" 2>/dev/null || true
            resolved_ip=$(awk '{print $1; exit}' "$tmp/own" 2>/dev/null || true)
        fi
        if [[ -n "$resolved_ip" ]]; then
            pass "$fqdn_now resolves to $resolved_ip"
            local own_ip
            own_ip=$(ip -4 -o addr show "$IFACE" 2>/dev/null |
                     awk '{split($4,a,"/"); print a[1]; exit}' || true)
            if [[ -n "$own_ip" && "$own_ip" != "$resolved_ip" ]]; then
                warn "DNS says $resolved_ip but $IFACE has $own_ip"
                note "a stale A record. The DC normally replaces it at join time;"
                note "if it does not, remove it in DNS or the host principal will"
                note "not match."
            fi
        else
            warn "$fqdn_now does not resolve in DNS yet"
            note "expected before a join: the domain controller creates the record"
            note "via dynamic DNS when the host joins. Re-check afterwards."
        fi
    fi

    # Ports a join needs on at least one DC.
    local dc
    dc=$(awk '{print $NF}' "$tmp/srv" 2>/dev/null | sed 's/\.$//' | head -n 1 || true)
    if [[ -n "$dc" ]]; then
        local port name
        for port in 88:Kerberos 389:LDAP 445:SMB 464:kpasswd; do
            name=${port#*:}; port=${port%%:*}
            if timeout 5 bash -c "exec 3<>/dev/tcp/$dc/$port" 2>/dev/null; then
                pass "$dc:$port reachable ($name)"
            else
                fail "$dc:$port unreachable ($name)"
                rc=1
            fi
        done

        # Kerberos refuses tickets outside a five-minute skew.
        if have chronyc || have timedatectl; then
            local sync
            sync=$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)
            if [[ "$sync" == "yes" ]]; then
                pass "clock is NTP synchronised"
            else
                warn "clock is not NTP synchronised; Kerberos rejects a skew over ~5 minutes"
                note "point NTP at the domain controller: timedatectl set-ntp true"
            fi
        fi
    else
        warn "no domain controller hostname could be read from the SRV records"
    fi

    local fqdn
    fqdn=$(hostname -f 2>/dev/null || true)
    if [[ "$fqdn" == *.* ]]; then
        pass "hostname -f: $fqdn"
        # Qualified but in some other zone. Not fatal -- a host may legitimately
        # carry a different DNS suffix -- but it is worth saying, because it
        # affects the host principal the KDC expects and how GPOs target the
        # machine, and a leftover suffix from a previous environment is easy to
        # miss.
        local suffix=${fqdn#*.}
        if [[ "${suffix,,}" != "${DOMAIN,,}" ]]; then
            warn "the DNS suffix is '$suffix', not '$DOMAIN'"
            note "this works, but the host principal and GPO targeting follow the"
            note "AD domain. To align it: --hostname ${fqdn%%.*}"
        fi
    else
        fail "hostname -f returns '${fqdn:-nothing}', not a fully qualified name"
        note "a join needs an FQDN; re-run with --hostname <name>"
        rc=1
    fi

    rm -rf "$tmp"
    return $rc
}

# --- argument parsing -------------------------------------------------------
while (( $# )); do
    case $1 in
        --domain)    DOMAIN="${2:?--domain needs a value}"; shift ;;
        --dns)       while IFS= read -r x; do DNS_SERVERS+=("$x"); done < <(split_list "${2:?--dns needs a value}"); shift ;;
        --search)    while IFS= read -r x; do SEARCH_DOMAINS+=("$x"); done < <(split_list "${2:?--search needs a value}"); shift ;;
        --hostname)  NEW_HOSTNAME="${2:?--hostname needs a value}"; shift ;;
        --iface)     IFACE="${2:?--iface needs a value}"; shift ;;
        --apply-now) APPLY_NOW=1 ;;
        --check)     CHECK_ONLY=1; DRY_RUN=1 ;;
        --dry-run)   DRY_RUN=1 ;;
        --yes)       DRY_RUN=0; ASSUME_YES=1 ;;
        --no-verify) DO_VERIFY=0 ;;
        --rollback)  ROLLBACK_DIR="${2:?--rollback needs a directory}"; shift ;;
        --log)       LOG_FILE="${2:?--log needs a path}"; shift ;;
        --env)       ENV_PATH="${2:?--env needs a path}"; shift ;;
        --init-env)  ENV_INIT=1 ;;
        -h|--help)   usage; exit 0 ;;
        --version)   printf '%s %s\n' "$PROGRAM" "$VERSION"; exit 0 ;;
        *)           die "unknown option: $1 (try --help)" ;;
    esac
    shift
done

say "$PROGRAM $VERSION"

if (( ${ENV_INIT:-0} )); then
    (( EUID == 0 )) || die "writing the environment file needs root"
    ENV_TARGET="${ENV_PATH:-$(env_default_path)}"
    declare -a INIT_ARGS=()

    if [[ -n "$DOMAIN" ]]; then
        DOMAIN=${DOMAIN,,}
        INIT_ARGS+=("domain=$DOMAIN" "realm=${DOMAIN^^}" "search=$DOMAIN")
        head1 "Discovering $DOMAIN"

        if (( ${#DNS_SERVERS[@]} )); then
            INIT_ARGS+=("dns=$(IFS=,; echo "${DNS_SERVERS[*]}")")
            pass "DNS servers given on the command line: ${DNS_SERVERS[*]}"
        elif FOUND_DNS=$(discover_dns_servers "$DOMAIN"); then
            INIT_ARGS+=("dns=$FOUND_DNS")
            pass "domain controllers found: ${FOUND_DNS//,/ }"
            note "from the SRV records of $DOMAIN; in AD these are normally the"
            note "DNS servers too. Add or replace them in the file if not."
        else
            warn "could not resolve any domain controller for $DOMAIN"
            note "the resolver this machine uses now cannot see that zone, which"
            note "is expected before it is pointed at AD. The file keeps the"
            note "example address -- replace it with the real one."
        fi

        INIT_ARGS+=("test_user=someone@$DOMAIN")
    else
        note "no --domain given, so nothing can be discovered; writing the template"
        note "re-run as: $PROGRAM --init-env --domain ad.example.com"
    fi

    SHORT_HOST=$(hostnamectl --static 2>/dev/null || hostname)
    SHORT_HOST=${SHORT_HOST%%.*}
    [[ -n "${NEW_HOSTNAME:-}" ]] && SHORT_HOST=${NEW_HOSTNAME%%.*}
    INIT_ARGS+=("hostname=$SHORT_HOST")
    pass "hostname: $SHORT_HOST"

    DISCOVERED_ROLE=$(discover_role)
    INIT_ARGS+=("role=$DISCOVERED_ROLE" "desktop=$([[ "$DISCOVERED_ROLE" == desktop ]] && echo true || echo false)")
    pass "role: $DISCOVERED_ROLE"

    say ""
    env_init "$ENV_TARGET" "${INIT_ARGS[@]}" || exit 1
    say ""
    note "still to fill in by hand: join_user and test_user."
    note "The ca list is left empty on purpose: 'sssd-smartcard ca discover"
    note "--from-card --install' fills the trust bundle, and the setup script"
    note "keeps an existing bundle. Name files there only to import from disk."
    note "Then: $PROGRAM --check"
    exit 0
fi

# An explicit --env must exist; the conventional path is used when present.
if [[ -n "$ENV_PATH" ]]; then
    env_load "$ENV_PATH" || die "could not read $ENV_PATH"
    pass "environment: $ENV_PATH"
elif [[ -r "$(env_default_path)" ]]; then
    env_load "$(env_default_path)" || die "could not read $(env_default_path)"
    pass "environment: $(env_default_path)"
fi
# Only where the command line said nothing.
[[ -z "$DOMAIN" ]] && DOMAIN=${ENV_DOMAIN:-}
[[ -z "$NEW_HOSTNAME" ]] && NEW_HOSTNAME=${ENV_HOSTNAME:-}
(( ${#DNS_SERVERS[@]} )) || DNS_SERVERS=("${ENV_DNS[@]:-}")
(( ${#SEARCH_DOMAINS[@]} )) || SEARCH_DOMAINS=("${ENV_SEARCH[@]:-}")
# An empty array expansion leaves one empty element behind.
[[ ${#DNS_SERVERS[@]} -eq 1 && -z ${DNS_SERVERS[0]} ]] && DNS_SERVERS=()
[[ ${#SEARCH_DOMAINS[@]} -eq 1 && -z ${SEARCH_DOMAINS[0]} ]] && SEARCH_DOMAINS=()

# A template that was never filled in would otherwise be applied verbatim:
# DNS set to 10.0.0.10, the hostname to wks01, on a real machine.
# Not for --rollback: that restores files and has no interest in the domain,
# yet the guard refused to let it run at all when the environment file still
# held template values.
if [[ -z "$ROLLBACK_DIR" ]] &&
   [[ -n "${ENV_FILE_LOADED:-}" ]] && declare -F env_has_placeholders >/dev/null; then
    # Only the fields this script acts on. The CA paths and notes belong to
    # the setup script and are none of its business.
    PLACEHOLDERS=$(env_has_placeholders domain realm dns search hostname || true)
    if [[ -n "$PLACEHOLDERS" ]]; then
        fail "$ENV_FILE_LOADED still holds template values:"
        printf '%s
' "$PLACEHOLDERS" | sed -e 's/^/       /'
        note "fill them in, or override them on the command line"
        exit 1
    fi
fi

if [[ -n "$ROLLBACK_DIR" ]]; then
    (( EUID == 0 )) || die "rollback must run as root"
    head1 "Rollback from $ROLLBACK_DIR"
    # A refused rollback is a clean "no", not a crash: drop the ERR trap so it
    # does not print "aborted in stage unknown" over a perfectly clear message.
    trap - ERR
    if ! do_rollback "$ROLLBACK_DIR"; then
        exit 1
    fi
    say ""
    pass "restored; reboot or re-apply networking to be sure the resolver matches"
    exit 0
fi

# --- run --------------------------------------------------------------------
(( DRY_RUN )) && note "dry run: nothing will be changed (add --yes to apply)"
(( CHECK_ONLY )) && note "check only: diagnosing, changing nothing"

stage_preflight

if (( CHECK_ONLY )); then
    head1 "Current state"
    say "  interface:        $IFACE"
    say "  DNS servers:      $(current_dns)"
    say "  static hostname:  $(hostnamectl --static 2>/dev/null || hostname)"
    say "  hostname -f:      $(hostname -f 2>/dev/null || echo '(fails)')"
    say "  persistence:      $RESOLVER_BACKEND"
    DRY_RUN=0
    DO_VERIFY=1
    VERIFY_RC=0
    stage_verify || VERIFY_RC=$?
    say ""
    if (( VERIFY_RC == 0 )); then
        pass "this host looks ready to join $DOMAIN"
    else
        fail "this host is not ready to join $DOMAIN"
    fi
    exit $VERIFY_RC
fi

stage_hostname
stage_dns

VERIFY_RC=0
if (( DO_VERIFY )); then
    stage_verify || VERIFY_RC=$?
else
    skip "verification (--no-verify)"
fi

head1 "Result"
if (( DRY_RUN )); then
    say "  dry run: nothing was written"
    say "  Re-run with --yes to apply."
    exit 0
fi

if [[ -n "$BACKUP_DIR" ]]; then
    say "  Backups: $BACKUP_DIR"
else
    say "  Backups: none needed (nothing was overwritten)"
fi
say "  Log:     $LOG_FILE"

if (( VERIFY_RC == 0 )); then
    say ""
    pass "ready to join $DOMAIN"
    say ""
    say "Next:"
    # The setup script reads the same environment file, so with one loaded the
    # command needs nothing but the stage selection. The long form printed a
    # literal <someone> where the test user belongs: a command that had to be
    # edited before it could be run.
    if [[ -n "${ENV_FILE_LOADED:-}" ]]; then
        say "  sudo sssd-smartcard-setup --only packages,join,identity --yes"
        note "realm, join user and test user come from $ENV_FILE_LOADED"
        # No `local` here: this block runs at the top level of the script,
        # where `local` is a runtime error that `bash -n` does not catch.
        missing=""
        [[ -n "${ENV_JOIN_USER:-}" ]] || missing="join_user"
        [[ -n "${ENV_TEST_USER:-}" ]] || missing="${missing:+$missing, }test_user"
        [[ -n "$missing" ]] && warn "still to fill in there: $missing"
    else
        say "  sudo sssd-smartcard-setup --only packages,join,identity \\"
        say "       --realm ${DOMAIN^^} --join-user <account> \\"
        say "       --test-user <a user in $DOMAIN> --yes"
        note "or write the environment file once and drop the flags:"
        note "    sudo $PROGRAM --init-env --domain $DOMAIN"
    fi
else
    say ""
    fail "configuration applied, but verification did not pass"
    note "nothing was rolled back: the settings are correct as given, and the"
    note "failure is upstream (wrong DNS address, wrong domain, firewall, clock)."
    note "To undo: sudo $PROGRAM --rollback $BACKUP_DIR"
fi
exit $VERIFY_RC
