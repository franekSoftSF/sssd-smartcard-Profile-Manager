# shellcheck shell=bash
#
# env.sh -- load a test environment definition from JSON.
#
# Typing --domain, --dns, --hostname, --realm and --test-user on every command
# is how a machine ends up half configured for one domain and half for another.
# The environment is described once, in one file, and every script reads it.
#
# The JSON itself is parsed by env.py next to this file. Hand-rolled JSON
# parsing in shell gets quoting, escapes and nesting wrong in ways that only
# surface with a real value in the file, and the package already depends on
# python3.
#
# Sourced, not executed. Defines:
#   env_default_path    the conventional location
#   env_lib_dir         where this file and env.py live
#   env_load FILE       set ENV_* variables from FILE
#   env_init FILE       write a template
#
# Scalars become ENV_<KEY>, lists become bash arrays ENV_<KEY>[@], booleans
# become 1 or 0. Callers apply them only where the operator gave no explicit
# flag, so a flag on the command line always wins over the file.

ENV_DEFAULT_PATH="/etc/sssd-smartcard/environment.json"

#: Keys the file may contain. Anything else is refused rather than ignored.
ENV_SCALAR_KEYS=(domain realm hostname join_user test_user account_domain
                 sssd_domain desktop_package crl_file role notes sudo_group)
ENV_LIST_KEYS=(dns search ca)
ENV_BOOL_KEYS=(desktop gpo adsys crl ocsp smartcard_required ssh sudo_agent mkhomedir)

env_default_path() { printf '%s' "$ENV_DEFAULT_PATH"; }

# Where env.py is: next to this file when run from a checkout, or the
# installed location.
env_lib_dir() {
    local here="${BASH_SOURCE[0]%/*}"
    if [[ -r "$here/env.py" ]]; then
        printf '%s' "$here"
    elif [[ -r /usr/share/sssd-smartcard/lib/env.py ]]; then
        printf '%s' /usr/share/sssd-smartcard/lib
    else
        printf '%s' "$here"
    fi
}

env_load() {
    local file=$1
    [[ -r "$file" ]] || { printf 'cannot read %s\n' "$file" >&2; return 1; }
    command -v python3 >/dev/null 2>&1 || {
        printf 'python3 is needed to read %s\n' "$file" >&2; return 1; }

    local parser emitted
    parser="$(env_lib_dir)/env.py"
    [[ -r "$parser" ]] || { printf 'missing %s\n' "$parser" >&2; return 1; }

    emitted=$(python3 "$parser" "$file" \
        "${ENV_SCALAR_KEYS[*]}" "${ENV_LIST_KEYS[*]}" "${ENV_BOOL_KEYS[*]}") || return 1

    # eval is safe here: every value was quoted with shlex.quote by env.py.
    eval "$emitted"
    ENV_FILE_LOADED="$file"
    return 0
}

#: Values the template ships with. Acting on them means the file was never
#: filled in, and ad-prepare would happily set DNS to 10.0.0.10 and the
#: hostname to wks01 on a real machine.
ENV_PLACEHOLDERS=(ad.example.com AD.EXAMPLE.COM 10.0.0.10 wks01
                  someone@ad.example.com /root/pki/root-ca.pem
                  /root/pki/issuing-ca.pem
                  "describe this environment so a later run is unambiguous")

# Returns 0 when any loaded value is still a template placeholder, and names
# them on stdout.
#
# Takes the keys to examine. Checking every key would block a script on a field
# it never reads -- ad-prepare refusing to set DNS because the CA paths are
# still examples, when it has no interest in CA paths at all.
env_has_placeholders() {
    local -a scalars=() lists=()
    if (( $# )); then
        local want
        for want in "$@"; do
            local s
            for s in "${ENV_SCALAR_KEYS[@]}"; do
                [[ "$s" == "$want" ]] && scalars+=("$want")
            done
            for s in "${ENV_LIST_KEYS[@]}"; do
                [[ "$s" == "$want" ]] && lists+=("$want")
            done
        done
    else
        scalars=("${ENV_SCALAR_KEYS[@]}")
        lists=("${ENV_LIST_KEYS[@]}")
    fi

    local found=0 key value item
    for key in "${scalars[@]:-}"; do
        [[ -n "$key" ]] || continue
        local var="ENV_${key^^}"
        value=${!var:-}
        [[ -n "$value" ]] || continue
        for item in "${ENV_PLACEHOLDERS[@]}"; do
            if [[ "$value" == "$item" ]]; then
                printf '%s = %s\n' "$key" "$value"
                found=1
            fi
        done
    done
    for key in "${lists[@]:-}"; do
        [[ -n "$key" ]] || continue
        local arr="ENV_${key^^}[@]"
        for value in "${!arr:-}"; do
            [[ -n "$value" ]] || continue
            for item in "${ENV_PLACEHOLDERS[@]}"; do
                if [[ "$value" == "$item" ]]; then
                    printf '%s = %s\n' "$key" "$value"
                    found=1
                fi
            done
        done
    done
    return $(( found ? 0 : 1 ))
}

env_init() {
    local file=$1
    shift || true
    if [[ -e "$file" ]]; then
        printf '%s already exists; not overwriting\n' "$file" >&2
        return 1
    fi
    local parser
    parser="$(env_lib_dir)/env.py"
    [[ -r "$parser" ]] || { printf 'missing %s\n' "$parser" >&2; return 1; }

    local body
    # Remaining arguments are key=value overrides for whatever the caller was
    # able to discover; everything else keeps its example value, so the shape
    # of what is still missing stays visible.
    body=$(python3 "$parser" --init "$@") || return 1

    install -d -m 0755 "${file%/*}"
    printf '%s\n' "$body" >"$file"
    chmod 0644 "$file"
    printf 'wrote %s\n' "$file"
    return 0
}
