#!/usr/bin/env bash
#
# run-tests.sh -- end-to-end acceptance tests, run on the lab client as root.
#
# These are the tests that a setup script must pass before anyone trusts it on a
# real host. They cover the layers this project owns: reading the card, deriving
# a profile, rendering and applying certmap, and mapping the certificate to an
# AD user that SSSD can actually resolve.
#
# Each test states what it proves. A failure prints the command output, because
# "test 7 failed" on its own is useless.

set -Eeuo pipefail

PKI="${LAB_PKI:-/vagrant/pki}"
WORK="/tmp/sssd-smartcard-lab"
mkdir -p "$WORK"

# shellcheck disable=SC1091
[[ -f /root/lab.env ]] && . /root/lab.env
UPN="${UPN:?run provisioning first}"
SOFTHSM_MODULE="${SOFTHSM_MODULE:?}"
export SOFTHSM2_CONF="${SOFTHSM2_CONF:-/etc/softhsm/softhsm2.conf}"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[90m'
    C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
else
    C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""
fi

TESTS=0; PASSED=0; FAILED=0; SKIPPED=0
declare -a FAILURES=()

t_start() { TESTS=$((TESTS + 1)); printf '\n%s[%02d]%s %s\n' "$C_BOLD" "$TESTS" "$C_RESET" "$1"; }
t_pass()  { PASSED=$((PASSED + 1)); printf '     %s✓ %s%s\n' "$C_GREEN" "$1" "$C_RESET"; }
t_fail()  {
    FAILED=$((FAILED + 1))
    FAILURES+=("$1")
    printf '     %s✗ %s%s\n' "$C_RED" "$1" "$C_RESET"
    if [[ -n "${2:-}" ]]; then
        printf '%s\n' "$2" | sed 's/^/       | /' | head -25
    fi
}
t_skip()  { SKIPPED=$((SKIPPED + 1)); printf '     %s- skipped: %s%s\n' "$C_DIM" "$1" "$C_RESET"; }
note()    { printf '     %s%s%s\n' "$C_DIM" "$1" "$C_RESET"; }

# expect_success <label> <command...>
expect_success() {
    local label="$1"; shift
    local out
    if out="$("$@" 2>&1)"; then
        t_pass "$label"
        printf '%s' "$out" >"$WORK/last.out"
        return 0
    fi
    t_fail "$label" "$out"
    printf '%s' "$out" >"$WORK/last.out"
    return 1
}

# expect_failure <label> <command...> -- the command MUST fail
expect_failure() {
    local label="$1"; shift
    local out
    if out="$("$@" 2>&1)"; then
        t_fail "$label (the command unexpectedly succeeded)" "$out"
        return 1
    fi
    t_pass "$label"
    printf '%s' "$out" >"$WORK/last.out"
    return 0
}

# expect_output <label> <pattern> <command...>
expect_output() {
    local label="$1" pattern="$2"; shift 2
    local out
    out="$("$@" 2>&1 || true)"
    if grep -qE "$pattern" <<<"$out"; then
        t_pass "$label"
        return 0
    fi
    t_fail "$label (expected /$pattern/)" "$out"
    return 1
}

printf '%ssssd-smartcard lab acceptance tests%s\n' "$C_BOLD" "$C_RESET"
note "user: $UPN"
note "card: $SOFTHSM_MODULE"
note "pki : $PKI"

# ===========================================================================
# Layer 1: the card
# ===========================================================================

t_start "The emulated card is visible as a PKCS#11 token"
expect_output "card detect finds a token and a certificate" \
    "certificate\(s\) found|PIV-LAB" \
    sssd-smartcard card detect || true

t_start "A certificate can be read off the card without touching the private key"
expect_output "the UPN is read from the SAN otherName" \
    "$UPN" \
    sssd-smartcard cert inspect --from-card --no-config || true

# ===========================================================================
# Layer 2: analysis and configuration derivation
# ===========================================================================

t_start "The tool derives a configuration from the real certificate"
if sssd-smartcard cert autoconfig --from-card \
        --save-profile "$WORK/derived.yaml" >"$WORK/autoconfig.out" 2>&1; then
    t_pass "cert autoconfig succeeded"
    if grep -q "type: san-upn" "$WORK/derived.yaml"; then
        t_pass "san-upn was recommended, which is correct for a UPN certificate"
    else
        t_fail "expected san-upn in the derived profile" "$(cat "$WORK/derived.yaml")"
    fi
    if grep -q "issuer: CN=Enterprise Issuing CA" "$WORK/derived.yaml"; then
        t_pass "the issuing CA was pinned automatically"
    else
        t_fail "the issuer was not pinned" "$(cat "$WORK/derived.yaml")"
    fi
    note "generated section: $(grep -o '\[certmap/[^]]*\]' "$WORK/autoconfig.out" | head -1)"
else
    t_fail "cert autoconfig failed" "$(cat "$WORK/autoconfig.out")"
fi

t_start "The AD SID extension is decoded when the CA issued one"
if [[ -n "${LAB_USER_SID:-}" ]] || grep -q "sid_extension" "$WORK/autoconfig.out" 2>/dev/null; then
    expect_output "the SID from the certificate is reported" \
        "S-1-5-" sssd-smartcard cert inspect --from-card --no-config || true
else
    t_skip "the lab certificate carries no SID extension"
fi

# ===========================================================================
# Layer 3: applying the configuration safely
# ===========================================================================

t_start "A dry run changes nothing"
BEFORE="$(sha256sum /etc/sssd/sssd.conf | cut -d' ' -f1)"
expect_success "setup --dry-run completed" \
    sssd-smartcard-setup --dry-run --non-interactive \
        --test-user "$UPN" --ca "$PKI/ca-chain.pem" || true
AFTER="$(sha256sum /etc/sssd/sssd.conf | cut -d' ' -f1)"
if [[ "$BEFORE" == "$AFTER" ]]; then
    t_pass "sssd.conf is byte-identical after the dry run"
else
    t_fail "the dry run modified sssd.conf"
fi

t_start "The real run configures the host and verifies itself"
if sssd-smartcard-setup --yes --test-user "$UPN" \
        --ca "$PKI/ca-chain.pem" --gpo >"$WORK/setup.out" 2>&1; then
    t_pass "setup completed and its own verification passed"
else
    t_fail "setup reported problems" "$(cat "$WORK/setup.out")"
fi
note "log: $(grep -o '/var/log/sssd-smartcard-setup-[0-9-]*\.log' "$WORK/setup.out" | head -1)"

t_start "sssd.conf is valid, restrictive and contains the rule"
expect_success "sssctl config-check passes" sssctl config-check || true
MODE="$(stat -c '%a' /etc/sssd/sssd.conf)"
if [[ "$MODE" == "600" ]]; then
    t_pass "sssd.conf is mode 0600"
else
    t_fail "sssd.conf is mode $MODE, expected 600"
fi
if grep -q '^\[certmap/' /etc/sssd/sssd.conf; then
    t_pass "a certmap section was written"
    note "$(grep -A4 '^\[certmap/' /etc/sssd/sssd.conf | head -5 | tr '\n' ' ')"
else
    t_fail "no certmap section in sssd.conf" "$(cat /etc/sssd/sssd.conf)"
fi
if grep -qE '^pam_cert_auth\s*=\s*True' /etc/sssd/sssd.conf; then
    t_pass "pam_cert_auth = True"
else
    t_fail "pam_cert_auth was not enabled" "$(cat /etc/sssd/sssd.conf)"
fi
if grep -qE '^ad_gpo_access_control\s*=\s*permissive' /etc/sssd/sssd.conf; then
    t_pass "ad_gpo_access_control = permissive (safe default, not the enforcing default)"
else
    t_fail "ad_gpo_access_control was not set to permissive" \
        "$(grep -n ad_gpo /etc/sssd/sssd.conf || echo '(absent)')"
fi

t_start "Running setup twice changes nothing (idempotent)"
BEFORE="$(sha256sum /etc/sssd/sssd.conf | cut -d' ' -f1)"
sssd-smartcard-setup --yes --test-user "$UPN" --ca "$PKI/ca-chain.pem" --gpo \
    >"$WORK/setup2.out" 2>&1 || true
AFTER="$(sha256sum /etc/sssd/sssd.conf | cut -d' ' -f1)"
if [[ "$BEFORE" == "$AFTER" ]]; then
    t_pass "the second run left sssd.conf untouched"
else
    t_fail "the second run modified sssd.conf" \
        "$(diff <(echo "$BEFORE") <(echo "$AFTER") || true)"
fi

# ===========================================================================
# Layer 4: does SSSD itself accept the card?
# ===========================================================================

t_start "SSSD's own p11_child reads and verifies the card"
P11CHILD=""
for c in /usr/libexec/sssd/p11_child /usr/lib/x86_64-linux-gnu/sssd/p11_child; do
    [[ -x "$c" ]] && P11CHILD="$c" && break
done
if [[ -z "$P11CHILD" ]]; then
    t_skip "p11_child not found"
elif "$P11CHILD" --pre -d 10 --debug-fd=2 \
        --ca_db=/etc/sssd/pki/sssd_auth_ca_db.pem >"$WORK/p11.out" 2>&1; then
    t_pass "p11_child verified a certificate from the token"
    note "$(head -1 "$WORK/p11.out")"
else
    t_fail "p11_child could not verify the card -- this is the exact login code path" \
        "$(tail -20 "$WORK/p11.out")"
fi

t_start "SSSD maps the certificate to the right AD user"
if command -v dbus-send >/dev/null 2>&1; then
    if OUT="$(dbus-send --system --print-reply \
            --dest=org.freedesktop.sssd.infopipe \
            /org/freedesktop/sssd/infopipe/Users \
            org.freedesktop.sssd.infopipe.Users.ListByCertificate \
            string:"$(cat "$PKI/user.crt")" uint32:10 2>&1)"; then
        if grep -q "object path" <<<"$OUT"; then
            t_pass "ListByCertificate returned a user object"
            note "$(grep -o '"/org/freedesktop/sssd/infopipe/Users/[^"]*"' <<<"$OUT" | head -1)"
        else
            t_fail "ListByCertificate returned no user" "$OUT"
        fi
    else
        t_fail "the InfoPipe call failed" "$OUT"
    fi
else
    t_skip "dbus-send not installed"
fi

# ===========================================================================
# Layer 5: the mapping tester, positive and negative
# ===========================================================================

PROFILE="/var/lib/sssd-smartcard/generated-profile.yaml"
[[ -f "$PROFILE" ]] || PROFILE="$WORK/derived.yaml"

t_start "The mapping tester agrees, and sssctl is the authority"
if OUT="$(sssd-smartcard mapping test "$PROFILE" --from-card 2>&1)"; then
    t_pass "mapping test: MATCH and the identity resolves"
else
    t_fail "mapping test did not fully pass" "$OUT"
fi
if grep -q "Decided by:.*sssctl" <<<"${OUT:-}"; then
    t_pass "the verdict came from sssctl cert-eval-rule (libsss_certmap itself)"
else
    note "verdict came from the local engine; sssctl cert-eval-rule may not exist here"
fi
if grep -qi "disagree" <<<"${OUT:-}"; then
    t_fail "the local engine and sssctl disagree" "$OUT"
else
    t_pass "the local engine and sssctl agree"
fi

t_start "A certificate from a different CA is rejected"
expect_output "rogue certificate does not match the pinned issuer" \
    "NO MATCH" \
    sssd-smartcard mapping test "$PROFILE" --file "$PKI/rogue.crt" || true

t_start "An expired certificate is called out"
if [[ -f "$PKI/expired.crt" ]]; then
    expect_output "expiry is reported as blocking" \
        "expired" \
        sssd-smartcard cert inspect --file "$PKI/expired.crt" --no-config || true
else
    t_skip "no expired test certificate was issued"
fi

t_start "A profile that asks for an option this SSSD lacks is refused, not degraded"
expect_failure "rendering a {sid} rule for SSSD 2.7 fails loudly" \
    sssd-smartcard config render "$PROFILE" --sssd-version 2.7.0 \
    || true

# ===========================================================================
# Layer 6: identity, Kerberos, diagnostics
# ===========================================================================

t_start "Identity resolution through the domain works"
expect_success "id $UPN" id "$UPN" || true
expect_success "getent passwd $UPN" getent passwd "$UPN" || true

t_start "Kerberos realm and KDC are reachable"
expect_output "the KDC is found and reachable" \
    "KDC.*(PASS|reachable)|Realm" \
    sssd-smartcard krb5 test --from-card || true
note "PKINIT needs a KDC certificate on the Samba DC; see lab/README.md"

t_start "doctor reports no failures"
if OUT="$(sssd-smartcard doctor --user "$UPN" 2>&1)"; then
    t_pass "doctor: no FAIL checks"
else
    t_fail "doctor found failures" "$(grep -E '^\[FAIL\]' <<<"$OUT" || echo "$OUT")"
fi

t_start "PAM was not touched without being asked"
if grep -qE '^\s*auth.*pam_sss\.so.*cert_auth' /etc/pam.d/common-auth 2>/dev/null; then
    t_fail "the PAM stack was modified even though --pam was never passed" \
        "$(grep -n pam_sss /etc/pam.d/common-auth)"
else
    t_pass "common-auth has no cert_auth line, as expected without --pam"
fi
note "to enable it: sudo pam-auth-update --enable sss-smart-card-optional"

# ===========================================================================
say_summary() {
    printf '\n%s=== Summary ===%s\n' "$C_BOLD" "$C_RESET"
    printf '  checks : %d\n' "$((PASSED + FAILED))"
    printf '  %spassed%s : %d\n' "$C_GREEN" "$C_RESET" "$PASSED"
    printf '  %sfailed%s : %d\n' "$C_RED" "$C_RESET" "$FAILED"
    printf '  %sskipped%s: %d\n' "$C_YELLOW" "$C_RESET" "$SKIPPED"
    if (( FAILED )); then
        printf '\n%sFailures:%s\n' "$C_RED" "$C_RESET"
        local f
        for f in "${FAILURES[@]}"; do printf '  * %s\n' "$f"; done
    fi
    printf '\nArtifacts in %s\n' "$WORK"
}
say_summary

if (( FAILED )); then
    printf '\n%sLAB FAILED%s\n' "$C_RED" "$C_RESET"
    exit 1
fi
printf '\n%sLAB PASSED%s -- the card path works end to end on this host.\n' "$C_GREEN" "$C_RESET"
printf 'Next, prove an actual login:\n'
printf '  pamtester -v login %s authenticate     # will prompt for the card PIN\n' "$UPN"
exit 0
