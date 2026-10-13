#!/usr/bin/env bash
#
# Provision the lab client: an Ubuntu domain member whose smart card is a
# SoftHSM2 token, then install sssd-smartcard on it.
#
# The SoftHSM token is what makes this lab useful: p11-kit advertises
# libsofthsm2.so to SSSD's p11_child exactly like a real PKCS#11 driver, so the
# whole card path runs without a reader or a physical card.
#
# Idempotent.

set -Eeuo pipefail

REALM="${LAB_REALM:?}"
DOMAIN="${LAB_DOMAIN:?}"
ADMINPASS="${LAB_ADMINPASS:?}"
DC_IP="${LAB_DC_IP:?}"
CARD_PIN="${LAB_CARD_PIN:?}"
CARD_SO_PIN="${LAB_CARD_SO_PIN:?}"

PKI="/vagrant/pki"
SOURCE="/opt/sssd-smartcard-source"
TOKEN_LABEL="PIV-LAB"
OBJECT_ID="01"

say()  { printf '\n=== %s ===\n' "$*"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '[ OK ] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*"; }
die()  { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive

[[ -f "$PKI/lab.env" ]] || die "the DC has not finished provisioning; run: vagrant up dc"
# shellcheck disable=SC1091
. "$PKI/lab.env"
UPN="${LAB_UPN:?}"
USERNAME="${LAB_USER:?}"

# ---------------------------------------------------------------------------
say "Resolver and time"
# ---------------------------------------------------------------------------
# The domain member must resolve through the DC's DNS, or the join fails with
# an error that has nothing to do with smart cards.
mkdir -p /etc/systemd/resolved.conf.d
cat >/etc/systemd/resolved.conf.d/lab.conf <<EOF
[Resolve]
DNS=$DC_IP
Domains=~$DOMAIN
EOF
systemctl restart systemd-resolved
ok "DNS for $DOMAIN -> $DC_IP"

apt-get update -qq
apt-get install -y -qq chrony >/dev/null
# Kerberos will not issue a ticket if the clocks disagree by more than 5 minutes.
grep -q "^server $DC_IP" /etc/chrony/chrony.conf 2>/dev/null \
    || printf 'server %s iburst prefer\n' "$DC_IP" >>/etc/chrony/chrony.conf
systemctl restart chrony || true
ok "time synced against the DC"

if ! host "$DOMAIN" >/dev/null 2>&1; then
    apt-get install -y -qq bind9-host >/dev/null 2>&1 || true
fi
getent hosts "dc.$DOMAIN" >/dev/null 2>&1 \
    || printf '%s dc.%s dc\n' "$DC_IP" "$DOMAIN" >>/etc/hosts

# ---------------------------------------------------------------------------
say "Packages"
# ---------------------------------------------------------------------------
apt-get install -y -qq \
    sssd sssd-ad sssd-tools libpam-sss libnss-sss \
    realmd adcli samba-common-bin krb5-user \
    opensc opensc-pkcs11 p11-kit pcscd pcsc-tools \
    softhsm2 gnutls-bin pamtester openssl \
    python3 python3-cryptography python3-yaml >/dev/null
ok "packages installed"

# ---------------------------------------------------------------------------
say "Domain join"
# ---------------------------------------------------------------------------
if realm list --name-only 2>/dev/null | grep -qix "$DOMAIN"; then
    ok "already joined to $DOMAIN"
else
    printf '%s' "$ADMINPASS" | realm join --user=Administrator --install=/ "$REALM" \
        --verbose 2>&1 | tail -5 \
        || die "realm join failed -- check DNS ($DC_IP), time sync, and the admin password"
    ok "joined $REALM"
fi
realm list --name-only | sed 's/^/    /'

systemctl restart sssd
sleep 3
if id "$UPN" >/dev/null 2>&1; then
    ok "id $UPN -> $(id "$UPN")"
else
    warn "id $UPN does not resolve yet"
    info "sssctl domain-list: $(sssctl domain-list 2>&1 | tr '\n' ' ')"
    info "the setup script will refuse to continue until this works, which is the point"
fi

# ---------------------------------------------------------------------------
say "Emulated smart card (SoftHSM2)"
# ---------------------------------------------------------------------------
SOFTHSM_MODULE=""
for candidate in \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib64/softhsm/libsofthsm2.so; do
    [[ -f "$candidate" ]] && SOFTHSM_MODULE="$candidate" && break
done
[[ -n "$SOFTHSM_MODULE" ]] || die "libsofthsm2.so not found after installing softhsm2"
info "module: $SOFTHSM_MODULE"

# SSSD's p11_child runs as the sssd user, so the token store must be readable
# by it. The default /var/lib/softhsm is fine; make sure the perms allow it.
export SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf

if softhsm2-util --show-slots 2>/dev/null | grep -q "$TOKEN_LABEL"; then
    ok "token $TOKEN_LABEL already initialised"
else
    softhsm2-util --init-token --free --label "$TOKEN_LABEL" \
        --so-pin "$CARD_SO_PIN" --pin "$CARD_PIN" >/dev/null
    ok "token $TOKEN_LABEL initialised (PIN $CARD_PIN)"
fi

load_object() {
    local file="$1" type="$2" label="$3"
    pkcs11-tool --module "$SOFTHSM_MODULE" --login --pin "$CARD_PIN" \
        --write-object "$file" --type "$type" --id "$OBJECT_ID" --label "$label" \
        >/dev/null 2>&1
}

if pkcs11-tool --module "$SOFTHSM_MODULE" --list-objects --type cert 2>/dev/null \
        | grep -q "$TOKEN_LABEL"; then
    ok "certificate already on the token"
else
    openssl pkcs8 -topk8 -nocrypt -in "$PKI/user.key" -outform DER -out /tmp/user.key.der
    openssl x509 -in "$PKI/user.crt" -outform DER -out /tmp/user.crt.der
    # Key and certificate must share the same CKA_ID so the token pairs them.
    load_object /tmp/user.key.der privkey "$TOKEN_LABEL" \
        || die "could not write the private key to the token"
    load_object /tmp/user.crt.der cert "$TOKEN_LABEL" \
        || die "could not write the certificate to the token"
    shred -u /tmp/user.key.der 2>/dev/null || rm -f /tmp/user.key.der
    rm -f /tmp/user.crt.der
    ok "certificate and key written to the token (id=$OBJECT_ID)"
fi

# p11_child runs as the sssd user and must be able to open the token store.
if getent passwd sssd >/dev/null 2>&1; then
    chgrp -R sssd /var/lib/softhsm 2>/dev/null || true
    chmod -R g+rX /var/lib/softhsm 2>/dev/null || true
    ok "token store readable by the sssd user"
fi

info "p11-kit sees:"
p11-kit list-modules 2>/dev/null | grep -A1 -i softhsm | sed 's/^/    /' || true

# ---------------------------------------------------------------------------
say "Install sssd-smartcard"
# ---------------------------------------------------------------------------
[[ -d "$SOURCE" ]] || die "$SOURCE is missing; run: vagrant rsync client"
cd "$SOURCE"
./install.sh --no-deps >/dev/null || die "install.sh failed"
ok "installed: $(sssd-smartcard --version)"

cat >/etc/profile.d/sssd-smartcard-lab.sh <<EOF
# Lab conveniences
export SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf
export LAB_PKI=$PKI
export LAB_UPN='$UPN'
export LAB_MODULE='$SOFTHSM_MODULE'
export LAB_CARD_PIN='$CARD_PIN'
EOF

cat >/root/lab.env <<EOF
SOFTHSM_MODULE='$SOFTHSM_MODULE'
CARD_PIN='$CARD_PIN'
UPN='$UPN'
USERNAME='$USERNAME'
DOMAIN='$DOMAIN'
REALM='$REALM'
PKI='$PKI'
EOF

# ---------------------------------------------------------------------------
if [[ "${LAB_DESKTOP:-0}" == "1" ]]; then
say "Graphical environment (LAB_DESKTOP=1)"
# ---------------------------------------------------------------------------
    if dpkg-query -W -f='${Status}' ubuntu-desktop-minimal 2>/dev/null \
            | grep -q "ok installed"; then
        ok "ubuntu-desktop-minimal already installed"
    else
        info "installing ubuntu-desktop-minimal -- this pulls ~1.5 GB, give it time"
        apt-get install -y -qq ubuntu-desktop-minimal >/dev/null \
            || die "could not install ubuntu-desktop-minimal"
        ok "ubuntu-desktop-minimal installed"
    fi

    # The documented packages for Smart Card login on Ubuntu Desktop. libpam-sss
    # and pcscd are already in by now; opensc-pkcs11 provides the module.
    apt-get install -y -qq libpam-sss opensc-pkcs11 pcscd >/dev/null || true

    if [[ "$(systemctl get-default)" != "graphical.target" ]]; then
        systemctl set-default graphical.target >/dev/null
        ok "default target set to graphical.target"
    else
        ok "already booting to graphical.target"
    fi

    # GDM's own PAM behaviour lives in /etc/pam.d/gdm-smartcard. It is NOT
    # configured here: this lab never edits PAM without being asked, and
    # run-tests.sh asserts exactly that.
    if command -v gdm-config >/dev/null 2>&1; then
        ok "gdm-config is available for the login screen"
        info "to allow card OR password at the greeter:"
        info "    sudo gdm-config smartcard --enable && sudo gdm-config password --enable"
        info "to require the card:"
        info "    sudo gdm-config smartcard --required"
    else
        info "this release has no gdm-config; configure the greeter through dconf:"
        info "    /etc/dconf/db/local.d/00_gdm-smartcard-enable with"
        info "    [org/gnome/login-screen]"
        info "    enable-smartcard-authentication=true"
        info "    then: sudo dconf update"
    fi
    warn "the emulated card is a SoftHSM token, not a PC/SC reader"
    note_gdm="GNOME switches to the card prompt on a reader insertion event, which a \
SoftHSM token never produces. The greeter may therefore never offer the card by itself. \
Console login and pamtester are unaffected and remain the reliable checks."
    printf '    %s\n' "$note_gdm"
    ok "desktop ready -- reboot the VM to reach the greeter: vagrant reload client"
fi

say "Client ready"
cat <<EOF
    Emulated card : $SOFTHSM_MODULE (token $TOKEN_LABEL, PIN $CARD_PIN)
    User          : $UPN
    Trust chain   : $PKI/ca-chain.pem
    Desktop       : ${LAB_DESKTOP:-0}

    Run the test suite:
      sudo /vagrant/run-tests.sh

    Or drive it by hand:
      sssd-smartcard card detect
      sssd-smartcard cert inspect --from-card
      sudo sssd-smartcard-setup --dry-run --test-user $UPN --ca $PKI/ca-chain.pem

    Test an actual login without risking your session:
      sudo pam-auth-update --enable sss-smart-card-optional
      pamtester -v login $UPN authenticate        # PIN: $CARD_PIN
EOF
