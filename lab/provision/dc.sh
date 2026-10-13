#!/usr/bin/env bash
#
# Provision the lab domain controller: Samba AD DC + a small PKI.
#
# Idempotent: re-running skips whatever already exists.

set -Eeuo pipefail

REALM="${LAB_REALM:?}"
DOMAIN="${LAB_DOMAIN:?}"
NETBIOS="${LAB_NETBIOS:?}"
ADMINPASS="${LAB_ADMINPASS:?}"
USERNAME="${LAB_USER:?}"
USERPASS="${LAB_USERPASS:?}"
DC_IP="${LAB_DC_IP:?}"

PKI="/vagrant/pki"
SAM_DB="/var/lib/samba/private/sam.ldb"

say()  { printf '\n=== %s ===\n' "$*"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '[ OK ] %s\n' "$*"; }
die()  { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------------------
say "Packages"
# ---------------------------------------------------------------------------
apt-get update -qq
apt-get install -y -qq \
    samba smbclient winbind krb5-user krb5-config ldb-tools \
    openssl python3 chrony >/dev/null
ok "packages installed"

# ---------------------------------------------------------------------------
say "Resolver"
# ---------------------------------------------------------------------------
# A Samba AD DC runs its own DNS on port 53, which systemd-resolved also wants.
if systemctl is-enabled --quiet systemd-resolved 2>/dev/null; then
    systemctl disable --now systemd-resolved
    ok "systemd-resolved disabled"
fi
rm -f /etc/resolv.conf
cat >/etc/resolv.conf <<EOF
nameserver 127.0.0.1
search $DOMAIN
EOF
chattr +i /etc/resolv.conf 2>/dev/null || true
ok "resolv.conf points at the DC itself"

grep -q "$DOMAIN" /etc/hosts || printf '%s dc.%s dc\n' "$DC_IP" "$DOMAIN" >>/etc/hosts

# ---------------------------------------------------------------------------
say "Samba AD domain"
# ---------------------------------------------------------------------------
if [[ -f "$SAM_DB" ]]; then
    ok "domain $REALM already provisioned"
else
    systemctl disable --now smbd nmbd winbind 2>/dev/null || true
    rm -f /etc/samba/smb.conf
    samba-tool domain provision \
        --use-rfc2307 \
        --realm="$REALM" \
        --domain="$NETBIOS" \
        --server-role=dc \
        --dns-backend=SAMBA_INTERNAL \
        --adminpass="$ADMINPASS" \
        --option="dns forwarder = 1.1.1.1" \
        >/dev/null
    cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf
    systemctl unmask samba-ad-dc
    systemctl enable samba-ad-dc
    ok "domain $REALM provisioned"
fi

systemctl restart samba-ad-dc
for _ in $(seq 1 30); do
    if samba-tool domain level show >/dev/null 2>&1; then break; fi
    sleep 2
done
samba-tool domain level show >/dev/null 2>&1 || die "samba-ad-dc did not come up"
ok "samba-ad-dc is running"

# Password policy gets in the way of a scripted lab user.
samba-tool domain passwordsettings set --complexity=off --min-pwd-length=7 \
    --max-pwd-age=0 >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
say "Lab user"
# ---------------------------------------------------------------------------
if samba-tool user show "$USERNAME" >/dev/null 2>&1; then
    ok "user $USERNAME already exists"
else
    samba-tool user create "$USERNAME" "$USERPASS" \
        --given-name=Jan --surname=Kowalski >/dev/null
    ok "user $USERNAME created"
fi

USER_DN="$(samba-tool user show "$USERNAME" --attributes=dn 2>/dev/null \
    | sed -n 's/^dn: //p' | head -1)"
[[ -n "$USER_DN" ]] || die "could not read the DN of $USERNAME"
info "DN: $USER_DN"

UPN="$USERNAME@$DOMAIN"
cat >/tmp/upn.ldif <<EOF
dn: $USER_DN
changetype: modify
replace: userPrincipalName
userPrincipalName: $UPN
EOF
ldbmodify -H "$SAM_DB" /tmp/upn.ldif >/dev/null 2>&1 || true
rm -f /tmp/upn.ldif
ok "userPrincipalName = $UPN"

# ---------------------------------------------------------------------------
say "Reading the account SID"
# ---------------------------------------------------------------------------
# The certificate embeds this SID in the AD security extension, so the
# sid-extension mapping can resolve the real account.
USER_SID="$(
    ldbsearch -H "$SAM_DB" "(sAMAccountName=$USERNAME)" objectSid 2>/dev/null \
    | python3 -c '
import base64, sys

blob = None
for line in sys.stdin:
    line = line.rstrip("\n")
    if line.startswith("objectSid:: "):
        blob = base64.b64decode(line.split(": ", 1)[1])
        break
    if line.startswith("objectSid: "):
        # Already textual on some Samba builds.
        print(line.split(": ", 1)[1].strip())
        raise SystemExit(0)
if blob is None or len(blob) < 8:
    raise SystemExit(0)
revision = blob[0]
count = blob[1]
authority = int.from_bytes(blob[2:8], "big")
subs = [
    int.from_bytes(blob[8 + 4 * i : 12 + 4 * i], "little") for i in range(count)
]
print("S-%d-%d-%s" % (revision, authority, "-".join(str(s) for s in subs)))
'
)"
if [[ -n "$USER_SID" ]]; then
    ok "objectSid = $USER_SID"
else
    info "could not read objectSid; the certificate will be issued without the SID extension"
fi

# ---------------------------------------------------------------------------
say "PKI"
# ---------------------------------------------------------------------------
mkdir -p "$PKI"
chmod 0755 "$PKI"

issue_ca() {
    local name="$1" subject="$2" pathlen="$3" signer_key="$4" signer_crt="$5"
    if [[ -f "$PKI/$name.crt" ]]; then
        info "$name already issued"
        return 0
    fi
    openssl req -newkey rsa:2048 -nodes -keyout "$PKI/$name.key" \
        -out "$PKI/$name.csr" -subj "$subject" >/dev/null 2>&1
    cat >"$PKI/$name.ext" <<EOF
basicConstraints=critical,CA:TRUE,pathlen:$pathlen
keyUsage=critical,keyCertSign,cRLSign,digitalSignature
subjectKeyIdentifier=hash
EOF
    if [[ -z "$signer_crt" ]]; then
        openssl x509 -req -in "$PKI/$name.csr" -signkey "$PKI/$name.key" \
            -days 3650 -extfile "$PKI/$name.ext" -sha256 \
            -out "$PKI/$name.crt" >/dev/null 2>&1
    else
        printf 'authorityKeyIdentifier=keyid,issuer\n' >>"$PKI/$name.ext"
        openssl x509 -req -in "$PKI/$name.csr" \
            -CA "$signer_crt" -CAkey "$signer_key" -CAcreateserial \
            -days 3650 -extfile "$PKI/$name.ext" -sha256 \
            -out "$PKI/$name.crt" >/dev/null 2>&1
    fi
    rm -f "$PKI/$name.csr"
    ok "$name issued"
}

issue_ca root-ca "/DC=local/DC=domain-b/CN=Lab Root CA" 1 "" ""
issue_ca issuing-ca "/DC=local/DC=domain-b/CN=Enterprise Issuing CA" 0 \
    "$PKI/root-ca.key" "$PKI/root-ca.crt"
# A second, untrusted CA, so the lab can prove the matchrule rejects it.
issue_ca rogue-ca "/DC=local/DC=domain-b/CN=Rogue CA" 0 "" ""

cat "$PKI/root-ca.crt" "$PKI/issuing-ca.crt" >"$PKI/ca-chain.pem"
ok "trust chain: $PKI/ca-chain.pem"

# The SID extension has no openssl shorthand, so build its DER by hand.
SID_EXT_LINE=""
if [[ -n "$USER_SID" ]]; then
    SID_DER="$(
        USER_SID="$USER_SID" python3 -c '
import os

def tlv(tag, content):
    assert len(content) < 128, "lab SIDs are always short"
    return bytes([tag, len(content)]) + content

sid = os.environ["USER_SID"].encode()
# szOID_NTDS_OBJECTSID = 1.3.6.1.4.1.311.25.2.1
oid = bytes([0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x19, 0x02, 0x01])
other_name = tlv(0xA0, tlv(0x06, oid) + tlv(0xA0, tlv(0x04, sid)))
print(":".join("%02X" % b for b in tlv(0x30, other_name)))
'
    )"
    SID_EXT_LINE="1.3.6.1.4.1.311.25.2=DER:$SID_DER"
fi

# issue_user <name> <signer> <upn> <days> <extra-ext>
issue_user() {
    local name="$1" signer="$2" upn="$3" days="$4" extra="${5:-}"
    if [[ -f "$PKI/$name.crt" ]]; then
        info "$name already issued"
        return 0
    fi
    openssl req -newkey rsa:2048 -nodes -keyout "$PKI/$name.key" \
        -out "$PKI/$name.csr" \
        -subj "/DC=local/DC=domain-b/OU=Users/CN=Jan Kowalski" >/dev/null 2>&1
    cat >"$PKI/$name.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
# clientAuth plus Microsoft Smart Card Logon (1.3.6.1.4.1.311.20.2.2)
extendedKeyUsage=clientAuth,1.3.6.1.4.1.311.20.2.2
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
# otherName=msUPN (1.3.6.1.4.1.311.20.2.3)
subjectAltName=otherName:1.3.6.1.4.1.311.20.2.3;UTF8:$upn
$extra
EOF
    openssl x509 -req -in "$PKI/$name.csr" \
        -CA "$PKI/$signer.crt" -CAkey "$PKI/$signer.key" -CAcreateserial \
        -days "$days" -extfile "$PKI/$name.ext" -sha256 \
        -out "$PKI/$name.crt" >/dev/null 2>&1 \
        || die "could not issue $name (check the openssl extension file $PKI/$name.ext)"
    rm -f "$PKI/$name.csr"
    ok "$name issued for $upn"
}

issue_user user issuing-ca "$UPN" 365 "$SID_EXT_LINE"
# Negative test material.
issue_user rogue rogue-ca "$UPN" 365 ""

if [[ ! -f "$PKI/expired.crt" ]]; then
    # openssl cannot backdate with -days, so use a one-day certificate and a
    # faked notBefore via -not_before/-not_after where available.
    if openssl x509 -help 2>&1 | grep -q -- "-not_before"; then
        openssl req -newkey rsa:2048 -nodes -keyout "$PKI/expired.key" \
            -out "$PKI/expired.csr" \
            -subj "/DC=local/DC=domain-b/OU=Users/CN=Jan Kowalski" >/dev/null 2>&1
        cp "$PKI/user.ext" "$PKI/expired.ext"
        openssl x509 -req -in "$PKI/expired.csr" \
            -CA "$PKI/issuing-ca.crt" -CAkey "$PKI/issuing-ca.key" -CAcreateserial \
            -not_before "20200101000000Z" -not_after "20200201000000Z" \
            -extfile "$PKI/expired.ext" -sha256 \
            -out "$PKI/expired.crt" >/dev/null 2>&1 \
            && ok "expired test certificate issued" \
            || info "could not issue an expired certificate; that negative test will be skipped"
        rm -f "$PKI/expired.csr"
    else
        info "this openssl has no -not_before; skipping the expired test certificate"
    fi
fi

# The client reads these; the private keys are lab-only throwaways.
chmod 0644 "$PKI"/*.crt "$PKI"/ca-chain.pem 2>/dev/null || true
chmod 0640 "$PKI"/*.key 2>/dev/null || true

cat >"$PKI/lab.env" <<EOF
LAB_REALM='$REALM'
LAB_DOMAIN='$DOMAIN'
LAB_NETBIOS='$NETBIOS'
LAB_USER='$USERNAME'
LAB_UPN='$UPN'
LAB_USER_SID='${USER_SID:-}'
LAB_DC_IP='$DC_IP'
EOF
ok "lab facts written to $PKI/lab.env"

say "Summary"
info "realm         : $REALM"
info "user          : $USERNAME ($UPN)"
info "objectSid     : ${USER_SID:-<unavailable>}"
info "trust chain   : $PKI/ca-chain.pem"
info "user cert     : $PKI/user.crt  (+ user.key)"
info "rogue cert    : $PKI/rogue.crt (different CA -- must NOT match)"
printf '\n'
openssl x509 -in "$PKI/user.crt" -noout -subject -issuer -ext subjectAltName 2>/dev/null || true
ok "domain controller ready"
