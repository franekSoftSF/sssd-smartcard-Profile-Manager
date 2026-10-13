# Tutorial: Smart Card logon on Ubuntu against ad.example.com

A walkthrough for the lab host **`wks-desktop`** (10.0.0.50), joined
to **`ad.example.com`** with the domain controller **`dc01`**
(10.0.0.10) and the PKI at **`subca.ad.example.com`** (10.0.0.16).

Each step says **what you run**, **what you should see**, and **what it means if
you do not**. Work top to bottom: every step depends on the one above it, and
that order is the point — a failure tells you *where* the fault is instead of
leaving you guessing at a login screen that only says "authentication failed".

Steps marked **✅ verified** were run on this host and produced the output shown.
The rest are still ahead of you.

---

## 0. Starting point ✅ verified

| | |
|---|---|
| OS | Ubuntu 24.04.5 LTS, VMware, 2 vCPU, 3.9 GB RAM, 11 GB free |
| DNS | `10.0.0.10` (DC01), search `ad.example.com` |
| Desktop | `ubuntu-desktop-minimal` 1.539.2 + GDM 46.2, running |
| Greeter | password **and** smart card both enabled in dconf |
| Domain | joined, `ad.example.com`, **single domain — no trusts** |
| Test user | `testuser@ad.example.com`, uid 1000001101 |
| Package | `sssd-smartcard` 0.2.0 installed |
| PAM | untouched: `pwquality, unix, sss, systemd, gnome-keyring, capability` |
| Pending | reboot for kernel 6.8.0-146 (running -138) |

Because the accounts live in the same domain the host is joined to, the
generated rule will **not** need a `domains=` line, and `doctor` reporting *"no
trusted domains"* is correct here rather than a fault.

Sanity check:

```bash
resolvectl status ens33 | grep -E 'DNS Server|DNS Domain'
dig +short _kerberos._tcp.ad.example.com SRV
```

```
Current DNS Server: 10.0.0.10
         DNS Domain: ad.example.com
0 100 88 dc01.ad.example.com.
```

---

## 1. Install the package ✅ verified

```bash
sudo apt install /tmp/sssd-smartcard/sssd-smartcard_0.2.0_all.deb
```

`apt` pulled in all 13 `Recommends`: `sssd`, `sssd-ad`, `sssd-tools`,
`sssd-dbus`, `libpam-sss`, `opensc`, `opensc-pkcs11`, `p11-kit`, `pcscd`,
`libccid`, `krb5-user`, `realmd`, `adcli`.

```bash
sssd-smartcard --version          # sssd-smartcard 0.2.0
sssd-smartcard profile list       # 7 packaged examples
man 8 sssd-smartcard-setup        # q to quit
```

### Two things that bit us here

**The `_apt` notice is harmless.**

```
N: Download is performed unsandboxed as root as file
   '/home/sysadmin/sssd-smartcard_0.2.0_all.deb' couldn't be accessed by
   user '_apt'. - pkgAcquire::Run (13: Permission denied)
```

A notice, not an error: `/home/sysadmin` is mode 0750 so the `_apt` user cannot
traverse it, and apt falls back to reading the file as root. **The install
succeeds.** Installing from a world-readable path silences it, which is why the
command above uses `/tmp/sssd-smartcard/`.

**This image is minimized, so the documentation was silently discarded.**
`/etc/dpkg/dpkg.cfg.d/excludes` contains `path-exclude=/usr/share/man/*` and
`path-exclude=/usr/share/doc/*`, so dpkg dropped the package's manual pages and
the SSSD reference even though `dpkg -L sssd-smartcard` still lists them. On top
of that `/usr/bin/man` was a diversion to a stub that only prints *"This system
has been minimized"*.

Already fixed on this host. If you rebuild the VM:

```bash
sudo tee /etc/dpkg/dpkg.cfg.d/zz-sssd-smartcard-docs >/dev/null <<'EOF'
path-include=/usr/share/man/man8/sssd-smartcard*
path-include=/usr/share/doc/sssd-smartcard/*
EOF
sudo apt install --reinstall /tmp/sssd-smartcard/sssd-smartcard_0.2.0_all.deb
sudo apt install -y man-db
sudo cp -a /usr/bin/man /root/man.minimized-stub.bak
sudo rm /usr/bin/man
sudo dpkg-divert --local --rename --remove /usr/bin/man
sudo mandb -q
```

### Baseline diagnosis

```bash
sudo sssd-smartcard doctor --user testuser@ad.example.com
```

Expect **2 failures** at this point — `pam_cert_auth` not set and no CA trust
bundle. That is correct: they are steps 6 and 3. You are confirming that the
tool sees the same reality you do before it changes anything.

---

## 2. Join the domain ✅ verified

```bash
sudo realm join --user=Administrator ad.example.com
```

`realm` prompts for the password. Nothing in this toolchain reads or stores it.

**Check — this is the hard gate:**

```bash
realm list --name-only
id testuser@ad.example.com
getent passwd testuser@ad.example.com
sudo sssctl domain-list
sudo sssctl domain-status ad.example.com
```

What it produced here:

```
ad.example.com
uid=1000001101(testuser@ad.example.com) gid=1000000513(domain users@…)
    groups=…,1052001115(grphorizonusers@…),1052001140(grpworkspaceoneuser@…)
testuser@ad.example.com:*:1000001101:1000000513:Test User:/home/…:/bin/bash

Online status: Online
Active servers:
  AD Global Catalog: dc01.ad.example.com
  AD Domain Controller: dc01.ad.example.com
```

**If `id` fails, stop here.** Smart Card authentication cannot map a certificate
to a user that SSSD cannot already resolve by name, and the setup script will
refuse to continue — by design. Look at `sssctl domain-status`,
`journalctl -u sssd -n 50`, and `timedatectl status` (Kerberos rejects more than
five minutes of clock skew).

### The `tkey query failed` noise in the journal

```
sssd[4100]: tkey query failed: GSSAPI error: … Minor = Server not found in
            Kerberos database.
```

Nothing to do with smart cards. `sssd-ad(5)` documents `dyndns_update` as
defaulting to **true**, so SSSD tries to register its own DNS record in AD using
GSS-TSIG. It cannot, because this host's FQDN is in a different zone from the AD
domain:

```
hostname -f  →  wks-desktop.legacy.example.net
AD zone      →  ad.example.com
```

`nsupdate` therefore cannot get a ticket for the DNS server's principal. Five
occurrences in two hours, no other errors, and identity resolution works — so on
this host it is noise. (The man page does not state whether a dyndns failure can
affect authentication, so that is an observation, not a documented guarantee.)

Silence it if you like, in `[domain/ad.example.com]`:

```ini
dyndns_update = False
```

The real fix would be giving the host an FQDN inside the AD zone. Not needed for
Smart Card logon.

---

## 3. Build the CA trust bundle ✅ verified up to the import

SSSD verifies card certificates against **one** PEM file, the documented default
being `/etc/sssd/pki/sssd_auth_ca_db.pem`. You need the chain that issued the
card certificate — root CA plus any intermediate.

Your PKI publishes them over HTTP:

```bash
mkdir -p ~/pki && cd ~/pki
BASE=http://pki.example.com/PKI
curl -sS --fail -o root-ca.crt    "$BASE/Example%20Root%20CA%20-%20homelab.crt"
curl -sS --fail -o issuing-ca.crt "$BASE/Example%20Issuing%20CA%20-%20homelab.crt"
```

What is published there:

| File | Size |
|---|---|
| `Example Root CA.crt` | 2206 B |
| `Example Issuing CA.crt` | 2702 B |
| `Example Root CA.crl` | 835 B |
| `Example Issuing CA.crl` | 1177 B |

AD CS served these as **PEM**, so no conversion was needed. `sssd-smartcard`
reads DER just as happily if your CA hands you DER.

### Look at them before trusting them

```bash
sssd-smartcard ca show ~/pki/root-ca.crt ~/pki/issuing-ca.crt
```

```
root: Example Root CA
  Subject:            CN=Example Root CA
  Issuer:             CN=Example Root CA
  Validity:           2025-10-29 .. 2045-10-29
  Basic Constraints:  CA:TRUE
  SHA-256:            22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:
                      22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22

intermediate: Example Issuing CA
  Subject:            CN=Example Issuing CA,DC=ad,DC=example,DC=pl
  Issuer:             CN=Example Root CA
  Validity:           2025-10-29 .. 2035-10-29
  Basic Constraints:  CA:TRUE
  SHA-256:            11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:
                      11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11
```

Confirm the chain links up, independently of this tool:

```bash
openssl verify -CAfile ~/pki/root-ca.crt ~/pki/issuing-ca.crt     # → OK
```

### Verify out of band — do not skip this ✅ verified

These came over **plain HTTP**. Importing a CA means SSSD will accept *any*
certificate it issues for login, so a tampered file is a login bypass.

#### Two traps to avoid first

**`certutil -hashfile` is a Windows command.** On Linux, `libnss3-tools`
installs NSS's `certutil`, a completely different tool with no `-hashfile` at
all. Do not install it for this.

**A file hash is not a certificate fingerprint.** A certificate's fingerprint is
the SHA-256 of its **DER** encoding. `sha256sum`, `certutil -hashfile` and
`Get-FileHash` hash the **file bytes**. For a DER `.crt` those agree; for a
**PEM** `.crt` — which is what AD CS served here — they do not:

```bash
openssl x509 -in ~/pki/root-ca.crt -noout -fingerprint -sha256
#   A4:EC:62:4B:83:65:...   <- the certificate fingerprint
sha256sum ~/pki/root-ca.crt
#   d81191352d7796b0...     <- the PEM file's hash, a different number
```

Comparing the second against the first will never match and looks like a
tampered file.

#### The strong check: compare against Active Directory

AD publishes the CA certificates itself, reachable over Kerberos-authenticated
LDAP — a completely different channel from that HTTP server. The host's own
keytab is enough.

```bash
# kinit -k on its own fails here: it derives host/<fqdn>, and this host's FQDN
# is wks-desktop.legacy.example.net, outside the AD zone. Name the principal.
sudo klist -k /etc/krb5.keytab | head
sudo kinit -k 'WKS-DESKTOP$@AD.EXAMPLE.COM'

CONF="CN=Public Key Services,CN=Services,CN=Configuration,DC=ad,DC=example,DC=pl"
sudo ldapsearch -o ldif-wrap=no -LLL -Y GSSAPI \
     -H ldap://dc01.ad.example.com \
     -b "CN=NTAuthCertificates,$CONF" -s base cACertificate \
  | awk '/^cACertificate::/{print $2}' | head -1 | base64 -d > /tmp/ad-issuing.der

openssl x509 -in /tmp/ad-issuing.der -inform DER -noout -subject -fingerprint -sha256
```

`NTAuthCertificates` is the store that authorises a CA to issue **logon**
certificates, so it is exactly the right thing to compare against. The same
certificate also appears under `CN=AIA` and `CN=Enrollment Services`.

Then two checks that settle it:

```bash
# 1. is the HTTP download the same bytes AD has?
openssl x509 -in ~/pki/issuing-ca.crt -outform DER -out /tmp/http-issuing.der
cmp /tmp/ad-issuing.der /tmp/http-issuing.der && echo IDENTICAL

# 2. does our root validate the AD-authenticated issuing CA?
openssl verify -CAfile ~/pki/root-ca.crt /tmp/ad-issuing.der

sudo kdestroy
```

Both passed here. That proves the root too, without anyone eyeballing a hash: to
substitute a forged root, an attacker would need a key that validly signs the
genuine issuing CA certificate taken from AD. The key identifiers line up as
expected:

```
our root SKI            33:33:33:33:33:33:33:33:33:33:33:33:33:33:33:33:33:33:33:33
AD issuing CA AKI       33:33:33:33:33:33:33:33:33:33:33:33:33:33:33:33:33:33:33:33
```

> Note: on this AD the root is **not** published in
> `CN=Certification Authorities` — that container is empty, so the root reaches
> Windows clients by some other route (Group Policy, or it was never
> `certutil -dspublish`ed). It does not matter here, because the signature check
> above establishes it anyway.

### Import ✅ verified

```bash
sssd-smartcard ca import ~/pki/root-ca.crt ~/pki/issuing-ca.crt --dry-run
sssd-smartcard ca import ~/pki/root-ca.crt ~/pki/issuing-ca.crt
```

The import **merges, never replaces**: an existing bundle is read, duplicates are
skipped by fingerprint, and a backup is taken first. `--dry-run` shows exactly
what would be added.

Result here:

```
Wrote /etc/sssd/pki/sssd_auth_ca_db.pem (2 certificates, mode 0644)
```

and `doctor` went from two failures to one:

```
[PASS] CA trust bundle  /etc/sssd/pki/sssd_auth_ca_db.pem: 2 certificate(s)
[FAIL] pam_cert_auth    [pam] pam_cert_auth = (not set, defaults to False)
1 check(s) failed
```

That remaining failure is step 6. Everything up to here is done.

---

## 4. Inspect the certificate and let the tool derive the configuration

> ### Every card command needs `sudo` over SSH ✅ verified
>
> pcsc-lite authorises clients through the polkit action
> `org.debian.pcsc-lite.access_pcsc`, and
> `/usr/share/polkit-1/actions/org.debian.pcsc-lite.policy` defaults it to:
>
> ```xml
> <allow_any>no</allow_any>
> <allow_inactive>no</allow_inactive>
> <allow_active>yes</allow_active>
> ```
>
> Only a session attached to a **local seat** counts. An SSH session is `active`
> in `loginctl` but has **no seat**, so it falls under `allow_any` and is
> refused — even with pcscd running and the reader plugged in. pcscd says so:
>
> ```
> pcscd: IsClientAuthorized() Process … (user: 1000) is NOT authorized
>        for action: access_pcsc
> pcscd: Rejected unauthorized PC/SC client
> ```
>
> So: **prefix every card command with `sudo`**, or run them from the machine's
> console, where the session does have a seat.
>
> SSSD itself is covered: it runs as root here, and `sssd-pcsc.rules` (shipped by
> the `sssd` package in `/usr/share/polkit-1/rules.d/`) grants root both
> `access_pcsc` and `access_card`. If you ever set `user =` in `sssd.conf` to run
> SSSD unprivileged, that rule stops matching and card login breaks.

This is the part the whole tool exists for. With the card in the reader:

```bash
sudo sssd-smartcard card detect
```

What it produced here — a YubiKey passed through to the VM, in PIV mode:

```
[PASS] readers        1 reader(s) detected
[PASS] token          1 token slot(s)
[PASS] certificates   1 certificate(s) found

Readers
  Yubico YubiKey OTP+FIDO+CCID 00 00

Tokens
  Slot: 0   Token: Test User   Manufacturer: piv_II
            Model: PKCS#15 emulated   Serial: 7ac8f04ebd63234b

Certificates on the card
 * id=01  label=Certificate for PIV Authentication
     Subject: CN=Test User,OU=Users,OU=EXAMPLE,DC=ad,DC=example,DC=pl
     Issuer:  CN=Example Issuing CA,DC=ad,DC=example,DC=pl
     UPN:     testuser@ad.example.com
     EKU:     msScLogin, clientAuth
```

Expect the reader, the token, the slot and the certificate objects, with the
authentication certificate marked `*`. The private key is never read and no PIN
is requested.

Then:

```bash
sudo sssd-smartcard cert inspect --from-card
```

You get four blocks:

1. **Certificate** — subject, issuer, serial, validity, SAN (UPN, PKINIT,
   e-mail), EKU, key usage, SKI/AKI, the AD SID extension, CRL and OCSP
   endpoints.
2. **Analysis** — anything that would trip SSSD up: expiry, a missing
   `clientAuth` EKU, no SAN, a CA certificate passed by mistake.
3. **Recommended mapping** — the mechanism, a confidence score, *why*, and the
   identity it would resolve to, plus the ranked alternatives.
4. **Generated profile and sssd.conf** — ready to use.

**What to confirm:**

- the **SAN UPN** matches a real account, e.g. `testuser@ad.example.com`;
- the **issuer** is `CN=Example Issuing CA,DC=ad,…` and it got
  pinned in the generated `matchrule`;
- the recommendation is `san-upn` with a high score. If it is something else, the
  Analysis block says why, and that reason is the thing to fix.

### Watch the `Domain:` line — alternative UPN suffix

Your AD domain is `ad.example.com`, but the public domain is
`example.com`. If Test's certificate carries a UPN like
`testuser@example.com`, that is an **alternative UPN suffix of the same
domain**, *not* a separate trusted domain — and writing `domains=` for it would
point SSSD at something it has never heard of, so every lookup would fail.

The tool now checks the inferred domain against the domains SSSD actually knows
and warns when they do not line up. If you see that warning, override it:

```bash
sudo sssd-smartcard cert inspect --from-card --domain ad.example.com
```

If the card is not in a reader, work from an exported certificate:

```bash
sssd-smartcard cert inspect --file ~/pki/user.pem
```

### Save the profile

```bash
sudo sssd-smartcard cert autoconfig --from-card \
    --save-profile /etc/sssd-smartcard/profiles/AD-PIV-UPN.yaml
```

Read it. It is plain YAML and you are allowed to disagree with it — the issuer
pin, the UPN suffix and the EKU list are all yours to adjust. Profiles in
`/etc/sssd-smartcard/profiles/` are searched before the packaged examples in
`/usr/share/sssd-smartcard/profiles/`.

---

## 5. Prove the mapping before applying anything

```bash
sudo sssd-smartcard mapping test AD-PIV-UPN --from-card
```

Term by term: which parts of the matching rule passed, what the mapping rule
expands to, the resulting LDAP filter, and the SSSD lookup for the resolved
identity.

**What to confirm:**

- **MATCH**, and `Decided by: sssctl` — that means `sssctl cert-eval-rule`,
  libsss_certmap itself, agreed. If it says `local`, `sssctl` was unavailable;
  if the two **disagree**, the tool says so loudly and `sssctl` is the authority.
- **Mapped identity** is the UPN you expect.
- **SSSD identity lookup: PASS** with a UID and groups.

A `NO MATCH` here is good news: you found it now, with the name of the term that
failed, rather than at a login prompt that just says authentication failed.

---

## 6. Review and apply

**Always look first:**

```bash
sudo sssd-smartcard config diff AD-PIV-UPN
```

A unified diff of `/etc/sssd/sssd.conf`. You should see a new
`[certmap/ad.example.com/AD-PIV-UPN]` section with `matchrule` and
`maprule`, `pam_cert_auth = True` under `[pam]`, and `certificate_verification`
under `[sssd]`. There should be **no `domains=` line**, because the accounts are
in the joined domain.

Then the dry run, which is also the default:

```bash
sudo sssd-smartcard-setup \
    --test-user testuser@ad.example.com \
    --ca ~/pki/root-ca.crt --ca ~/pki/issuing-ca.crt \
    --profile /etc/sssd-smartcard/profiles/AD-PIV-UPN.yaml \
    --gpo \
    --dry-run
```

Read the nine stages. Nothing was written. When it looks right, drop `--dry-run`
and add `--yes`.

It backs everything up under `/var/lib/sssd-smartcard/backups/<timestamp>/`,
writes `sssd.conf` at mode 0600, runs `sssctl config-check`, restarts SSSD and
verifies. **Any failure rolls every touched file back** and restarts SSSD on the
old configuration.

Note what it does **not** do: it leaves PAM alone. That is step 8 and it is
deliberately yours.

---

## 7. Does SSSD itself accept the card?

Two checks that do not involve PAM at all, so a failure here is unambiguous.

```bash
sudo /usr/libexec/sssd/p11_child --pre -d 10 --debug-fd=2 \
    --ca_db=/etc/sssd/pki/sssd_auth_ca_db.pem
```

This is the exact code path SSSD uses at login. It should print the token and
certificate. A failure here is almost always the CA bundle: the issuing CA is
missing, or the chain is incomplete — try `certificate_verification =
partial_chain`.

```bash
sudo dbus-send --system --print-reply \
    --dest=org.freedesktop.sssd.infopipe \
    /org/freedesktop/sssd/infopipe/Users \
    org.freedesktop.sssd.infopipe.Users.ListByCertificate \
    string:"$(cat ~/pki/user.pem)" uint32:10
```

Expect an object path under `/org/freedesktop/sssd/infopipe/Users/`. That is
SSSD confirming it maps your certificate to a real AD user.

> **This needs SSSD's InfoPipe, a separate responder.** `sssd-dbus` is installed,
> but `ifp` also has to be running. `ServiceUnknown` or `NameHasNoOwner` means
> that is what is missing — **not** your certificate:
>
> ```bash
> systemctl status sssd-ifp.service          # socket-activated
> grep -n '^services' /etc/sssd/sssd.conf    # currently: nss, pam
> ```
>
> Add it with `services = nss, pam, ifp` and restart SSSD. This tool does not add
> `ifp` by itself, because card authentication works without it. If you would
> rather skip this check, step 5 already proves the same thing through `sssctl`.

---

## 8. Enable PAM, carefully ✅ verified

**Open a second SSH session now and keep it open.** If PAM goes wrong, that
session is how you fix it.

```bash
sudo pam-auth-update --enable sss-smart-card-optional
```

`optional` means card **or** password. Do not reach for `required` until a card
login has worked.

> Do not run `pam-auth-update --list`. That flag does not exist, so the command
> falls through to an interactive debconf dialog; with no terminal it loops
> forever. (Found the hard way on this host — it changed nothing, because
> `pam-auth-update` refuses an empty selection.) To see the current state:
>
> ```bash
> sudo debconf-show libpam-runtime | grep profiles
> grep -nE 'pam_sss' /etc/pam.d/common-auth
> ```

### `local_auth_policy` — the step that is missing from every guide ✅ verified

PAM being right is not enough. On the first run here everything checked out —
the certmap rule loaded, `sssctl cert-map` resolved `testuser@...`, `p11_child`
read and verified the card, `pam check` reported `try_cert_auth` — and
`pamtester` still asked for a **password**. Raising `debug_level` to 9 showed
the reason in `/var/log/sssd/sssd_pam.log`:

```
[pam] [pam_reply] (0x0400): [CID#1] Local auth policy allowed: smartcard [False], passkey [True]
```

`local_auth_policy` lives in the **domain** section and defaults to `match`,
which means "offer what the backend offers". The AD provider has no Smart Card
authentication of its own, so SSSD declined the card it had just verified.

The tool handles this from 0.2.1 onwards. Check it:

```bash
sudo sssd-smartcard pam check
```

```
  local_auth_policy:     ad.example.com = enable:smartcard
...
[PASS] local_auth_policy ad.example.com  enable:smartcard -- SSSD may authenticate the card locally
```

A `[FAIL]` there means re-applying the profile adds the one missing line:

```bash
sudo sssd-smartcard config apply /etc/sssd-smartcard/profiles/AD-PIV-UPN.yaml --yes
```

```diff
 ad_gpo_access_control = permissive
+local_auth_policy = enable:smartcard
```

Two consequences, both deliberate:

* with a card inserted the Smart Card becomes the **preferred** method, so the
  prompt is a PIN rather than a password;
* it authenticates **locally**, so the session gets no Kerberos TGT. That is
  step 10, and it is a separate mechanism.

### Test without logging out ✅ verified

```bash
pamtester -v login testuser@ad.example.com authenticate
```

```
pamtester: invoking pam_start(login, testuser@ad.example.com, ...)
pamtester: performing operation - authenticate
PIN for Test User:
pamtester: successfully authenticated
```

That is the whole chain working: the card was found, the certificate verified
against the CA bundle, the certmap rule matched it, the account resolved in AD,
`local_auth_policy` let SSSD accept it, and the token signed with the private
key to prove the PIN. The prompt is a **PIN**, not a password — that is how you
know the card path was taken and not the fallback.

If it still says `Password:`, the layers to check, in this order — each one has
its own command, so none of this needs `debug_level`:

| Layer | Command | What right looks like |
|---|---|---|
| certmap rule loads | `sudo sssd-smartcard mapping test --from-card` | `MATCH`, decided by sssctl |
| account resolves | `sudo sssctl cert-map --certificate ...` | the user name, not "no mapped users found" |
| card is readable | `sudo sssd-smartcard card detect` | the token and the certificate |
| PAM is enabled | `sudo sssd-smartcard pam check` | `try_cert_auth` |
| SSSD will accept it | `sudo sssd-smartcard pam check` | `local_auth_policy ... PASS` |

> Do not test this over SSH as a login method. `sshd` is absent from the
> documented default of `pam_p11_allowed_services` (`login, su, su-l,
> gdm-smartcard, gdm-password, gdm-switchable-auth, kdm, plasmalogin, sudo,
> sudo-i, gnome-screensaver`), and `pam_sss` reads the card on the *server*,
> which is not where your card is when you connect remotely. `pamtester` and the
> VMware console are the right tools.

---

## 8b. Home directories — the black screen ✅ verified

Do this **before** the first graphical login, not after.

```bash
sudo pam-auth-update --enable mkhomedir
```

`fallback_homedir = /home/%u@%d` in sssd.conf only *names* the path. Nothing
creates it. Without `pam_mkhomedir.so` in `common-session`, the first login of
every domain user authenticates correctly, the session starts — and GNOME
shows a **black screen**, because it has nowhere to write. `loginctl` happily
reports the session as active:

```
SESSION        UID USER                            SEAT  TTY   STATE
    114 1000001101 testuser@ad.example.com seat0 tty2  active
```

and the journal says what is actually wrong:

```
gsd-keyboard: Failed to create directory /home/testuser@ad.example.com/.local/share/...: Permission denied
nautilus: Failed to create file ".../.config/dconf/user.LOGUW3": No such file or directory
```

Verify it works, without needing a second domain account:

```bash
sudo pamtester login <some-user-without-a-home> open_session
```

```
Creating directory '/home/<some-user-without-a-home>'.
pamtester: successfully opened a session
```

For a user who already logged in before you enabled this, create the directory
by hand once (`doctor` prints this command with the right ids filled in):

```bash
sudo install -d -m 0700 -o <uid> -g <gid> "/home/<user>@<domain>" && sudo cp -rT /etc/skel "/home/<user>@<domain>" && sudo chown -R <uid>:<gid> "/home/<user>@<domain>"
```

From 0.2.2 the tool checks both halves, so this is not something you meet at a
black screen:

```bash
sudo sssd-smartcard doctor --user testuser@ad.example.com
```

```
[PASS] home provisioning  pam_mkhomedir.so in /etc/pam.d/common-session creates missing home directories
[PASS] home directory     /home/testuser@ad.example.com (mode 0o700, uid 1000001101)
```

> `pam_mkhomedir` creates the directory as `0750`, so other members of
> `domain users` can read it. The tool warns about that; `chmod 0700` if you
> want it private.

---

## 9. The graphical login screen ✅ verified

The desktop is installed and GDM is running. Its authentication behaviour is
configured separately from `common-auth`, through `gdm-config` (verified present
at `/usr/bin/gdm-config`):

```bash
sudo gdm-config show                   # current state
sudo gdm-config smartcard --enable
sudo gdm-config password --enable      # keep the password fallback while testing
sudo gdm-config smartcard --required   # card only, once you are confident
sudo gdm-config reset                  # back to defaults
```

Subcommands: `help`, `password`, `fingerprint`, `smartcard`, `reset`, `show`.

### How GDM picks its PAM stack

`/etc/pam.d/gdm-smartcard` is a **symlink managed by update-alternatives**, and
on this host it resolves to `gdm-smartcard-sssd-exclusive`:

```bash
sudo update-alternatives --display gdm-smartcard
```

| Variant | Priority | Behaviour |
|---|---|---|
| `gdm-smartcard-sssd-exclusive` | 50 (current) | card via `pam_sss`, no password fallback in this service |
| `gdm-smartcard-sssd-or-password` | 40 | card via `pam_sss`, falls back to `common-auth` |
| `gdm-smartcard-pkcs11-exclusive` | 30 | card via `pam_pkcs11` instead of SSSD |

Password login at the greeter goes through a different service entirely,
`/etc/pam.d/gdm-password`, which includes `common-auth`. That is why the greeter
can offer both.

> **`gdm-config show` can lie on a fresh install.** On this host it reported
> *Password authentication: Disabled, Smart Card authentication: Required* while
> also warning that `/var/lib/gdm3/greeter-dconf-defaults` does not exist. The
> authoritative values are the dconf keys, and both were in fact `true`:
>
> ```bash
> sudo -u gdm env DCONF_PROFILE=gdm gsettings get org.gnome.login-screen enable-password-authentication
> sudo -u gdm env DCONF_PROFILE=gdm gsettings get org.gnome.login-screen enable-smartcard-authentication
> ```
>
> If `gdm-config show` alarms you, check those two keys and
> `/etc/pam.d/gdm-password` before believing it.

### What the login actually looked like ✅ verified

At the VMware console, with the card inserted, the card login worked — with
one thing to know:

**The username must be typed in full UPN form**, `testuser@ad.example.com`.
A short `testuser` is not a user at all as far as SSSD is concerned, because the
join set:

```ini
use_fully_qualified_names = True
```

That applies everywhere, not just at the greeter: `id testuser` fails,
`id testuser@ad.example.com` works, and the home directory is named
`/home/testuser@ad.example.com` to match. Setting it to `False` gives
short names, but in a cross-domain trust short names can collide, which is why
the join turns it on.

> The `gdm-smartcard-sssd-exclusive` stack carries `pam_sss.so
> allow_missing_name`, which is meant to identify the user *from the
> certificate* so nothing needs typing. That did not happen here; the name was
> still required. Not yet investigated — the login works either way.

---

## 10. Kerberos: is a ticket actually issued? ✅ verified

A successful card login does **not** by itself give the user a Kerberos TGT.
That needs PKINIT, and it is a separate question with a separate answer.

```bash
# in the logged-in user's session, not under sudo:
sssd-smartcard krb5 status
```

> Running `krb5 status` under `sudo` reads root's cache (`/tmp/krb5cc_0`) and
> will say "No credentials cache found" even when the user has a perfectly good
> ticket. That is what `doctor` reported here.

PKINIT on this host needed **four** things. Card login worked without any of
them, which is the point: these two mechanisms share only the certificate.

### 10a. The PKINIT plugin — and a false success worth understanding

```bash
sudo apt-get install -y krb5-pkinit
```

Skip this and the failure mode is genuinely dangerous. MIT's `kinit` **silently
ignores** `-X X509_user_identity` when the plugin is absent, prompts
`Password for <principal>`, and returns a perfectly valid TGT from your
password. The first run here reported `[PASS] PKINIT` for a ticket the card had
nothing to do with. The giveaway was in the prompt: `Password for ...` instead
of `PIN for ...`.

`krb5 test` now refuses to run `kinit` at all without the plugin, rather than
collecting a password during a card test, and its verdict requires `KRB5_TRACE`
to show a `pkinit` module returning `0/Success`.

### 10b. Make SSSD's Kerberos snippets live

```bash
sudo sed -i '1i includedir /var/lib/sss/pubconf/krb5.include.d/' /etc/krb5.conf
```

SSSD writes three snippets there. Without this line they are inert — and
nothing visibly breaks, because the realm comes from `default_realm` and the KDC
from DNS.

### 10c. Trust anchors for the KDC's certificate

```bash
sudo sed -i '/^\[libdefaults\]/a \tpkinit_anchors = FILE:/etc/sssd/pki/sssd_auth_ca_db.pem' /etc/krb5.conf
```

PKINIT is mutual: the KDC must prove itself to the client too.

### 10d. The DC's certificate is the wrong template ✅ the real blocker

With the above, the PIN prompt appeared — then a password prompt, then
failure. PKINIT engaged and rejected the KDC. The reason is the DC's own
certificate:

```
X509v3 Extended Key Usage: TLS Web Client Authentication, TLS Web Server Authentication
X509v3 Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1, DNS:DC01.ad.example.com
```

RFC 4556 wants `id-pkinit-KPKdc` (1.3.6.1.5.2.3.5) and `id-pkinit-san`
(1.3.6.1.5.2.2). This is Microsoft's older **Domain Controller** template, which
has neither. Windows accepts it for backwards compatibility; MIT does not,
because `pkinit_eku_checking` defaults to `kpKDC`.

The tool reads the DC's certificate and tells you the options:

```bash
sudo sssd-smartcard krb5 test --pkinit --principal testuser@ad.example.com
```

```
[WARN] KDC certificate PKINIT suitability  lacks id-pkinit-KPKdc EKU (1.3.6.1.5.2.3.5)
       and id-pkinit-san otherName (1.3.6.1.5.2.2); EKU is clientAuth, serverAuth
[INFO] needs pkinit_eku_checking  kpServerAuth
[INFO] needs pkinit_kdc_hostname  DC01.ad.example.com
```

The proper fix is to reissue the DC certificate from a **Kerberos
Authentication** template. To accept the one it has:

```bash
sudo sed -i '/^\[libdefaults\]/a \tpkinit_kdc_hostname = DC01.ad.example.com' /etc/krb5.conf
```

```bash
sudo sed -i '/^\[libdefaults\]/a \tpkinit_eku_checking = kpServerAuth' /etc/krb5.conf
```

`pkinit_kdc_hostname` must match the `dNSName` in the certificate.

### 10e. The verified result

```bash
sudo sssd-smartcard krb5 test --from-card --pkinit
```

```
Test User                    PIN:

[PASS] pkinit_anchors  FILE:/etc/sssd/pki/sssd_auth_ca_db.pem
[PASS] PKINIT plugin  /usr/lib/x86_64-linux-gnu/krb5/plugins/preauth/pkinit.so
[PASS] PKINIT  the card obtained krbtgt/AD.EXAMPLE.COM@AD.EXAMPLE.COM
       for testuser\@ad.example.com@AD.EXAMPLE.COM
       (KRB5_TRACE confirms PA-PK-AS-REQ)

PKINIT succeeded: the KDC issued a ticket for this card
```

A PIN prompt and **no** password prompt. The `\@` in the principal is normal:
that is how MIT renders an enterprise principal passed with `-E`.

---

## 11. Revocation and Group Policy (optional)

### CRL

Your PKI publishes a current CRL, refreshed today. SSSD reads a CRL from a
**local PEM file** via `crl_file=`; it does not fetch the distribution point, and
AD CS publishes DER, so it needs converting:

```bash
cd /tmp
curl -sO "http://pki.example.com/PKI/Example%20Issuing%20CA%20-%20homelab.crl"
sudo openssl crl -inform DER -in "Example Issuing CA.crl" \
    -outform PEM -out /etc/sssd/pki/issuing-ca.crl.pem
```

Nothing refreshes that file by itself — schedule a timer or cron job, or the CRL
will expire and verification will start failing. Then in the profile:

```yaml
revocation:
  enabled: true
  method: crl
  fail_mode: closed
  crl_file: /etc/sssd/pki/issuing-ca.crl.pem
```

### Group Policy

Two unrelated things, kept apart.

**SSSD's own logon-rights check** is configured by step 6 as
`ad_gpo_access_control = permissive` — it evaluates the Windows logon rights and
logs what it *would* deny without denying it. Read the log, and only then:

```bash
sudo sssd-smartcard-setup --gpo-enforcing --yes --skip packages,join,ca,card
journalctl -u sssd | grep -i gpo
```

`sssd-ad(5)` documents the default as `enforcing`, which is why the tool takes
control of it and starts permissive.

**Canonical's adsys**, the real GPO client:

```bash
sudo apt install adsys
sudo adsysctl update -m
adsysctl policy admx lts-only       # templates for your AD
```

dconf policy is available to everyone; other adsys features need an Ubuntu Pro
subscription, free for up to five machines. Certificate auto-enrolment from AD CS
additionally needs `certmonger` and `cepces`, and is switched on in the GPO under
*Computer Configuration → Policies → Windows Settings → Security Settings →
Public Key Policies → Certificate Services Client - Auto-Enrollment*.

---

## If something breaks

```bash
sudo sssd-smartcard doctor --user testuser@ad.example.com
sudo sssd-smartcard-setup --check --test-user testuser@ad.example.com
```

Logs and backups:

```bash
ls -lt /var/log/sssd-smartcard-setup-*.log | head
ls -lt /var/lib/sssd-smartcard/backups/
sudo journalctl -u sssd -n 100 --no-pager
```

Roll back by hand if you ever need to:

```bash
sudo cp -a /var/lib/sssd-smartcard/backups/<timestamp>/sssd.conf.orig /etc/sssd/sssd.conf
sudo chmod 600 /etc/sssd/sssd.conf
sudo systemctl restart sssd
```

Undo the PAM change:

```bash
sudo pam-auth-update --disable sss-smart-card-optional --disable sss-smart-card-required
```

## Reading order for the symptom you hit

| Symptom | Where the fault is |
|---|---|
| `id user@domain` fails | step 2. Nothing below it can work. |
| `tkey query failed` in the journal | step 2. Cosmetic — `dyndns_update`, not cards. |
| `doctor` says "no trusted domains" | expected here: single domain, accounts in the joined domain. |
| `doctor` warns about `pcscd.service` inactive | fixed in 0.2.0 — pcscd is socket-activated; `pcscd.socket` active is correct. |
| `p11_child --pre` fails | the CA bundle. Steps 3 and 7. |
| `mapping test` says NO MATCH | which term failed, step 5. Usually issuer or UPN suffix. |
| `cert inspect` infers an unexpected domain | alternative UPN suffix. Use `--domain ad.example.com`, step 4. |
| `ListByCertificate` → `ServiceUnknown` | the `ifp` responder, not the certificate. Step 7. |
| `pamtester` fails but steps 5 and 7 passed | PAM, step 8. |
| Login works, Kerberised services do not | PKINIT, step 10. Not a card problem. |
| `krb5 status` says no cache under `sudo` | you are reading root's cache. Run it as the user. |
| Login denied after enabling GPO | `ad_gpo_access_control`, step 11. Go back to permissive. |
| `man 8 …` prints "system has been minimized" | step 1 — dpkg excludes dropped the docs. |
| a CA fingerprint "does not match" | you compared a **file** hash with a **certificate** fingerprint. Step 3. |
| `certutil: command not found` / NSS usage text | `certutil -hashfile` is Windows-only. Step 3. |
| `kinit -k` says "no suitable keys for host/…" | the FQDN is outside the AD zone; name the keytab principal. Step 3. |
| `card detect` finds no reader, but `sudo` does | polkit `access_pcsc`: an SSH session has no seat. Step 4. |
| card commands work as root but not as the user | same thing. Use `sudo`, or the console. Step 4. |
