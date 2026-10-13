# Test lab

A throwaway environment that exercises the whole Smart Card path with **no
reader and no physical card**, so the setup script can be proven before it
touches a real host.

```
  dc  (192.168.56.10)                     client (192.168.56.11)
  ------------------------                ------------------------
  Samba AD DC, DOMAIN-B.LOCAL             Ubuntu domain member
  DNS for the domain                      sssd + libpam-sss
  Root CA -> Issuing CA                   SoftHSM2 token = "smart card"
  user jan.kowalski@domain-b.local        sssd-smartcard installed from source
  + a Rogue CA, for negative tests
```

The trick that makes this work is SoftHSM2. p11-kit advertises
`libsofthsm2.so` to SSSD's `p11_child` exactly like a real PKCS#11 driver, so
the card path — enumerate token, read certificate, verify chain, check PIN —
runs unmodified.

## Requirements

Vagrant with VirtualBox, and about 4 GB of free RAM — 7 GB with
`LAB_DESKTOP=1`. It works from Windows, macOS and Linux hosts.

On a **Windows host** add `LAB_SYNC=virtualbox`: the default `rsync` sync needs
an `rsync` binary, which Windows does not ship, and `vagrant up` fails on the
synced folder before provisioning even starts.

## Run it

```bash
cd lab
vagrant up
vagrant ssh client -c 'sudo /vagrant/run-tests.sh'
```

First `vagrant up` takes roughly 10-15 minutes: it provisions a Samba domain,
issues a small PKI, joins the client, builds the token and installs the tool.
Re-provisioning is idempotent:

```bash
vagrant provision dc
vagrant rsync client && vagrant provision client
```

With `LAB_SYNC=virtualbox` the share is live, so drop the `vagrant rsync` step.

Tear down with `vagrant destroy -f`.

## What the tests prove

`run-tests.sh` is the acceptance suite. It checks, in dependency order:

1. the emulated card is visible as a PKCS#11 token and its certificate is readable;
2. `cert autoconfig` derives a profile from the real certificate, recommends
   `san-upn`, and pins the issuing CA by itself;
3. the AD SID extension is decoded (the certificate carries the real `objectSid`);
4. `--dry-run` leaves `sssd.conf` byte-identical;
5. the real run configures the host, passes its own verification, and leaves
   `sssd.conf` at mode 0600 with the certmap section and `pam_cert_auth = True`;
6. `ad_gpo_access_control` is set to `permissive` rather than inheriting the
   documented `enforcing` default;
7. running setup twice changes nothing;
8. **SSSD's own `p11_child` verifies the card** — the exact code path used at login;
9. **SSSD maps the certificate to the right AD user** via the InfoPipe
   `ListByCertificate` call;
10. the mapping tester agrees with `sssctl cert-eval-rule`, and any disagreement
    is a failure;
11. a certificate from a different CA does **not** match, and an expired one is
    called out;
12. a profile needing a template this SSSD lacks is refused rather than degraded;
13. `id`/`getent` resolve the user, the KDC is reachable, `doctor` is clean;
14. **PAM was not modified**, because `--pam` was never passed.

## Log in for real

The suite stops short of an interactive login because that needs a PIN typed at
a terminal. Do it by hand on the client:

```bash
# enable the PAM profile (Ubuntu 23.10+)
sudo pam-auth-update --enable sss-smart-card-optional

# then test without risking your session
pamtester -v login jan.kowalski@domain-b.local authenticate
# PIN: 123456
```

This authenticates locally: `p11_child` verifies the certificate against the CA
bundle and checks the PIN by having the token sign with the private key.

`pamtester` is the right tool here, and **not** an SSH login. `sshd` is absent
from the documented default of `pam_p11_allowed_services` (`login, su, su-l,
gdm-smartcard, gdm-password, gdm-switchable-auth, kdm, plasmalogin, sudo,
sudo-i, gnome-screensaver`), and in any case `pam_sss` reads the card on the
*server*, which is not where your card is when you connect over SSH. For a real
interactive login use the VM console.

## Graphical environment: LAB_DESKTOP=1

Off by default. Everything this project is responsible for is testable from a
console, and a desktop only puts a GNOME layer between you and the actual fault.

```bash
LAB_DESKTOP=1 vagrant up
# or on an existing lab:
LAB_DESKTOP=1 vagrant provision client && vagrant reload client
```

What the switch changes:

| | default | `LAB_DESKTOP=1` |
|---|---|---|
| client RAM | 2048 MB | 4096 MB (`LAB_CLIENT_MEMORY` overrides) |
| VirtualBox window | hidden | shown (`vb.gui`) |
| video RAM | 16 MB | 128 MB, `vmsvga` controller |
| packages | server only | `+ ubuntu-desktop-minimal` (~1.5 GB) |
| default target | `multi-user.target` | `graphical.target` |

It does **not** configure the greeter, because this lab never edits PAM without
being asked and `run-tests.sh` asserts exactly that. GDM's behaviour lives in
`/etc/pam.d/gdm-smartcard`; set it yourself on the client:

```bash
sudo gdm-config smartcard --enable && sudo gdm-config password --enable
sudo gdm-config smartcard --required     # card only
```

On releases without `gdm-config`, write `[org/gnome/login-screen]` with
`enable-smartcard-authentication=true` into `/etc/dconf/db/local.d/` and run
`sudo dconf update`.

**Honest caveat.** GNOME switches to the card prompt on a *reader insertion
event*, which a SoftHSM token never produces — it is simply always present. The
greeter may therefore never offer the card by itself in this lab. Console login
and `pamtester` are unaffected and remain the reliable checks; treat the desktop
as a way to look at the greeter, not as a way to prove the card path.

For what actually matters to PIV, a desktop is unnecessary: certificate
auto-enrolment through adsys is machine-scoped (`adsysctl update -m`,
`certmonger`, `cepces`) and runs headless. Only adsys's dconf policy needs a
desktop session, and that has nothing to do with cards.

## Kerberos tickets are a separate question

A successful card login does **not** by itself produce a Kerberos TGT. That
needs PKINIT, which needs a KDC certificate on the domain controller — extra
Samba configuration this lab does not perform, because it is Samba
administration rather than anything this tool controls.

So in the lab:

```bash
sssd-smartcard krb5 test --from-card     # realm, KDC discovery, reachability, cert fitness
sssd-smartcard krb5 status               # shows there is no TGT yet
```

`sssd-smartcard krb5 test --from-card --pkinit` is the command that proves the
KDC issues a ticket. Run it once your real domain controller has a KDC
certificate; it will fail in this lab, which is the correct answer here.

## One-way trust

The real target scenario is accounts in DOMAIN A, host joined to DOMAIN B,
B trusts A. This lab is deliberately **single-domain**, for two reasons:

* everything the tool is responsible for is already exercised by one domain —
  the trusted-domain logic is about which `domains=` value gets written, and
  that is covered by the unit tests and visible in `cert inspect` output;
* a Samba-to-Samba forest trust is the least reliable part of such a lab, and
  the exact `samba-tool domain trust create` flags vary between Samba versions.
  Rather than ship a command that might not exist on your build, run
  `samba-tool domain trust create --help` on your DC and use what it prints.

To see the trusted-domain code path without a second domain, force the account
domain and watch the generated rule change:

```bash
sssd-smartcard cert inspect --from-card \
    --sssd-domain domain-b.local --domain domain-a.local
```

The section becomes `[certmap/domain-b.local/...]` and gains
`domains = domain-a.local`. The setup script's identity gate will then correctly
refuse, because SSSD cannot resolve users in a domain that is not there — which
is exactly the behaviour you want on a real host with a broken trust.

## Knobs

Override with environment variables before `vagrant up`:

| Variable | Default | Notes |
|---|---|---|
| `LAB_BOX` | `bento/ubuntu-24.04` | |
| `LAB_NET` | `192.168.56` | |
| `LAB_REALM` | `DOMAIN-B.LOCAL` | |
| `LAB_USER` | `jan.kowalski` | |
| `LAB_ADMINPASS` | `Passw0rd!2026` | |
| `LAB_CARD_PIN` | `123456` | |
| `LAB_DESKTOP` | `0` | `1` installs GNOME and shows the VM window |
| `LAB_CLIENT_MEMORY` | `2048`, or `4096` with a desktop | MB |
| `LAB_SYNC` | `rsync` | set `virtualbox` on a Windows host |

Use `LAB_BOX=bento/ubuntu-22.04` to test the other PAM path: 22.04 has no
`sss-smart-card-*` profiles, so the setup script should print the exact
`common-auth` line instead of running `pam-auth-update`. That is also a better
test of the Debian code path than Debian itself, since 22.04 takes the same
`manual` branch while still having adsys available.

## Every credential here is a throwaway

The PINs, passwords and private keys in this lab are fixed and public on
purpose. Never point this at a real domain, and never reuse these values.
