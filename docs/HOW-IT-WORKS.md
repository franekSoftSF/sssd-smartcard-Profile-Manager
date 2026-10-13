# How Smart Card login works, as verified

This describes the mechanism that is actually running, not a design. Every
component, option and log line below was observed on a real host:

| | |
|---|---|
| Client | Ubuntu 24.04, SSSD 2.9.4, joined with `adcli` via `realmd` |
| Domain | `ad.example.com` (Samba AD), `AD.EXAMPLE.COM` |
| PKI | Example Root CA → Issuing CA (homelab), two-tier |
| Token | YubiKey OTP+FIDO+CCID, PIV applet, `Certificate for PIV Authentication` |
| Account | `testuser@ad.example.com` (`CN=Test User`) |
| Result | `PIN for Test User:` → `pamtester: successfully authenticated` |

The tool that produced the configuration is `sssd-smartcard` 0.2.1. Nothing here
is specific to Microsoft AD CS — the PKI is only the source of the certificate.

---

## 1. What happens when the user authenticates

```
   login / gdm-smartcard / pamtester
        │
        │  PAM
        ▼
   pam_sss.so try_cert_auth            /etc/pam.d/common-auth
        │
        │  unix socket /var/lib/sss/pipes/pam
        ▼
   sssd_pam  (the PAM responder)       [pam] section of sssd.conf
        │
        ├── 1. fork p11_child ─────────► PKCS#11 / p11-kit ─► pcscd ─► card
        │        reads the certificate, builds the chain, verifies it
        │        against pam_cert_db_path, then asks the token to sign
        │        with the private key to prove the PIN
        │
        ├── 2. evaluate the certmap rules  [certmap/...] sections
        │        matchrule  → is this certificate acceptable?
        │        maprule    → what LDAP search finds its owner?
        │
        ├── 3. hand the search to the ID provider (id_provider = ad)
        │        → LDAP/Kerberos query to the DC, resolves the account
        │
        └── 4. consult local_auth_policy  domain section
                 may SSSD accept a locally checked Smart Card at all?
                 │
                 ▼
              PAM_SUCCESS
```

Four independent things must all be true. Each one has its own configuration
option, its own failure mode and its own diagnostic command — which is why a
single "it asks for a password" symptom has four different causes.

### Step 1 — the card and the certificate (`p11_child`)

`sssd_pam` never touches the token itself; it forks `p11_child`, which goes
through p11-kit to the PKCS#11 module and through `pcscd` to the reader.

`p11_child` does three things: it reads the certificate off the slot, it builds
and verifies the chain against `pam_cert_db_path`
(`/etc/sssd/pki/sssd_auth_ca_db.pem`), and — only after the certificate is
trusted — it asks the token to sign a challenge with the private key, which is
what the PIN unlocks.

**The private key never leaves the token.** SSSD does not read it and neither
does this tool. The PIN is passed to the PKCS#11 `C_Login` call and is never
written to disk, logged, or stored in a profile.

Verified independently of PAM:

```bash
sudo /usr/libexec/sssd/p11_child --pre -d 10 --debug-fd=2 \
     --ca_db=/etc/sssd/pki/sssd_auth_ca_db.pem
```

```
[do_slot] Found [Test User] in slot [Yubico YubiKey OTP+FIDO+CCID 00 00][0]
```

### Step 2 — certificate to user (`certmap`)

```ini
[certmap/ad.example.com/AD-PIV-UPN]
matchrule = KRB5:<ISSUER>^CN=Example Issuing CA,DC=ad,DC=example,DC=pl$<EKU>clientAuth,msScLogin<SAN:ntPrincipalName>.*@ad\.example\.pl$
maprule = LDAP:(|(userPrincipalName={subject_nt_principal})(sAMAccountName={subject_nt_principal.short_name}))
```

The section name carries two separate pieces of information: the domain whose
rules these are (`ad.example.com` — the domain **this host is joined
to**) and the rule name (`AD-PIV-UPN`, which is the profile file's name).

**`matchrule` — which certificates are acceptable.** Three components, and they
are **concatenated with no operator at all**. This is the single most
consequential detail in the whole configuration:

| Component | Means |
|---|---|
| `<ISSUER>^CN=Example Issuing CA...$` | issued by exactly this CA, anchored at both ends |
| `<EKU>clientAuth,msScLogin` | has both Extended Key Usages |
| `<SAN:ntPrincipalName>.*@ad\.example\.pl$` | the UPN in the SAN ends with this realm |

An infix `" && "` between components makes `libsss_certmap` reject the whole
rule with `[22][Invalid argument]`, SSSD skips it, falls back to its default
`userCertificate;binary` mapping, finds nobody, and login silently drops to the
password prompt. See `docs/sssd-reference.md` for the measured evidence; the man
page wording genuinely reads as though `&&` were infix.

The anchors matter too: without `^...$`, `<ISSUER>CN=Issuing CA` would also
accept a CA called `CN=Issuing CA-Evil`.

**`maprule` — which LDAP search finds the owner.** `{subject_nt_principal}` is
the UPN from the certificate's SAN; `.short_name` is the part before the `@`.
The `(|...)` alternative means the rule survives an account whose
`userPrincipalName` does not match its `sAMAccountName`.

**On alternative UPN suffixes:** the UPN in the certificate is what the rule
matches, and it can differ from the AD domain name. If the certificate says
`testuser@example.com` while the domain is `ad.example.com`, the
anchored `matchrule` will not match. `sssd-smartcard cert inspect` prints the
`Domain:` line it derived precisely so this is visible before anything is
applied.

### Step 3 — resolving the account

The map rule produces an LDAP filter; the ID provider runs it. Nothing
Smart-Card-specific happens here, which is why a broken trust or a DNS problem
shows up as a Smart Card failure. The account must already be resolvable by
name before any of this can work:

```bash
id testuser@ad.example.com
```

In the one-way-trust scenario (accounts in domain A, host joined to domain B)
this is also where `domains=` in the certmap section comes in — it tells SSSD to
search the trusted domain. On this host both are the same domain, so the tool
omitted `domains=` and said so.

### Step 4 — `local_auth_policy`, the one nobody documents

```ini
[domain/ad.example.com]
local_auth_policy = enable:smartcard
```

This is the option that decides whether all of the above is allowed to count.
It defaults to `match` — "offer whatever the backend offers" — and the AD
provider has no Smart Card authentication of its own. Under the default, SSSD
reads the card, verifies the certificate, maps it to a real user, and then
declines:

```
[pam] [pam_reply] (0x0400): [CID#1] Local auth policy allowed: smartcard [False], passkey [True]
```

`pam_sss` then falls through to the password prompt, and every certmap-level
diagnostic still reports success. This cost a full debugging session to find,
and is why `sssd-smartcard doctor` and `pam check` now report the option
explicitly.

---

## 2. The verified configuration, annotated

```ini
[sssd]
domains = ad.example.com
services = nss, pam
certificate_verification = no_ocsp     # the cert has no OCSP AIA; see §5

[domain/ad.example.com]
id_provider = ad                       # from the realm join
access_provider = ad
ad_gpo_access_control = permissive     # see §6 -- the default is enforcing
local_auth_policy = enable:smartcard   # ← step 4; without this, no card login

[certmap/ad.example.com/AD-PIV-UPN]
matchrule = ...                        # ← step 2
maprule = ...

[pam]
pam_cert_auth = True                   # ← enables the whole code path
```

Four lines of the file are what makes Smart Card login work: `pam_cert_auth`,
`local_auth_policy`, `matchrule`, `maprule`. Everything else came from the
domain join.

`/etc/sssd/sssd.conf` is mode `0600`, owner root — SSSD refuses to start
otherwise, and the tool always writes it back that way.

**Home directories.** `fallback_homedir = /home/%u@%d` only *names* the path;
something has to create it. On this host that is `pam_mkhomedir.so` in
`/etc/pam.d/common-session`, enabled with `pam-auth-update --enable mkhomedir`
(on RHEL: `authselect enable-feature with-mkhomedir`, plus `oddjobd`). Without
it the first login of every domain user succeeds and lands in a session that
cannot write anything — a black screen under GNOME. Verified working:

```
$ sudo pamtester login <fresh-user> open_session
Creating directory '/home/<fresh-user>'.
pamtester: successfully opened a session
```

`doctor` reports both halves, so this is no longer something you discover at a
black screen:

```
[PASS] home provisioning  pam_mkhomedir.so in /etc/pam.d/common-session creates missing home directories
[PASS] home directory     /home/testuser@ad.example.com (mode 0o700, uid 1000001101)
```

**PAM** (`/etc/pam.d/common-auth`, written by `pam-auth-update`, never by this
tool):

```
auth  [success=3 default=ignore]  pam_sss.so allow_missing_name try_cert_auth
auth  [success=1 default=ignore]  pam_sss.so use_first_pass
```

`try_cert_auth` = card first, password still accepted. `require_cert_auth` =
card only. `allow_missing_name` is what lets the user be identified *from the
certificate* rather than typed in — that is how a GDM card login with no
username works.

**CA trust** (`/etc/sssd/pki/sssd_auth_ca_db.pem`), both tiers, verified against
AD's NTAuth store over Kerberos LDAP before being imported:

```
subject=CN = Example Root CA
subject=DC = pl, DC = example, DC = ad, CN = Example Issuing CA
```

This bundle is the trust decision. Anything in it can issue a certificate that
logs in, subject to the `matchrule`.

---

## 3. Two authentication paths, and why the session has no ticket

What was verified is **local** Smart Card authentication: `p11_child` checks the
certificate and the PIN on this machine. The user is authenticated. The user has
**no Kerberos TGT**.

```bash
klist          # after a card login: no ticket cache
```

A TGT requires **PKINIT** — the KDC itself validating the certificate and
issuing a ticket. That is a different mechanism with different prerequisites:
the KDC needs its own certificate, the client needs `krb5_pkinit` configuration
and the CA in `/var/lib/sss/pubconf/krb5.include.d/`, and the certificate needs
the `pkinit` or `ntPrincipalName` SAN the KDC expects.

```bash
sudo sssd-smartcard krb5 test --from-card --pkinit
```

Two client-side prerequisites are worth checking before blaming the KDC, and
`krb5 test` now reports both:

* **`pkinit_anchors`** — the client must trust the CA that signed the *KDC's*
  certificate. Without it the client cannot validate the KDC and no ticket is
  possible, regardless of how good the user certificate is.
* **`includedir`** — on the verified host `/etc/krb5.conf` was the stock MIT
  sample plus a `default_realm` line, and never included
  `/var/lib/sss/pubconf/krb5.include.d/`. SSSD had written three snippets there
  (`domain_realm_*`, `krb5_libdefaults`, `localauth_plugin`) and all three were
  inert. Card login was unaffected — it is local authentication and does not
  consult them — but SSSD's realm mapping and localauth plugin were doing
  nothing, and anything configured through those snippets would too. The fix is
  one line at the top of krb5.conf:

  ```ini
  includedir /var/lib/sss/pubconf/krb5.include.d/
  ```

This is deliberately a separate command with a separate verdict, because "the
user logged in" and "the user can reach Kerberized services" are different
claims.

**PKINIT is verified working on this host**, with this configuration:

```ini
[libdefaults]
    pkinit_eku_checking = kpServerAuth
    pkinit_kdc_hostname = DC01.ad.example.com
    pkinit_anchors = FILE:/etc/sssd/pki/sssd_auth_ca_db.pem
```

plus the `krb5-pkinit` package. The result:

```
[PASS] PKINIT  the card obtained krbtgt/AD.EXAMPLE.COM@AD.EXAMPLE.COM
       for testuser\@ad.example.com@AD.EXAMPLE.COM
       (KRB5_TRACE confirms PA-PK-AS-REQ)
```

The two non-obvious options are forced by the DC's certificate, which comes from
Microsoft's older *Domain Controller* template and carries `serverAuth` plus a
`dNSName` rather than the `id-pkinit-KPKdc` EKU and `id-pkinit-san` that
RFC 4556 specifies. Windows accepts that; MIT's `pkinit_eku_checking` defaults
to `kpKDC` and does not. `krb5 test --pkinit` reads the DC's certificate and
names the options itself — see `docs/sssd-reference.md` for the measured detail.

A note on what "verified" means here. `krb5 test` requires `KRB5_TRACE` to show
a `pkinit` preauth module returning `0/Success`; it does not accept a ticket in
the cache as proof. Without that rule the tool reported PASS for a TGT that a
**password** had obtained, because the PKINIT plugin was missing and kinit had
silently ignored the card. It now refuses to run kinit at all in that state,
rather than prompting for a password during a card test. On a Samba AD DC without a KDC certificate, expect the PKINIT test to
fail while login keeps working — that is consistent, not contradictory.

`local_auth_policy = enable:smartcard` also makes the card the *preferred*
method when one is present, so it is what guarantees the PIN prompt — and, for
the same reason, what guarantees no TGT on that path.

---

## 4. Operating it: which command answers which question

Each layer in §1 has one command. Run them in this order; the first failure is
the real cause.

| Question | Command | Right answer |
|---|---|---|
| Is everything sane? | `sudo sssd-smartcard doctor` | no FAIL |
| Is the card visible? | `sudo sssd-smartcard card detect` | token + certificate |
| What does the certificate say? | `sudo sssd-smartcard cert inspect --from-card` | issuer, UPN, EKU, `Domain:` |
| Would this certificate map? | `sudo sssd-smartcard mapping test --from-card` | `MATCH`, decided by sssctl |
| Does SSSD agree? | `sudo sssctl cert-map --certificate <file>` | the user name |
| Is PAM enabled? | `sudo sssd-smartcard pam check` | `try_cert_auth` |
| Will SSSD accept a card? | `sudo sssd-smartcard pam check` | `local_auth_policy ... PASS` |
| Can a session start? | `sudo sssd-smartcard doctor --user <user>` | `home provisioning` and `home directory` both PASS |
| Does login work? | `pamtester -v login <user> authenticate` | `PIN for ...` then success |
| Is a ticket issued? | `sudo sssd-smartcard krb5 test --from-card --pkinit` | separate question, see §3 |

Two things about running these:

* **`card detect` needs root.** `pcsc-lite` authorises through polkit
  (`org.debian.pcsc-lite.access_pcsc`, `allow_any=no, allow_inactive=no`), and
  an SSH session has no seat, so an unprivileged SSH user is denied and the
  error looks like a missing reader. The tool says so explicitly now.
* **Do not test over SSH as a login method.** `sshd` is absent from the
  documented default of `pam_p11_allowed_services`, and `pam_sss` reads the card
  on the *server* — which is not where your card is. `pamtester` and the console
  are the right tools.

### Logs

Default debug level says almost nothing useful. When you need more:

```bash
sudo sssd-smartcard config diff          # see what would change first
# raise debug_level = 9 in [pam] and the domain section, restart sssd
sudo tail -f /var/log/sssd/sssd_pam.log /var/log/sssd/p11_child.log
```

The three lines worth grepping for:

| Line | Means |
|---|---|
| `Trying to add rule [NAME]...` | the certmap rule was parsed; if followed by `[22][Invalid argument]`, it was rejected and skipped |
| `Found [CN] in slot [...]` | `p11_child` read and verified the certificate |
| `Local auth policy allowed: smartcard [True]` | step 4 passed |

**Put `debug_level` back when you are done.** It logs a great deal, including
certificate contents. Keep a copy of the file before raising it.

---

## 5. Revocation

Currently `certificate_verification = no_ocsp`, because the certificate on this
card carries no OCSP AIA — with OCSP on and no responder to ask, verification
fails closed and nobody logs in.

That is a deliberate, stated trade-off, not an oversight: **a revoked
certificate currently still logs in.** To close it, use the CRL instead:

```ini
[sssd]
certificate_verification = no_ocsp, crl_file=/etc/sssd/pki/revocation.crl.pem
```

The CRL file has to be fetched and refreshed by something outside SSSD (a timer
pulling the CDP URL). `soft_crl` makes a stale or missing CRL non-fatal, which
is the soft-fail choice; `crl_file` alone fails closed. The profile's
`revocation` block generates either shape, and `sssd-smartcard` refuses to claim
revocation is enforced when it is not.

---

## 6. Access control: `ad_gpo_access_control`

Set to `permissive` here. `sssd-ad(5)` documents the default as **`enforcing`**,
which on a freshly joined host denies interactive login to anyone the domain's
GPOs do not explicitly grant `SeInteractiveLogonRight`. That is a very common
"the card works but login is refused" cause, and it is unrelated to
certificates.

`permissive` logs what it would have denied without denying it. Read the syslog
messages, fix the GPO, and only then switch to `enforcing` — with a root session
open.

---

## 7. Rolling this out to another host

The host-specific parts are the CA bundle and the certmap rule; both are
derivable. On a new machine:

```bash
sudo apt install ./sssd-smartcard_0.2.1_all.deb
sudo sssd-smartcard-setup --dry-run --test-user testuser@ad.example.com
sudo sssd-smartcard-setup --yes    --test-user testuser@ad.example.com
sudo pam-auth-update --enable sss-smart-card-optional
```

The setup script runs nine stages (preflight, packages, join, identity gate, CA,
card, certmap, GPO, PAM) and then verifies. The **identity gate** is the one
that matters: it refuses to continue until the test user resolves by name,
because Smart Card authentication cannot work before plain identity lookup does,
and a broken trust otherwise gets misdiagnosed as a certificate problem.

Or carry the profile over directly — it is the whole configuration:

```bash
sudo sssd-smartcard config apply /etc/sssd-smartcard/profiles/AD-PIV-UPN.yaml --dry-run
```

Every change is backed up to `/var/lib/sssd-smartcard/backups/<timestamp>/`
before anything is written, `sssctl config-check` must pass before SSSD is
restarted, and any failure — validation, restart, or the service not coming back
— rolls every touched file back. The PAM stack is only ever reported on, never
edited, because a bad PAM file locks you out of the machine.

### For the graphical login

GDM's Smart Card behaviour is configured separately from `common-auth`:

```bash
sudo gdm-config show          # reports what it believes, which is not always what is linked
ls -l /etc/pam.d/gdm-smartcard
```

`/etc/pam.d/gdm-smartcard` is an `update-alternatives` symlink —
`sssd-exclusive` (50), `sssd-or-password` (40), `pkcs11-exclusive` (30). Check
the link, not just `gdm-config show`.

---

## 8. What is trusted, and what is not

* **The CA bundle** at `/etc/sssd/pki/sssd_auth_ca_db.pem` is the trust
  decision. Any CA in it can issue a certificate that logs in, subject to the
  `matchrule`. It was verified against AD's NTAuth store before import, and the
  tool never overwrites a trust store without a backup.
* **The `matchrule`** is the second half of that decision: anchored issuer, and
  required EKUs. A certificate from another CA is rejected — this is covered by
  a regression test, not just by inspection.
* **The private key** is never read, by SSSD or by this tool. It stays on the
  token; authentication is a signature the token produces.
* **The PIN** is never stored, logged or written to a profile. It is passed to
  the PKCS#11 login call, and when the tool needs one for `kinit` it hands the
  terminal to `kinit` rather than capturing it.
* **`sssd.conf`** is `0600` root. The tool writes it atomically and never
  relaxes the mode.
* **A revoked certificate still logs in** until §5 is addressed. Stated plainly
  because a security property nobody wrote down is a security property nobody
  has.

---

## 9. The failure modes actually encountered

Recorded because each one looked like something else.

| Symptom | Real cause | How it was found |
|---|---|---|
| `sssctl cert-map` → "no mapped users found", login asks for a password | `matchrule` used an infix `" && "`; `libsss_certmap` rejected the rule with `[22][Invalid argument]` and skipped it, so SSSD fell back to its default mapping | `debug_level = 9`, `Trying to add rule` followed by the error |
| Tool reported `MATCH / decided by sssctl` for a rule SSSD had refused to load | the output parser tested for the substring `"match"`, which occurs inside `"matching"` in `Failed to add mapping and matching rules` | the two diagnostics disagreed with reality in the same direction |
| Everything passes, login still asks for a password | `local_auth_policy` defaulted to `match`; the AD provider offers no local Smart Card authentication, so SSSD declined the verified card | `debug_level = 9`, `Local auth policy allowed: smartcard [False]` |
| `card detect` → "no PC/SC reader detected" | polkit denied `org.debian.pcsc-lite.access_pcsc` to an unprivileged SSH session (no seat); the reader was fine | running the same command under `sudo` |
| Card login succeeds, then a **black screen** in GNOME | no home directory: `fallback_homedir` only declares the path, and `pam_mkhomedir` was absent from `common-session` | `journalctl` full of `Failed to create .../.config/dconf/user: No such file or directory` |
| `krb5 test --pkinit` reported `[PASS]`, having prompted for a **password** | the `krb5-pkinit` plugin was missing, so kinit ignored `-X X509_user_identity` and used password pre-auth; the tool inferred PKINIT from the resulting ticket | `KRB5_TRACE`: `Error loading plugin module pkinit` then `encrypted_timestamp (2) ... returned: 0/Success` |
| PIN prompt, then a password prompt, then failure | the DC's certificate lacks `id-pkinit-KPKdc` and `id-pkinit-san`; MIT's `pkinit_eku_checking` defaults to `kpKDC` and rejected the KDC | reading the DC certificate over LDAPS and comparing with RFC 4556 |

The pattern in nearly all of them: a layer reported success while a layer below
it had failed. Every one of them is now a check with its own name, so the next person
sees a `FAIL` with a hint instead of a password prompt.

---

## Sources

Every option above traces to upstream documentation; `docs/sssd-reference.md`
records the exact source per option, including the measured evidence for the
`matchrule` concatenation and the `local_auth_policy` version history
(`local_auth_policy` SSSD 2.9.2, local Smart Card 2.9.3).

* `sssd.conf(5)`, `sss-certmap(5)`, `sssd-ad(5)`, `pam_sss(8)`
* [Smartcard authentication — local](https://sssd.io/design-pages/smartcard_authentication_step1.html)
* [Smartcard authentication — PKINIT](https://sssd.io/design-pages/smartcard_authentication_pkinit.html)
* [local_auth_policy](https://sssd.io/design-pages/local_auth_policy.html)
