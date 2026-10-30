# SSSD facts this tool relies on

Every `sssd.conf` key, matching-rule keyword and mapping template the generator
emits is listed here with the documentation it came from. Nothing in the code
is derived from memory or inference; where upstream documentation is silent or
carries a caveat, this file says so and the tool warns at runtime.

## Certificate mapping sections

Source: [`sss-certmap(5)`](https://www.mankier.com/5/sss-certmap),
[`sssd.conf(5)`](https://www.mankier.com/5/sssd.conf)

```ini
[certmap/DOMAIN_NAME/RULE_NAME]
matchrule = ...
maprule   = ...
domains   = ...
priority  = ...
```

| Key | Default |
|---|---|
| `matchrule` | `KRB5:<EKU>clientAuth` |
| `maprule` | `LDAP:(userCertificate;binary={cert!bin})` for LDAP-based providers |
| `domains` | the rule's own domain |
| `priority` | lowest (0 is the **highest** priority) |

## Matching rule syntax

Default prefix `KRB5`. Components are joined with `&&` and `||`.

`<ISSUER>` `<SUBJECT>` `<KU>` `<EKU>` `<SAN>` `<SAN:Principal>`
`<SAN:ntPrincipalName>` `<SAN:pkinit>` `<SAN:rfc822Name>` `<SAN:dNSName>`
`<SAN:x400Address>` `<SAN:directoryName>` `<SAN:ediPartyName>`
`<SAN:uniformResourceIdentifier>` `<SAN:iPAddress>` `<SAN:registeredID>`
`<SAN:otherName>` `<SAN:dotted-decimal-oid>`

- `<ISSUER>` / `<SUBJECT>` take a POSIX ERE against the DN in RFC 4514 form,
  most specific component first.
- `<KU>` takes `digitalSignature, nonRepudiation, keyEncipherment,
  dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly,
  decipherOnly` or a numeric value.
- `<EKU>` takes `serverAuth, clientAuth, codeSigning, emailProtection,
  timeStamping, OCSPSigning, KPClientAuth, pkinit, msScLogin` or a
  dotted-decimal OID.
- `<SAN:otherName>`, `<SAN:x400Address>` and `<SAN:ediPartyName>` compare raw
  DER against a base64 string.
- These characters must be escaped in a regex: `^ . [ $ ( ) | * + ? { \`

**Where the tool is conservative.** It emits a symbolic EKU name only for
`serverAuth, clientAuth, codeSigning, emailProtection, timeStamping,
OCSPSigning, msScLogin`. `KPClientAuth` and `pkinit` are documented as keywords
but this project did not confirm which OID each maps to, so for those it writes
the dotted-decimal OID, which the syntax accepts everywhere a name is accepted.

### Combining components: concatenate, do not use an infix `&&`

This is the single most dangerous ambiguity in the SSSD documentation, and it
cost a working deployment to find.

`sss-certmap(5)` says only:

> Multiple keyword pattern pairs can be either joined with '&&' (and) or '||' (or).

which reads like an infix operator. It is not. The
[SSSD design page](https://sssd.io/design-pages/matching_and_mapping_certificates.html)
disambiguates it:

> And can be grouped together with a prefixed `&&` (and) or `||` (or) operator
> (`&&` is the default).

The operator is a **prefix for grouping**, and `&&` — being the default — is
never written. Every upstream example simply concatenates:

```
<ISSUER>^CN=CA,dc=ISSUER,DC=COM$<EKU>clientAuth
<ISSUER>^CN=AD-CA,dc=ISSUER,DC=COM$<EKU>clientAuth<SAN:ntPrincipalName>*@AD.DOM
<ISSUER>*my-company*<SAN:rfc822Name>*@my-company.com$
```

**Why an infix operator breaks.** A component's value runs to the next `<`, and
the operator characters are not stripped. Measured against SSSD 2.9.4:

| Rule | Result |
|---|---|
| `<ISSUER>^CN=Good$<SAN:ntPrincipalName>.*@d$` | **MATCH** |
| `<ISSUER>^CN=Good$ && <SAN:ntPrincipalName>.*@d$` | parses, **never matches** — the issuer regex becomes `^CN=Good$ && ` |
| `<ISSUER>^CN=Good$&&<SAN:...>` | parses, never matches — the regex becomes `^CN=Good$&&` |
| `<EKU>clientAuth && <SAN:...>` | **rejected, EINVAL** — `<EKU>` tries to read `clientAuth && ` as a key-usage list |

A rejected rule is not a soft failure. The backend logs

```
sss_certmap_add_rule failed for rule [NAME] with error [22][Invalid argument], skipping.
```

**skips the rule entirely**, and falls back to the default
`LDAP:(userCertificate;binary={cert!bin})`. On AD, where the certificate is not
stored on the user object, nothing ever matches — `sssctl cert-map` reports
"no mapped users found" and smart card login silently falls through to the
password prompt. Everything looks configured; nothing works.

**`<EKU>` and `<KU>` may appear anywhere**, including before other components:
their comma separated value terminates at the next `<`. Verified with positive
and negative controls, and it is what upstream's own example does.

**`||` is best avoided.** It does switch the rule to OR, but the literal `||`
is left in the preceding component's value, so the branch before it can never
match:

| Rule | Result |
|---|---|
| `<ISSUER>^CN=Bad$\|\|<SAN:...>good` | MATCH — via the SAN branch |
| `<ISSUER>^CN=Good$\|\|<SAN:...>bad` | **NO MATCH** — the issuer regex became `^CN=Good$\|\|` |

Use separate `[certmap/...]` sections with `priority` instead of OR inside one
rule.

**Always confirm a hand-written rule** with `sssctl cert-eval-rule`, and check
that the backend accepted it:

```bash
grep -i certmap /var/log/sssd/sssd_<domain>.log
```

## Mapping rule templates

Default prefix `LDAP`. The extended templates require `LDAPU1`.

`LDAP` prefix: `{issuer_dn}` `{subject_dn}` (each with
`!ad`/`!ad_x500`/`!ad_ldap`/`!nss_x500`/`!nss`/`!nss_ldap`), `{cert}`
(`!bin` default, `!base64`), `{subject_principal}`,
`{subject_pkinit_principal}`, `{subject_nt_principal}`,
`{subject_rfc822_name}`, `{subject_dns_name}` (each with `.short_name`),
`{subject_uri}`, `{subject_ip_address}`, `{subject_x400_address}`,
`{subject_directory_name}`, `{subject_ediparty_name}`,
`{subject_registered_id}`.

`LDAPU1` prefix: `{serial_number}` (`!dec`, `!hex[_ucr]`), `{subject_key_id}`
(`!hex[_ucr]`), `{cert!DIGEST[_ucr]}` (any OpenSSL digest),
`{subject_dn_component[.attr][[n]]}`, `{issuer_dn_component[...]}`,
`{sid[.rid]}`.

Modifiers: `u` upper case, `c` colon separated, `r` reversed bytes; combinable
(`!hex_ur`).

The recommended attribute to search is `altSecurityIdentities` on AD,
`ipaCertMapData` on IPA, and `userCertificate;binary` for a full DER match.

## Certificate verification

Source: [`sssd.conf(5)`](https://www.mankier.com/5/sssd.conf)

`certificate_verification` lives in `[sssd]`; `pam_cert_verification` in `[pam]`
overrides it for PAM only. Default: not set, i.e. verification is not
restricted.

| Value | Meaning |
|---|---|
| `no_ocsp` | disable OCSP checks |
| `soft_ocsp` | skip OCSP when the responder is unreachable |
| `ocsp_dgst=sha1\|sha256\|sha384\|sha512` | OCSP request digest |
| `no_verification` | disable verification entirely |
| `partial_chain` | accept a chain to a trusted but non-self-signed certificate |
| `ocsp_default_responder=URL` | **documented as currently ignored** |
| `ocsp_default_responder_signing_cert=NAME` | documented as currently ignored |
| `crl_file=/PATH` | CRL in PEM form, read from disk |
| `soft_crl` | keep using an expired CRL |

SSSD does **not** fetch CRL distribution points. `crl_file` is a local file
something else must keep current.

## `[pam]` options

| Option | Default |
|---|---|
| `pam_cert_auth` | `False` |
| `pam_cert_db_path` | `/etc/sssd/pki/sssd_auth_ca_db.pem` |
| `pam_cert_verification` | not set |
| `p11_child_timeout` | `10` |
| `p11_uri` | none |
| `pam_p11_allowed_services` | `login, su, su-l, gdm-smartcard, gdm-password, gdm-switchable-auth, kdm, plasmalogin, sudo, sudo-i, gnome-screensaver` |

`pam_p11_allowed_services` replaces the built-in list rather than extending it.

## `local_auth_policy` — the option that decides PIN or password

`local_auth_policy` lives in the **domain** section, not in `[pam]`, and it is
the difference between a PIN prompt and a password prompt.

| Value | Meaning |
|---|---|
| `match` | **default** — offer the methods the backend offers |
| `only` | offer only locally checked methods |
| `enable:<method>` | add a method to what the backend offers |
| `disable:<method>` | remove one (upstream design page; not in the man page) |

Methods: `password`, `otp`, `passkey`, `smartcard`. Values are comma separated,
so `enable:smartcard, enable:passkey` is valid.

**Why this matters:** the AD and LDAP providers have no Smart Card
authentication of their own, so under the default `match` SSSD reads the card,
verifies the certificate against the trust bundle, maps it to a real user
through the certmap rule — and then declines it:

```
[pam] [pam_reply] (0x0400): [CID#1] Local auth policy allowed: smartcard [False], passkey [True]
```

`pam_sss` then falls through to the password prompt. Measured on SSSD 2.9.4 with
a working YubiKey PIV certificate: `sssctl cert-map` resolved the account,
`sssctl cert-eval-rule` matched, `p11_child --pre` read and verified the card,
PAM carried `try_cert_auth` — and login still asked for a password. Nothing
except `debug_level = 9` showed the cause, which is why `doctor` and
`pam check` now report this option explicitly.

The fix, in the domain section:

```ini
[domain/ad.example.com]
local_auth_policy = enable:smartcard
```

Two consequences worth knowing before enabling it:

* with a card present the Smart Card becomes the **preferred** method, so the
  user is prompted for a PIN instead of a password (`sssd.conf(5)`);
* it authenticates locally, so it grants **no Kerberos TGT**. PKINIT is the
  separate path — see *Smart card authentication without PKINIT* below.

The tool writes this value for the `ad` and `ldap` providers and leaves `ipa`
alone, since IPA authenticates the card through the backend. An existing value
is extended rather than replaced, so a host that already had `enable:passkey`
ends up with `enable:passkey, enable:smartcard`; an existing `only` is left
untouched and reported, because guessing at which methods may be offered at all
could lock people out.

Source: `sssd.conf(5)` → `local_auth_policy`;
[local_auth_policy design page](https://sssd.io/design-pages/local_auth_policy.html)

## Version history

| Feature | Introduced |
|---|---|
| `p11_uri`, `crl_file` | 2.1.0 |
| `ocsp_dgst` | 2.2.1 |
| `soft_ocsp`, `soft_crl` | 2.2.3 |
| `{serial_number}`, `{subject_key_id}`, `{sid}`, `{cert!DIGEST}`, `{*_dn_component}` | 2.8.2 |
| `local_auth_policy` | 2.9.2 |
| `local_auth_policy = enable:smartcard` (local Smart Card) | 2.9.3 |

`partial_chain`, `no_ocsp`, `no_verification`, `pam_cert_auth` and
`pam_cert_verification` are documented without an introduction version; the
feature table records that explicitly instead of guessing one, and treats them
as always available.

## Enforcement lives in PAM, not in sssd.conf — and PAM differs per distribution

There is no "Smart Card only" option in `sssd.conf`. Enforcement is
`pam_sss.so require_cert_auth`. **How you turn that on has no portable answer**,
and getting this wrong is the most common way a setup script fails: `authselect`
does not exist on Ubuntu and `pam-auth-update` does not exist on RHEL.

### RHEL family — authselect

```bash
authselect select sssd with-smartcard with-smartcard-required --force
# or, incrementally:
authselect enable-feature with-smartcard
authselect enable-feature with-smartcard-required
```

`with-smartcard-required` adds `pam_sss.so require_cert_auth
ignore_authinfo_unavail`.

Source: [Configuring smart card authentication using authselect (RHEL 9)](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/managing_smart_card_authentication/configuring-smart-cards-using-authselect_managing-smart-card-authentication)

### Debian 13 and later, Ubuntu 23.10 and later — pam-auth-update

```bash
sudo pam-auth-update --disable sss-smart-card-required --enable sss-smart-card-optional
sudo pam-auth-update --disable sss-smart-card-optional --enable sss-smart-card-required
```

### Debian 12, Ubuntu 23.04 and earlier — by hand

No `sss-smart-card-*` profile exists, so the line goes into
`/etc/pam.d/common-auth` manually:

```
# optional, password still works
auth [success=ok default=ignore] pam_sss.so allow_missing_name try_cert_auth
# Smart Card only
auth [success=done default=die] pam_sss.so allow_missing_name require_cert_auth
```

### Ubuntu packages and paths

```bash
sudo apt install opensc-pkcs11 pcscd sssd libpam-sss
sudo cat Ca-Auth-CERT*.pem >> /etc/sssd/pki/sssd_auth_ca_db.pem
```

Verify the card with SSSD's own helper:

```bash
# Ubuntu 22.04 LTS and later
sudo /usr/libexec/sssd/p11_child --pre -d 10 --debug-fd=2 \
    --ca_db=/etc/sssd/pki/sssd_auth_ca_db.pem
# Ubuntu 20.04 LTS and earlier used --nssdb= instead of --ca_db=
```

Verify the mapping without logging out:

```bash
sudo dbus-send --system --print-reply \
    --dest=org.freedesktop.sssd.infopipe \
    /org/freedesktop/sssd/infopipe/Users \
    org.freedesktop.sssd.infopipe.Users.ListByCertificate \
    string:"$(cat card-cert.pem)" uint32:10

pamtester -v login "$USER" authenticate
```

Source: [Smart card authentication — Ubuntu Server documentation](https://ubuntu.com/server/docs/how-to/security/smart-card-authentication/)

## Group Policy: two different things

### SSSD's own logon-rights check — `ad_gpo_*`, no extra package

From `sssd-ad(5)`:

| Option | Default |
|---|---|
| `ad_gpo_access_control` | **`enforcing`** (`enforcing`, `permissive`, `disabled`) |
| `ad_gpo_implicit_deny` | `False` |
| `ad_gpo_ignore_unreadable` | `False` |
| `ad_gpo_cache_timeout` | `5` |
| `ad_gpo_default_right` | `deny` |

`ad_gpo_map_interactive` default set: `login, su, su-l, gdm-fingerprint,
gdm-password, gdm-smartcard, kdm, lightdm, lxdm, plasmalogin, sddm, unity, xdm`
— note `gdm-smartcard` is already there. Other maps: `ad_gpo_map_remote_interactive`
(`sshd, cockpit`), `ad_gpo_map_network` (`ftp, samba`), `ad_gpo_map_batch`
(`crond`), `ad_gpo_map_permit` (`polkit-1, sudo, sudo-i, systemd-user`),
`ad_gpo_map_service` and `ad_gpo_map_deny` (both empty).

Every map option takes `+service_name` to add to the default set and
`-service_name` to remove from it. `ad_gpo_map_service` and `ad_gpo_map_deny`
support `+` only.

**Conflicting documentation, and it matters.** Red Hat's RHEL 7 Windows
Integration Guide states that `permissive` is the default. Current `sssd-ad(5)`
states the default is **`enforcing`**. This project follows the current man page,
which means a freshly joined host already denies login to anyone the domain's
GPOs do not grant `InteractiveLogonRight`. That is why the tool warns when
`gpo.manage` is unset, and why the generated profile and the setup script both
default to `permissive`.

### Canonical's adsys — Ubuntu only

```bash
sudo apt install adsys
adsysctl update -m                      # refresh machine policy
adsysctl policy admx lts-only           # generate the ADMX/ADML templates for AD
adsysctl policy debug cert-autoenroll-script
```

Prerequisites: `realmd`, `sssd`, `krb5-user`, `samba-common`,
`samba-common-bin`, `adcli`, `sssd-tools`, and SSSD configured for user
authentication.

Joining AD and managing desktop settings with dconf is available to all users;
**other adsys features need an Ubuntu Pro subscription, which is free for up to
five machines.**

Certificate auto-enrolment from AD CS needs `certmonger` and `cepces` installed
on the client, and is switched on in the GPO under *Computer Configuration >
Policies > Windows Settings > Security Settings > Public Key Policies >
Certificate Services Client - Auto-Enrollment*, with the Configuration Model set
to Enabled.

Sources: [ADSys documentation](https://documentation.ubuntu.com/adsys/),
[Feature availability](https://ubuntu.com/docs/adsys/stable/reference/features/),
[Certificate auto-enrolment](https://documentation.ubuntu.com/adsys/latest/how-to/certificates-auto-enrollment/)

## The account phase: a card that authenticates can still be refused

Authentication and authorisation are separate PAM phases, and only the first
one involves the card. Measured on a joined Ubuntu 24.04 host where card login
had just been made to work:

```
pam_sss(gdm-smartcard:auth):    authentication success; user=someone@example.com
pam_sss(gdm-smartcard:account): Access denied for user someone@example.com: 4 (System error)
```

The greeter showed *"Sorry, smart card authentication didn't work."* The card
had worked. What failed was `access_provider = ad`, which `realm join` writes
and which makes SSSD evaluate the Windows logon rights through Group Policy:

```
ad_gpo_process_gpo_done: Unable to get GPO list from server ...: [14](Bad address)
ad_gpo_access_done:      GPO-based access control failed.
```

**`ad_gpo_access_control` defaults to `enforcing`**, so a GPO list that cannot
be built is a denial. On that host a single Group Policy Container was
unreadable by the machine account, which aborted the whole list:

```
ad_gpo_missing_or_unreadable_attr: Group Policy Container with DN
  [cn={...},cn=policies,cn=system,DC=...] is unreadable or has unreadable or
  missing attributes ... nTSecurityDescriptor, cn, gPCFileSysPath,
  gPCMachineExtensionNames, gPCFunctionalityVersion, flags
```

### Diagnosing it, and why the obvious test misses it

`pamtester <service> <user> authenticate` runs the **auth phase only**. It
passed on this host while every real login failed. Test both:

```bash
pamtester -v login someone@ad.example.com authenticate acct_mgmt
```

### Settling it

```yaml
gpo:
  manage: true
  access_control: permissive     # evaluate and log, never deny
```

`permissive` is the safe first move: it shows in the log what it *would* decide
without refusing anyone. It is not a destination — while it is set, the AD
logon rights are not enforced at all. Once the GPO list can be built, move to
`enforcing`. Where one container stays unreadable and its policy is not needed:

```yaml
gpo:
  manage: true
  access_control: enforcing
  ignore_unreadable: true        # ad_gpo_ignore_unreadable
```

with the cost stated plainly: a skipped GPO's settings are not applied, so if
that is the GPO carrying the logon right, the decision changes. Granting the
machine account read access on the object in AD is the clean fix.

This is checked, because the tool configures the layer above it and the
failure is attributed to the card by every greeter that reports it.

## SSH with a Smart Card: a different mechanism

A working local card login says nothing about SSH, because almost nothing is
shared. The token is on the **client**, so the server never sees a PIN and
`pam_cert_auth`, `local_auth_policy` and the PAM auth phase take no part at
all. Measured on a host where card login worked locally: `sshd -T` reported
`authorizedkeyscommand none`, and SSH with the card did not work.

What happens instead: SSSD derives an SSH public key from the X.509 certificate
in the user's directory entry, and sshd asks for it.

```bash
$ sss_ssh_authorizedkeys someone@ad.example.com
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDeKtB6x5...
```

Verified that the first key really is the card's, by decoding both sides rather
than trusting the order: the RSA modulus `de2ad07ac79fc2c32912df2b4a441ae0`
appears in the certificate read from the card.

### What carries over

More than it looks. `sss_ssh_authorizedkeys(1)` validates those certificates
with `ca_db` and `certificate_verification` and filters them through the
certmap rules — the same bundle, the same CRL and the same rule the local login
uses. **Revoking a certificate therefore removes SSH access too**, with no
separate configuration. On the measured host, 9 keys came back out of a larger
set; the rest were dropped by verification or by the rules.

The **account** phase runs as well, since sshd has `UsePAM yes` — so the GPO
section above applies to SSH exactly as it does to the console.

### What is missing by default

Only the sshd directive:

```
# /etc/ssh/sshd_config.d/60-sssd-smartcard.conf
AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys
AuthorizedKeysCommandUser nobody
```

```bash
sudo sshd -t && sudo systemctl reload ssh
```

`sshd -t` before the reload, for the same reason `sssctl config-check` runs
before SSSD is restarted: never leave a service with a file it cannot parse.

The SSH responder does **not** need adding to `services =` on Ubuntu 24.04 —
`sssd-ssh.socket` is socket-activated, and was already running on a host whose
`services` line read `nss, pam`.

### Client side

```
Host server.example.com
    PKCS11Provider /usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so
    User someone@ad.example.com
```

The PIN is requested locally by the client to use the private key; it is never
sent to the server, and the key never leaves the token.

## Logging in with the card is not holding a Kerberos identity

Measured on a host where card login, SSH and `sudo` all worked:

```
$ klist
klist: No credentials cache found (filename: /tmp/krb5cc_<uid>)
```

Both paths were observed, not inferred from one another. The same result came
from an SSH session, and separately from a local graphical session logged in
with the card — `loginctl` confirming it was the local one rather than a remote
shell:

```
SESSION 2: someone@ad.example.com   Seat: seat0   Type: wayland   Remote: no
/tmp/krb5cc_*: no such file
```

That distinction matters because the two have *different* causes, so a single
observation would not have covered both. Nothing was wrong in either case. The
two statements are independent, and which paths yield a ticket is worth knowing
before someone discovers it at the worst moment.

| Path | Authenticates with | Kerberos ticket |
|---|---|---|
| console or greeter, card | SSSD, **locally** (`local_auth_policy = enable:smartcard`) | **no** |
| SSH, key derived from the certificate | sshd, public key | **no** |
| any path, password | `pam_sss` -> SSSD's Kerberos auth provider | **yes** |
| card + PKINIT | `krb5-pkinit` with `pkinit_anchors` | yes |

Two separate reasons, neither of them a fault:

* **`local_auth_policy = enable:smartcard` is local authentication.** SSSD
  verifies the certificate against the CA bundle and the certmap rule and never
  contacts the KDC, so there is nothing to put in a cache. A ticket needs
  PKINIT, which needs the MIT plugin -- without `krb5-pkinit` installed, no
  amount of configuration produces one.
* **SSH public-key authentication skips the PAM `auth` stack altogether.**
  `pam_sss` never runs, so nothing obtains credentials. This is true however
  the key was derived.

A password login does obtain a ticket, which is usually what someone has
already seen when they report that tickets "sometimes" appear.

`doctor` reports both as INFO. They are consequences of the chosen mechanisms,
not misconfiguration, and flagging them as problems would be wrong.

### If a session genuinely needs a ticket

For the console: install `krb5-pkinit`, set `pkinit_anchors`, and add the
`includedir` line so SSSD's own snippets are not inert. `krb5 test --from-card
--pkinit` confirms it, and confirms it by the preauth type in `KRB5_TRACE`
rather than by `kinit` returning zero -- a TGT obtained with a password looks
identical from the outside.

For SSH: `GSSAPIAuthentication` with credential delegation. Note what that
means -- delegation forwards a ticket the **client already holds**, so the
client must have obtained one first, which on a Windows workstation means being
domain-joined and signing in with the card. Measured on one that was not: zero
cached tickets, nothing to delegate. The authentication is then Kerberos rather
than the card; the card's part happens one step earlier, at the Windows logon.

## CRL revocation: four measured rules

Where there is no OCSP responder, CRLs are the only revocation mechanism. SSSD
reads one local PEM file (`crl_file=`) and **never downloads or refreshes it**.
Four behaviours decide whether a CRL configuration works, and none of them is
in `sssd.conf(5)`. All were measured with `p11_child --verification
--verify=...` on SSSD 2.9.4 against a two-tier PKI with a real PIV card.

| `--verify` | Result | Reason |
|---|---|---|
| *(no CRL)* | pass | baseline |
| `crl_file=`*issuing CA CRL* | **FAIL** | `[3][unable to get certificate CRL]` |
| `crl_file=`*root CA CRL* | **FAIL** | same |
| `crl_file=`*both, concatenated* | **pass** | |
| `crl_file=`*both, reversed* | pass | order is irrelevant |
| `soft_crl,crl_file=`*issuing only* | **FAIL** | forgives expiry, not absence |
| `ocsp_dgst=sha256,crl_file=`*issuing only* | **FAIL** | OCSP does not relax it |
| `partial_chain,crl_file=`*both* | **FAIL** | incompatible with `crl_file` |

**1. Every CA in the chain needs a current CRL.** Not just the CA that issued
the card's certificate — which is the intuitive choice, since that is the list
naming revoked *user* certificates. One CRL short and OpenSSL returns
`X509_V_ERR_UNABLE_TO_GET_CRL` (`X509_V_FLAG_CRL_CHECK_ALL`). Because
`crl_file` fails closed, the result is that **nobody can log in at all**.

**2. Several CRLs concatenated into one PEM file work**, in any order. The man
page says only "The CRL must be given in PEM format"; this is the shape a
multi-tier PKI needs.

**3. `soft_crl` forgives an expired CRL, never a missing one.** It is no safety
net against an incomplete set.

**4. `partial_chain` and `crl_file` cannot be combined.** A complete, valid CRL
set that verifies cleanly starts failing with `unable to get certificate CRL`
the moment `partial_chain` is added. The tool drops `partial_chain` and says so
rather than emitting a combination that rejects every card.

### Measured on a live login: the file is load-bearing, and a loss degrades silently

The four rules above come from `p11_child --verification`, which asks the
question directly. The question they do *not* answer is whether a login
actually consults the file, because a successful login with a certificate that
is not revoked looks identical whether the CRL was checked or ignored.

Measured by removing the file from a working configuration (SSSD 2.9.4,
Ubuntu 24.04, real PIV card, `sss-smart-card-optional`):

| CRL file | Prompt | Result |
|---|---|---|
| present | `PIN for <name>:` | authenticated by card |
| **absent** | `Password:` | card path refused, password accepted |
| restored | `PIN for <name>:` | authenticated by card |

`p11_child.log` names the mechanism, and it is not "verified and rejected" —
verification never starts:

```
[init_verification] X509_load_crl_file for [/etc/sssd/pki/revocation.crl.pem]
    failed [error:80000002:system library::No such file or directory]
[do_work] init_verification failed.
[main] p11_child failed (5)
```

The same log confirms the generated `certificate_verification` string is parsed
rather than merely accepted: `parse_cert_verify_opts: Found 'no_ocsp' option,
disabling OCSP`.

Note what this does and does not establish. It proves `crl_file` is
load-bearing: the file is opened on every authentication and the card is
refused when it cannot be read. It does **not** prove that a revoked serial is
rejected — that rests on OpenSSL's `X509_V_FLAG_CRL_CHECK_ALL` once the list
loads, and the only direct test is to revoke a certificate and re-run.

**The operational consequence is the part worth remembering.** The failure
lands differently depending on one PAM choice:

* `sss-smart-card-optional` — the card is refused and the password prompt
  takes over. No error reaches the user, and from the outside it looks like
  "people are being asked for passwords again", not like a broken revocation
  check. A Smart Card deployment quietly stops being one.
* `sss-smart-card-required` — `pam_sss.so require_cert_auth` has no fallback,
  so the same condition locks out **every** user at once.

Since SSSD never refreshes the file itself, an expired CRL produces exactly
this on a schedule the CA sets: the lab's issuing CA publishes a list valid for
about eight days. `sssd-smartcard ca crl timer --install` is therefore part of
the configuration, not an optimisation, and the unit deliberately fails loudly
rather than replacing a working file with an incomplete set.

### "OCSP at the issuing CA, CRL at the root" is not expressible

A reasonable plan where the subca has a responder and the root only publishes a
CRL. It does not work through `certificate_verification`: rule 1 is unaffected
by OCSP being enabled, so **as soon as `crl_file` is set, every CA in the chain
still needs its own CRL**, `ocsp_dgst` and `soft_ocsp` notwithstanding. The
choices are therefore:

* OCSP alone, with **no** `crl_file` — the card's certificate is checked against
  the responder; the root's revocation is not checked, which in practice is
  handled by removing a repudiated root from the trust bundle;
* or supply a CRL for every CA, and use OCSP in addition if you want it.

### Finding the CRLs

A certificate's `crlDistributionPoints` names the CRL that would revoke **that
certificate** — the one published by its *issuer*. So:

| CRL needed | Advertised by |
|---|---|
| issuing CA's CRL (revokes user certificates) | the **card's** certificate |
| root CA's CRL (revokes the issuing CA cert) | the **issuing CA's** certificate |
| a self-signed root's own CRL | nothing — no pointer exists |

Reading each CA's own CDP therefore finds the root's CRL twice and the issuing
CA's never. `sssd-smartcard ca crl update --from-card` walks the chain the right
way, records the URL it used for each CA in
`/var/lib/sssd-smartcard/crl-sources.json`, and refuses to install an
incomplete set.

### Reading a concatenated CRL file

`openssl crl -in <file>` parses only the **first** CRL in the file and silently
ignores the rest, so on a combined file it reports the first CA's entries and
nothing else -- easily mistaken for "no certificates are revoked". Either split
the file first, or use:

```bash
sudo sssd-smartcard ca crl show
```

which lists every CRL in it with its issuer, dates and entry count.

### Keeping it fresh

An expired CRL is a total outage under rule 1 + fail-closed. The issuing CA in
the lab republishes weekly, so:

```bash
sudo sssd-smartcard ca crl update --from-card   # once, to learn the URLs
sudo sssd-smartcard ca crl timer --install      # daily refresh thereafter
```

The timer unit carries `Persistent=true` deliberately: a host that was switched
off past `nextUpdate` must refresh at boot rather than wait for the next tick,
because by then every card login is already failing. The service runs the same
`ca crl update`, which refuses to install an incomplete or expired set — so a
failed refresh leaves the previous working CRL in place and shows up in
`systemctl status`, instead of replacing a good file with one that locks
everyone out.

Sources: `sssd.conf(5)` -> `certificate_verification` (`crl_file`: "The CRL must
be given in PEM format, see crl(1ssl) for details"; `soft_crl`: "If a
Certificate Revocation List (CRL) is expired ignore the expiration time of the
CRL"). Rules 1-4 and the discovery table are measured, as above.

## Alternative UPN suffixes: a UPN suffix is not a domain

A certificate whose UPN suffix differs from the domain the host is joined to
means one of two unrelated things, and they want opposite configurations.

| | Trusted domain | Alternative UPN suffix |
|---|---|---|
| Where the accounts are | another SSSD domain | **this** domain |
| `domains=` | names that domain | **must be absent** |
| UPN suffix in `matchrule` | pin it | do not pin it |
| How to tell | the suffix **is** a domain `sssctl domain-list` shows | it is not |

Active Directory lets a forest publish several UPN suffixes, and aligning the
AD UPN with the Entra ID one is the usual reason: users log in as
`someone@example.com` while the domain is `ad.example.com`. The suffix is then
a label on the account, not a domain — nothing resolves it, and SSSD has never
heard of it.

Two things go wrong if it is mistaken for a trusted domain:

* `domains = example.com` points SSSD at a domain it does not have. Measured:
  `sssctl domain-status example.com` answers *Unable to get online status*,
  while `sssctl domain-list` shows only `ad.example.com`.
* `<SAN:ntPrincipalName>.*@example\.com$` pins **one** suffix. A forest can
  have several, so a card issued under any other silently fails to match, SSSD
  falls back to its default mapping, and login drops to the password prompt —
  the same symptom as a broken rule, from a working one.

### What the tool emits

It asks whether the suffix is a domain SSSD knows, and generates accordingly.
For the alternative-suffix case:

```ini
[certmap/ad.example.com/EXAMPLE-UPN]
matchrule = KRB5:<ISSUER>^CN=Example Sub CA,DC=ad,DC=example,DC=com$<EKU>clientAuth,msScLogin<SAN:ntPrincipalName>.*
maprule = LDAP:(|(userPrincipalName={subject_nt_principal})(sAMAccountName={subject_nt_principal.short_name}))
```

No `domains=`, so the search stays in the rule's own domain, which is where the
accounts are. No suffix anchor, so **every** suffix the CA issues for is
accepted — one rule for all of them.

Dropping the suffix anchor costs nothing that matters. The trust is carried by
the anchored `<ISSUER>` and the required `<EKU>`: only certificates from that
CA, issued for Smart Card logon, reach the map rule at all. And the map rule
looks the account up **by the exact UPN on the card**, so a certificate whose
UPN belongs to no account resolves to nobody.

Listing several suffixes in one rule is not an option: components joined with
`||` leave the literal operator in the preceding component's value — measured,
see the matching-rule section above.

### Kerberos confirms the same thing, independently

`kinit` treats whatever follows the `@` as a **realm**, so a UPN suffix fails
outright:

```
$ kinit someone@example.com
kinit: Cannot find KDC for realm "example.com" while getting initial credentials
```

while the real domain resolves and prompts. That is the distinction in one
command, from a tool that knows nothing about this project's certmap rule: the
suffix is a label on the account, and nothing resolves it.

To authenticate *by* the UPN rather than by `user@REALM`, Kerberos has a
separate mode -- the enterprise principal:

```bash
kinit -E someone@example.com
```

`-E` says the name is an enterprise principal, and the client works the realm
out itself. `sssd-smartcard krb5 test --enterprise` passes the same flag.

### Verifying it

```bash
sudo sssd-smartcard mapping test <profile> --from-card
```

```
MATCH
  Decided by:            sssctl
  LDAP filter:           (|(userPrincipalName=someone@example.com)(sAMAccountName=someone))
[PASS] getent passwd  someone@ad.example.com:*:827801106:827800513:...
[PASS] sssctl user-checks  user: someone@example.com
```

The filter carries the UPN from the card; the account it finds is in the joined
domain. Those two lines being different is the whole point, and seeing them
agree is what confirms the configuration.

### Overriding it

The decision needs `sssctl domain-list` to answer, so on a host that cannot
reach its domain the tool keeps the trusted-domain reading rather than guessing
the narrower one. To state it yourself, in the profile:

```yaml
mapping:
  type: san-upn
  options:
    any_suffix: true          # accept every UPN suffix
    # or pin exactly one:
    # upn_suffix: example.com
  domains: [other.example.com]   # only for a real trusted domain
```

## PKINIT: what the KDC must present, and what MIT demands

Smart Card login and a Kerberos ticket are different mechanisms. Login is local
(`p11_child` plus `local_auth_policy`); a TGT needs PKINIT, where the KDC also
has to prove itself to the client. Three client-side things are required, and
all three were missing on a host where card login already worked:

| Requirement | Symptom when absent |
|---|---|
| `krb5-pkinit` package (`pkinit.so`) | kinit **silently ignores** `-X X509_user_identity`, prompts `Password for <principal>` and returns a valid TGT from the password |
| `pkinit_anchors` | the client cannot validate the KDC certificate |
| EKU/SAN relaxation (below) | PIN prompt, then a password prompt — PKINIT engaged, rejected the KDC, fell back |

### The false-success trap

Without `pkinit.so` the chain is: `-X` ignored → password prompt → correct
password → real `krbtgt` in the cache → *everything looks like success*.
Measured:

```
Error loading plugin module pkinit: 2/unable to load plugin
  [/usr/lib/x86_64-linux-gnu/krb5/plugins/preauth/pkinit.so]: cannot open shared object file
Processing preauth types: PA-PK-AS-REQ (16), PA-PK-AS-REP_OLD (15), PA-ETYPE-INFO2 (19), PA-ENC-TIMESTAMP (2)
Preauth module encrypted_timestamp (2) (real) returned: 0/Success
```

So a PKINIT verdict may never rest on "exit status 0 and a ticket exists". The
tool runs kinit with `KRB5_TRACE` pointed at a file (the terminal stays free for
the PIN prompt) and requires the trace to show a `pkinit` module returning
`0/Success`. It also refuses to run kinit at all when the plugin is missing,
rather than prompting for a password during what is advertised as a card test.

### KDC certificate requirements

RFC 4556 §3.2.4 wants the KDC certificate to carry the `id-pkinit-KPKdc` EKU
(1.3.6.1.5.2.3.5) and an `id-pkinit-san` otherName (1.3.6.1.5.2.2) naming
`krbtgt/REALM@REALM`.

Microsoft's older **Domain Controller** template issues neither. Measured on the
lab DC:

```
X509v3 Extended Key Usage: TLS Web Client Authentication, TLS Web Server Authentication
X509v3 Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1, DNS:DC01.ad.example.com
```

Windows clients accept that for backwards compatibility. MIT does not, because:

| Option | Default | Documented meaning |
|---|---|---|
| `pkinit_eku_checking` | `kpKDC` | "the KDC must have the id-pkinit-KPKdc EKU as defined in RFC 4556" |
| `pkinit_kdc_hostname` | unset | its presence accepts "a KDC certificate with a dNSName SAN rather than requiring the id-pkinit-san" |

Two ways out. Reissue the DC certificate from a **Kerberos Authentication**
template (the correct fix), or tell the client to accept the one it has:

```ini
[libdefaults]
    pkinit_eku_checking = kpServerAuth
    pkinit_kdc_hostname = DC01.ad.example.com
    pkinit_anchors = FILE:/etc/sssd/pki/sssd_auth_ca_db.pem
```

`pkinit_kdc_hostname` must match the `dNSName` in the certificate. With these,
PKINIT succeeded on the lab host and the trace confirmed `PA-PK-AS-REQ`.

`sssd-smartcard krb5 test --pkinit` reads the DC's certificate over LDAPS (port
636 presents the same certificate the KDC uses, on both Samba and Windows) and
names the options required, instead of leaving them to be deduced from a
password prompt:

```
[WARN] KDC certificate PKINIT suitability  lacks id-pkinit-KPKdc EKU (1.3.6.1.5.2.3.5)
       and id-pkinit-san otherName (1.3.6.1.5.2.2); EKU is clientAuth, serverAuth
[INFO] needs pkinit_eku_checking  kpServerAuth
[INFO] needs pkinit_kdc_hostname  DC01.ad.example.com
```

### `includedir`

SSSD writes `domain_realm_*`, `krb5_libdefaults` and `localauth_plugin` into
`/var/lib/sss/pubconf/krb5.include.d/`. They do nothing unless krb5.conf
includes that directory, and a realm-joined host can lack the line entirely —
the realm comes from `default_realm` and the KDC from DNS, so nothing visibly
breaks:

```ini
includedir /var/lib/sss/pubconf/krb5.include.d/
```

Sources: RFC 4556;
[krb5.conf(5)](https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html)
-> `pkinit_eku_checking`, `pkinit_kdc_hostname`, `pkinit_anchors`.

## Smart card authentication without PKINIT

SSSD's Smart Card authentication authenticates **against the local system**:
`p11_child` verifies the certificate against the CA bundle and checks the PIN by
having the token sign with the private key. PKINIT is what additionally obtains a
Kerberos TGT.

So a card login can succeed while the user has no ticket at all — which is why
`sssd-smartcard krb5 status` and `krb5 test --pkinit` are separate from the rest
of the verification. Local authentication is also what `local_auth_policy =
enable:smartcard` switches on, so enabling it is what makes the card usable for
login, and also what guarantees the session starts without a TGT.

Source: [Smartcard authentication - Step 1 (local authentication)](https://sssd.io/design-pages/smartcard_authentication_step1.html),
[Smartcard Authentication - PKINIT](https://sssd.io/design-pages/smartcard_authentication_pkinit.html)

## Testing without a card: SoftHSM2

`p11_child` finds PKCS#11 modules through p11-kit, and SoftHSM2 registers
`libsofthsm2.so` like any other driver, so an emulated token works end to end.
On Ubuntu the module is at
`/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so`. This is what the `lab/`
environment uses.

## AD provider and certificates

The AD provider does not read certificates by default. A `certificate-binary`
mapping additionally needs, in the domain section:

```ini
ldap_user_certificate = userCertificate;binary
```

Source: [Smartcard authentication - testing with AD](https://sssd.io/design-pages/smartcard_authentication_testing_with_ad.html),
which also documents the pre-authentication marker
`/var/lib/sss/pubconf/pam_preauth_available`.

## Verifying a rule on the host

```bash
CERT=$(openssl x509 -in /path/to/certificate -outform der | base64 -w0)
sssctl cert-eval-rule "$CERT" \
  --match='<ISSUER>CN=adcs19-WIN1-CA,DC=AD,DC=EXAMPLE,DC=COM' \
  --map='LDAPU1:(altSecurityIdentities=X509:<I>{issuer_dn!ad_x500}<SR>{serial_number!hex_ur})'
```

Source: [Configuring certificate mapping rules in IdM (RHEL 9)](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/managing_certificates_in_idm/conf-certmap-idm_managing-certificates-in-idm)

## PKINIT from the command line

```bash
kinit -X X509_user_identity='PKCS11:opensc-pkcs11.so' ad_user@AD.DOMAIN.COM
klist
```

`X509_anchors=FILE:<pem>` points the PKINIT plugin at the CA that must validate
the KDC's own certificate.

Source: [Authenticating as an AD user using PKINIT with a smart card (RHEL 9)](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/managing_smart_card_authentication/authenticating-as-an-active-directory-user-using-pkinit-with-a-smart-card_managing-smart-card-authentication)

## Certificate extensions the inspector decodes by hand

`cryptography` exposes these only as raw DER, so `x509/der.py` decodes them:

| OID | Meaning | Encoding |
|---|---|---|
| `1.3.6.1.4.1.311.20.2.3` | Microsoft UPN (`otherName`) | `UTF8String` |
| `1.3.6.1.5.2.2` | Kerberos `KRB5PrincipalName` (PKINIT `otherName`) | `SEQUENCE` |
| `1.3.6.1.4.1.311.25.2` | AD SID security extension (KB5014754) | `GeneralNames` holding an `otherName` `1.3.6.1.4.1.311.25.2.1` with the SID as an `OCTET STRING` |
| `1.3.6.1.4.1.311.20.2.2` | Microsoft Smart Card Logon EKU | -- |
