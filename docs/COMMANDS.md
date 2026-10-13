# Command reference

Five programs. One reads and writes configuration (`sssd-smartcard`); four
prepare, reset, install and set up a machine.

| Program | Purpose |
|---|---|
| `sssd-smartcard` | inspect certificates, generate and apply configuration, diagnose |
| `ad-prepare` | DNS and hostname, before a join |
| `ad-reset` | remove one domain so the machine can be reused |
| `sssd-smartcard-install-desktop` | minimal desktop for greeter testing |
| `sssd-smartcard-setup` | guided end-to-end setup, in stages |

Flags shared by every `sssd-smartcard` subcommand: `--json`, `--no-color`,
`--sssd-version X.Y.Z`, `--config PATH`. They work before or after the
subcommand.

Anything that writes defaults to **showing** rather than doing. `--dry-run` is
the default where one exists; `--yes` applies.

---

## `sssd-smartcard`

### Reading a certificate

Most subcommands that need a certificate accept the same source flags:
`--from-card`, `--file PATH`, `--base64 B64`, `--stdin`, plus `--module`,
`--slot` and `--cert-id` to pick a particular PKCS#11 object.

```
cert inspect [source] [--domain D] [--sssd-domain D] [--provider ad|ldap|ipa]
             [--mapping KEY] [--profile-name N] [--save-profile PATH]
             [--ca-bundle PATH] [--no-pin-issuer] [--no-pin-eku]
             [--with-revocation] [--require-smartcard] [--no-config]
```

Decodes the certificate, ranks the mapping mechanisms it can support, and
prints the profile and `sssd.conf` section that follow from it. The `Domain:`
line is worth reading: it is taken from the SAN UPN suffix, and when it differs
from the domain the host is joined to, the accounts live in a trusted domain.

`cert autoconfig` is the same thing with the profile written out —
`--save-profile` names the file, and the profile's name comes from its stem, so
the `[certmap/...]` section is named after the file.

### The card

```
card detect [--module M] [--slot S] [--no-read]
```

Readers, tokens, modules and the certificates on them. **Needs `sudo`:**
`pcsc-lite` authorises through polkit (`allow_any=no`, `allow_inactive=no`), so
an unprivileged SSH session has no seat and is denied — and the error reads
like a missing reader.

### Mapping

```
mapping types
mapping test <profile> [source] [--no-sssctl] [--no-lookup]
```

`mapping test` evaluates the rule two ways: locally against the decoded
certificate, and through `sssctl cert-eval-rule` where available. It reports
which decided the verdict. `--no-lookup` skips resolving the mapped user.

### CA trust and revocation

```
ca show [FILE...] [--bundle PATH]
ca import FILE... [--bundle PATH] [--dry-run] [--backup-dir D]
```

`ca show` prints subject, issuer, serial, SHA-256, validity and basic
constraints. `ca import` merges certificates into the trust bundle, never
overwriting it without a backup.

```
ca discover [source] [--pki-url URL] [--bundle PATH] [--install]
            [--no-probe] [--timeout S] [--backup-dir D]
```

Works the PKI out from one certificate and fetches it: follows AIA `caIssuers`
up to a self-signed root, collects the CRL distribution points of the leaf and
every CA, and sends a **real OCSP request** to find out whether a responder
answers. Handles PEM, DER and PKCS#7, since AD CS serves all three.

**With no certificate, `--pki-url` alone lists the PKI.** The directory is
read and every certificate and CRL in it is fetched and reported: which CAs,
their fingerprints and validity, whether the chain closes, and whether the CRLs
are current. That answers "what is this PKI" before anyone has a card from it.
Only same-host links are followed, and only a bounded number; the common AD CS
paths (`PKI/`, `CertEnroll/`, `certdata/`) are tried when the URL given has no
listing, and a host with listings disabled is reported rather than guessed at.

With a certificate, `--pki-url` is a fallback for an AIA that is missing or
LDAP-only; the issuer's CN is then tried as a filename under it. `--install`
writes the trust bundle and, in certificate mode, the CRLs. `--no-probe`
reports the advertised OCSP URL without contacting it.

Two distinctions it keeps, because each decides the configuration:

* **Downloaded is not trusted.** The chain is a proposal — anyone able to answer
  the AIA URL could otherwise install themselves as a CA whose certificates log
  in. Fingerprints are printed for out-of-band comparison, and again at the
  moment of import.
* **Advertised is not working.** SSSD fails closed on OCSP, so enabling it
  against a silent responder stops every card login. `crl` is recommended when
  the responder does not answer, and the reason distinguishes *no responder
  advertised* from *the advertised responder did not answer*.

```
ca crl show [FILE] [--bundle PATH]
ca crl update [--bundle PATH] [--crl-file PATH] [--from-file F]... [--no-fetch]
              [source] [--dry-run] [--force] [--backup-dir D]
ca crl timer [--bundle PATH] [--crl-file PATH] [--on-calendar EXPR]
             [--install] [--backup-dir D]
```

`crl_file` needs **one current CRL per CA in the chain**, concatenated into one
PEM. One short and verification fails with `unable to get certificate CRL` for
every card, because it fails closed. `ca crl update` builds that set and
refuses to install an incomplete or expired one.

Run it once with the card (`--from-card`): a CA's CRL URL is advertised by the
certificates it *signed*, not by its own certificate, so the issuing CA's CRL
is only discoverable from an end-entity certificate. The URL is then remembered
in `/var/lib/sssd-smartcard/crl-sources.json` so the timer can refresh with no
card present.

`ca crl show` lists every CRL in the file. Use it rather than `openssl crl
-in`, which parses only the **first** CRL in a concatenated file and silently
ignores the rest — easily mistaken for "nothing is revoked".

### Profiles

```
profile list
profile show <name>
profile validate <name>
```

Administrator profiles in `/etc/sssd-smartcard/profiles` are searched before
the examples in `/usr/share/sssd-smartcard/profiles`.

### Configuration

```
config render <profile> [--verification-scope sssd|pam] [--allow-degraded]
              [--no-comments]
config diff <profile> [--skip-ca]
config validate <profile> [--skip-ca]
config apply <profile> [--dry-run] [--yes] [--no-restart] [--no-validate]
             [--backup-dir D] [--force]
```

`config apply` backs up before writing, writes `sssd.conf` atomically at mode
0600, requires `sssctl config-check` to pass before restarting SSSD, and rolls
every touched file back on any failure. `--allow-degraded` turns "this SSSD is
too old for that option" into a warning instead of a refusal.

### Domains and Kerberos

```
domain list [DOMAIN] [--user U]
domain test [DOMAIN] [--user U]
krb5 status [--cache SPEC]
krb5 test [source] [--realm R] [--principal P] [--pkinit] [--anchors PATH]
          [--enterprise] [--keep-cache]
```

`krb5 test --pkinit` obtains a real ticket into a throwaway cache, so your own
is untouched. Its verdict requires `KRB5_TRACE` to show a `pkinit` preauth
module succeeding — a ticket alone is not proof, because without the
`krb5-pkinit` plugin `kinit` ignores `-X X509_user_identity`, asks for the
account password and returns a perfectly valid TGT. It refuses to run at all
when the plugin is missing, rather than collecting a password during a card
test.

`krb5 status` under `sudo` reads root's cache and will report no ticket even
when the user has one. Run it in the user's session.

### Diagnosis

```
pam check
doctor [--user U] [--no-domains] [--no-card] [--no-krb5]
```

`doctor --user <someone>` is the one command worth remembering. It covers every
layer: SSSD and its version, the certificate, the mapping, the CA bundle, PAM,
`local_auth_policy`, the home directory, Kerberos, the CRL and its refresh
timer.

---

## `ad-prepare`

```
ad-prepare [--env FILE] [--init-env] [--domain D] [--dns IP[,IP]]
           [--search D[,D]] [--hostname N] [--iface IF]
           [--check] [--dry-run] [--yes] [--apply-now] [--no-verify]
           [--rollback DIR] [--log FILE]
```

DNS and hostname, before a join. `--check` diagnoses and changes nothing.

`--init-env --domain <domain>` writes the environment file and fills in what it
can work out: the domain controllers from the `_ldap._tcp` SRV records (falling
back to `NS`, then the domain's `A` records), the realm and search domain from
the domain, the hostname from the machine, and the role from whether a display
manager is running. `--dns` overrides the discovery. Discovery needs a resolver
that can already see the zone; when it finds nothing it says so and leaves the
example value rather than writing a guess.

The template's own example values are refused if applied unedited — but only
for the fields the running script acts on, so `ad-prepare` does not object to
CA paths it never reads.

It **does not bounce the interface**: the resolver is applied with `resolvectl`,
which takes effect immediately without dropping the SSH session running the
script, and persistence lands for the next boot. `--apply-now` accepts the
bounce. A netplan file is validated with `netplan generate` before the run is
called a success.

Verification proves what a join needs: each configured server answers for the
AD zone (reachable is not authoritative), the `_ldap._tcp` and `_kerberos._tcp`
records resolve, the DC accepts 88, 389, 445 and 464, the clock is synchronised,
and the host's own FQDN resolves.

---

## `ad-reset`

```
ad-reset [--env FILE] [--domain D] [--check] [--dry-run] [--yes]
         [--local-only] [--remove-homes] [--keep-backups] [--log FILE]
```

Removes every trace of one domain so the machine can be reused. Reusing one
without this leaves traces in thirteen places, and the ones that mislead are
not obvious: the SSSD cache keeps answering for the old domain's users, the
keytab holds the old host principal, `krb5.conf` still names the old realm and
KDC, and the certmap rule still pins the old issuer DN — so a certificate from
a new PKI silently fails to match and login falls through to a password.

`realm leave` runs first, while the old DC is still reachable, so the machine
account is deleted rather than orphaned. SSSD is stopped before its caches go.
`--check` reports what remains, and the same report runs after a removal, so
"it is gone" is a finding and not an assumption.

Deliberately left alone: PAM, local accounts, SSH, sudo, DNS and the hostname.
DNS and the hostname belong to the next domain.

`--remove-homes` also deletes `/home/<user>@<domain>`; off by default because
that is user data. `--local-only` skips the leave when the old DC is gone, and
the machine account then stays in AD to be deleted by hand.

---

## `sssd-smartcard-install-desktop`

```
sssd-smartcard-install-desktop [--env FILE] [--package NAME] [--yes]
                               [--dry-run] [--status] [--no-follow]
                               [--force-role] [--reboot] [--log FILE]
```

Installs **the desktop and the SSH server, and nothing else**. SSSD and the
Smart Card packages come from `sssd-smartcard-setup --only packages`, where
they are version checked. `openssh-server` is included deliberately: a machine
that has just gained a graphical login but lost remote access needs a console
to fix.

The install runs **detached under systemd**, because a ten-minute apt
transaction interrupted by a dropped SSH session leaves dpkg to be untangled by
hand. `--status` attaches to one in flight; re-running does the same rather
than starting a second apt.

It refuses to run when the environment file says `role: server`;
`--force-role` overrides. The refusal comes *after* preflight and the network
stage, so a machine that needs the clean-up below still gets it.

**A warning from a real failure.** Earlier versions marked the SSH interface
unmanaged in NetworkManager, meaning to stop it claiming the link mid-install.
That setting survives a reboot — and so does the desktop install's switch of
netplan's renderer *to* NetworkManager. Together, nothing configured the
interface and the machine came back with **no address at all**. The guard was
unnecessary too: a server rendered by systemd-networkd is not claimed by
NetworkManager anyway. It is gone, `--no-protect-iface` is accepted and
ignored, and the script now removes the file where an earlier run left it.
Nothing here changes network configuration.

Keep console access when you reboot a remote machine after this, and check the
address first:

```bash
ip -4 addr show <iface> && nmcli device status
```

---

## `sssd-smartcard-setup`

```
sssd-smartcard-setup [--env FILE] [--realm R] [--join-user U] [--test-user UPN]
                     [--ca FILE]... [--sssd-domain D] [--account-domain D]
                     [--gpo] [--adsys] [--cert-autoenroll] [--pam]
                     [--only STAGES] [--skip STAGES] [--no-verify]
                     [--check] [--dry-run] [--yes] [--force]
```

Reads the environment file for the realm, join user, test user, SSSD and
account domains, CA paths and the GPO and Smart Card switches, so with one
written the usual invocation carries no arguments but the stage selection:

```bash
sudo sssd-smartcard-setup --only packages,join,identity --yes
```

A flag always overrides the file, and a file still holding the template's
example values is refused rather than used — but only for the fields this
script acts on.

Nine stages: `preflight, packages, join, identity, ca, card, certmap, gpo, pam`,
then verification. `--only` and `--skip` take comma-separated stage names, so
joining and nothing else is:

```bash
sudo sssd-smartcard-setup --only packages,join,identity \
     --realm AD.EXAMPLE.COM --join-user administrator \
     --test-user someone@ad.example.com --yes
```

The `identity` stage is a hard gate: it refuses to continue until the test user
resolves by name. Smart Card authentication cannot work before plain identity
lookup does, and a broken trust otherwise gets misdiagnosed as a certificate
problem.

PAM is only ever **reported on** unless `--pam` is given, because a bad PAM file
locks the administrator out of the machine.

---

## The environment file

`/etc/sssd-smartcard/environment.json`, read by `ad-prepare`, `ad-reset` and
the desktop installer. `ad-prepare --init-env` writes a template. A flag on the
command line always overrides it, and `--env FILE` reads a different one.

```json
{
  "domain": "ad.example.com",
  "dns": ["10.0.0.10"],
  "hostname": "wks-server",
  "role": "server",
  "join_user": "administrator",
  "test_user": "someone@ad.example.com",
  "ca": ["/root/pki/root-ca.pem", "/root/pki/issuing-ca.pem"],
  "crl": true,
  "notes": "second test PKI"
}
```

Accepted keys: `domain`, `realm`, `hostname`, `role`, `join_user`, `test_user`,
`account_domain`, `sssd_domain`, `desktop_package`, `crl_file`, `notes`,
`dns`, `search`, `ca`, `desktop`, `gpo`, `adsys`, `crl`, `ocsp`,
`smartcard_required`.

An unknown key is an **error**, not a warning: a typo that is silently dropped
leaves you believing a setting took effect. `realm` is derived from `domain`
upper-cased when omitted. A file still holding the template's example values is
refused, so an unedited template cannot set your DNS to `10.0.0.10`.

---

## Where things live

| Path | What |
|---|---|
| `/etc/sssd/sssd.conf` | the configuration, mode 0600 |
| `/etc/sssd/pki/sssd_auth_ca_db.pem` | CA trust bundle — the trust decision |
| `/etc/sssd/pki/revocation.crl.pem` | combined CRL, one per CA in the chain |
| `/etc/sssd-smartcard/profiles/` | administrator profiles, searched first |
| `/etc/sssd-smartcard/environment.json` | the environment definition |
| `/usr/share/sssd-smartcard/profiles/` | example profiles |
| `/var/lib/sssd-smartcard/backups/` | every change, newest last |
| `/var/lib/sssd-smartcard/crl-sources.json` | remembered CRL URLs per CA |
| `/usr/share/doc/sssd-smartcard/` | this and the other documents |

---

## Further reading

* [DEPLOY.md](../DEPLOY.md) — copy-paste deployment, and a clean machine from
  nothing to a card login, including the two-machine layout
* [HOW-IT-WORKS.md](HOW-IT-WORKS.md) — the mechanism as it actually runs, and
  the failure modes encountered
* [sssd-reference.md](sssd-reference.md) — every emitted option with its source,
  and the measured findings behind the non-obvious ones
