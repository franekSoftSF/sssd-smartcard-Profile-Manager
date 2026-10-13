# Deploying to a test machine

Copy-paste reference. Replace `sysadmin@10.0.0.50` with the target and
`ad.example.com` / `10.0.0.10` with the domain and its DNS server.

Releases, with the `.deb`, the tarball and their checksums:
[github.com/franekSoftSF/sssd-smartcard-Profile-Manager/releases](https://github.com/franekSoftSF/sssd-smartcard-Profile-Manager/releases)

## 1. Get the package onto the machine

Two ways. The first needs nothing but outbound HTTPS from the target, which is
usually the shorter path.

### From the release

Run this **on the machine being set up**:

```bash
VER=0.2.2
REPO=https://github.com/franekSoftSF/sssd-smartcard-Profile-Manager/releases/download/v$VER
curl -sSfLO "$REPO/sssd-smartcard_${VER}_all.deb"
curl -sSfLO "$REPO/sssd-smartcard_${VER}_all.deb.sha256"
sha256sum -c "sssd-smartcard_${VER}_all.deb.sha256"
```

```
sssd-smartcard_0.2.2_all.deb: OK
```

That `OK` is the whole point of shipping the checksum beside the file. A
truncated download fails later, during `dpkg`, in ways that read like a broken
package rather than a broken transfer.

The `-f` in `curl -sSfL` matters as much. Without it, a wrong URL leaves you
with the server's error body in the file and an exit status of zero — measured
against this release, a 9-byte file reading `Not Found`:

```
$ curl -sSLO ".../does-not-exist.deb"   # no -f
$ ls -l does-not-exist.deb              # 9 bytes
$ head -c 60 does-not-exist.deb         # Not Found

$ curl -sSfLO ".../does-not-exist.deb"  # with -f
curl: (22) The requested URL returned error: 404
                                        # nothing written
```

A note on why there is no table of hashes here: this document ships *inside*
the package, so any checksum printed in it would be the checksum of a different
build than the one carrying it. The authoritative value is the `.sha256` file
published beside each asset, which is what `sha256sum -c` above checks. To
verify out of band, compare against the release page rather than against a
document the package contains.

There is a second reason. The build is not currently reproducible: two builds
of identical source produce different `.deb` checksums, because `dpkg-deb`
records file modification times. So a checksum identifies one published
artefact, not the source it was built from — which is exactly what you want
when checking a download, and useless for checking that two builds agree.

### From the machine that built it

For a target with no outbound HTTP, or when testing a build that is not
released yet:

```bash
scp dist/sssd-smartcard_0.2.2_all.deb sysadmin@10.0.0.50:/tmp/
```

If `scp` refuses because the host key changed — a rebuilt VM on a reused
address — remove the stale key rather than turning checking off:

```bash
ssh-keygen -R 10.0.0.50
```

Then confirm the file survived the copy:

```bash
sha256sum dist/sssd-smartcard_0.2.2_all.deb
ssh sysadmin@10.0.0.50 'sha256sum /tmp/sssd-smartcard_0.2.2_all.deb'
```

Both must print the same hash.

## 2. Install it

Prefer `apt install` over `dpkg -i`: apt pulls in the dependencies, dpkg does
not and leaves the package unconfigured if anything is missing.

On the target, from the directory the file is in:

```bash
sudo apt-get install -y ./sssd-smartcard_0.2.2_all.deb
```

Or over SSH, if it was copied to `/tmp`:

```bash
ssh sysadmin@10.0.0.50 'sudo apt-get install -y /tmp/sssd-smartcard_0.2.2_all.deb'
```

The leading path matters: `apt-get install sssd-smartcard` would look in the
archives and fail. A path starting with `/` or `./` tells apt it is a local
file.

**Reinstalling the same version does nothing.** `apt-get install` compares
versions and stops at *already the newest version (0.2.2)* without unpacking
anything, so iterating on a build that keeps the same version number leaves the
old code in place and every test afterwards runs against it. Found the hard
way. When the version has not changed:

```bash
sudo apt-get install -y --reinstall ./sssd-smartcard_0.2.2_all.deb
```

If apt is unavailable, `dpkg` plus a dependency fix:

```bash
ssh sysadmin@10.0.0.50 'sudo dpkg -i /tmp/sssd-smartcard_0.2.2_all.deb || sudo apt-get -f install -y'
```

Confirm all four commands are present and agree on their version:

```bash
ssh sysadmin@10.0.0.50 'sssd-smartcard --version; ad-prepare --version; sssd-smartcard-install-desktop --version; sssd-smartcard-setup --version | head -1'
```

```
sssd-smartcard 0.2.2
ad-prepare 0.2.2
sssd-smartcard-install-desktop 0.2.2
sssd-smartcard-setup 0.2.2
```

## 3. One-liner for a repeat deployment

Copy, install and verify in a single command:

Straight from the release, on the target:

```bash
VER=0.2.2; curl -sSfLO "https://github.com/franekSoftSF/sssd-smartcard-Profile-Manager/releases/download/v$VER/sssd-smartcard_${VER}_all.deb" && sudo apt-get install -y "./sssd-smartcard_${VER}_all.deb" >/dev/null && sssd-smartcard --version
```

Or copy-and-install from the build machine:

```bash
scp dist/sssd-smartcard_0.2.2_all.deb sysadmin@10.0.0.50:/tmp/ && ssh sysadmin@10.0.0.50 'sudo apt-get install -y /tmp/sssd-smartcard_0.2.2_all.deb >/dev/null && sssd-smartcard --version'
```

## Without a .deb: the tarball

For a machine where installing a package is not wanted, or a non-Debian host:

```bash
VER=0.2.2
REPO=https://github.com/franekSoftSF/sssd-smartcard-Profile-Manager/releases/download/v$VER
curl -sSfLO "$REPO/sssd-smartcard-${VER}.tar.gz"
curl -sSfLO "$REPO/sssd-smartcard-${VER}.tar.gz.sha256"
sha256sum -c "sssd-smartcard-${VER}.tar.gz.sha256"
```

or, from the build machine:

```bash
scp dist/sssd-smartcard-0.2.2.tar.gz sysadmin@10.0.0.50:/tmp/
```

```bash
ssh sysadmin@10.0.0.50 'cd /tmp && tar xzf sssd-smartcard-0.2.2.tar.gz && cd sssd-smartcard-0.2.2 && sudo ./install.sh'
```

`install.sh` puts the same files in the same places as the package; it just has
no dpkg database entry, so `apt remove` will not undo it. `sudo ./install.sh
--uninstall` does.

---

# Setting up a clean machine

## Two machines, one domain

Where the tests use a desktop host and a server host in the same domain, keep
**one environment file per machine**. Everything except `hostname` and `role`
is identical, so copy and edit two lines.

Desktop host — `/etc/sssd-smartcard/environment.json`:

```json
{
  "domain": "ad.example.com",
  "dns": ["10.0.0.10"],
  "hostname": "wks-desktop",
  "role": "desktop",
  "desktop": true,
  "join_user": "administrator",
  "test_user": "someone@ad.example.com",
  "ca": ["/root/pki/root-ca.pem", "/root/pki/issuing-ca.pem"],
  "crl": true,
  "notes": "greeter testing"
}
```

Server host — same file, two lines different:

```json
  "hostname": "wks-server",
  "role": "server",
  "desktop": false,
```

`role` is not decoration. `sssd-smartcard-install-desktop` **refuses to run**
on a machine whose file says `role: server`, which is the mistake that happens
when two hosts share a domain and two terminals are open at once.
`--force-role` overrides it.

**The hostnames must differ.** Two machines joining with the same name means
the second join takes over the first machine's account in AD, and the first
then fails Kerberos with a KVNO mismatch that looks like nothing to do with
names. `ad-prepare` warns when the name it is about to take already resolves
to a different address.

What differs in practice between the two:

| | Desktop host | Server host |
|---|---|---|
| Card login tested with | the GDM greeter | `pamtester` under `sudo` |
| Needs step 3 (desktop) | yes | no |
| `card detect` | works | **needs `sudo`** |
| `allow_missing_name` | relevant: no username typed | not applicable |

That `sudo` row matters on the server: `pcsc-lite` authorises through polkit
(`allow_any=no`, `allow_inactive=no`), and an SSH session has no seat, so an
unprivileged user is denied and the error reads like a missing reader. Every
card command on the server goes through `sudo`.

## Step 0 — describe the environment once

The domain, its DNS servers, the hostname and the CA paths go in one JSON file
instead of being retyped on every command. Every script reads it.

Give it the domain and it works out the rest:

```bash
sudo ad-prepare --init-env --domain ad.example.com
```

```
Discovering ad.example.com
[ OK ] domain controllers found: 10.0.0.10
   from the SRV records of ad.example.com; in AD these are normally the
   DNS servers too. Add or replace them in the file if not.
[ OK ] hostname: wks-server
[ OK ] role: server

wrote /etc/sssd-smartcard/environment.json

   still to fill in by hand: join_user, test_user and ca (the CA files).
```

It reads the domain controllers out of the `_ldap._tcp` SRV records, falling
back to the zone's `NS` records and then to the domain's own `A` records; in AD
those hosts are normally the DNS servers as well. The realm, the search domain
and the test user's suffix follow from the domain, the hostname is read from
the machine, and the role is decided by whether a display manager is running or
`graphical.target` is the default.

That needs a resolver which can already see the zone — true when DHCP hands out
the AD servers, not true on an isolated network. When discovery finds nothing it
says so and leaves the example address rather than writing a guess.

`--dns` overrides the discovery, and more servers can be added to the file by
hand afterwards:

```bash
sudo ad-prepare --init-env --domain ad.example.com --dns 10.0.0.10,10.0.0.11
```

Without `--domain` it writes the bare template, which is refused if applied
unedited. Either way the result looks like this — fill in what it could not
know:

```json
{
  "domain": "ad.example.com",
  "dns": ["10.0.0.10"],
  "hostname": "wks01",
  "join_user": "administrator",
  "test_user": "someone@ad.example.com",
  "ca": ["/root/pki/root-ca.pem", "/root/pki/issuing-ca.pem"],
  "crl": true,
  "notes": "second test PKI"
}
```

| Key | Meaning |
|---|---|
| `domain` | AD DNS domain. Required. |
| `realm` | Kerberos realm. Derived from `domain` upper-cased when omitted. |
| `dns` | Domain controller DNS servers, as a list. |
| `search` | DNS search domains. Defaults to `domain`. |
| `hostname` | Short name for this host; the FQDN becomes `<hostname>.<domain>`. |
| `join_user` | Account used for `realm join`. |
| `test_user` | The user every verification step resolves and tests. |
| `ca` | CA certificate files, root first. |
| `crl` / `ocsp` | Which revocation mechanism this PKI offers. |
| `role` | `desktop` or `server`. The desktop installer refuses to run on a `server`. |
| `desktop` | Whether this machine needs a graphical environment. |
| `smartcard_required` | `true` for card-only login, `false` for card-or-password. |
| `notes` | Free text, so a later run is unambiguous about which lab this is. |

An unknown key is an error, not a warning — a typo that is silently dropped
leaves you believing a setting took effect. A file still holding the template's
example values is refused too, so an unedited template cannot set your DNS to
`10.0.0.10`.

A flag on the command line always overrides the file, and `--env FILE` reads a
different one — useful for keeping several labs side by side:

```bash
sudo ad-prepare --env /root/labs/pki-two.json --yes
```

From here the commands need no arguments at all.

## The four steps

In order. Each verifies its own work and refuses to hand the next
one a broken host, so a failure stops where the fault is.

**Keep a second SSH session open throughout.** Steps 3 and 4 touch networking
and PAM.

## Step 1 — DNS and hostname

A join fails for two boring reasons far more often than interesting ones: the
host cannot resolve the domain's SRV records, or it does not know its own
fully qualified name.

```bash
sudo ad-prepare --check
```

```bash
sudo ad-prepare --dry-run
```

```bash
sudo ad-prepare --yes
```

It does not bounce the interface, so the SSH session survives; persistence
lands for the next boot. Undo with the path it prints:

```bash
sudo ad-prepare --rollback /var/lib/sssd-smartcard/backups/<stamp>
```

## Step 2 — Join the domain

```bash
sudo sssd-smartcard-setup --only packages,join,identity --realm AD.EXAMPLE.COM --join-user administrator --test-user someone@ad.example.com --yes
```

The `identity` stage is a hard gate: it refuses to continue until the test user
resolves by name. Smart Card authentication cannot work before plain identity
lookup does, and a broken trust otherwise gets misdiagnosed as a certificate
problem.

Confirm by hand:

```bash
id someone@ad.example.com
```

## Step 3 — A minimal desktop (only for greeter testing)

Skip this if `pamtester` is enough. A card login at the real GDM greeter is the
only test that exercises what users actually do.

```bash
sudo sssd-smartcard-install-desktop --dry-run
```

```bash
sudo sssd-smartcard-install-desktop --yes
```

Roughly 1.5 GB, ten minutes or more. It runs **detached under systemd**, so
losing the SSH session does not interrupt dpkg. If the session drops, reattach:

```bash
sudo sssd-smartcard-install-desktop --status
```

The greeter appears after a reboot, or immediately:

```bash
sudo systemctl isolate graphical.target
```

## Step 3b — let the tool work the PKI out for itself

With a card from the new PKI inserted, this follows the certificate's own
pointers and fetches everything: the CA chain via AIA `caIssuers`, the CRLs via
the distribution points, and a live OCSP request to find out whether a
responder actually answers.

```bash
sudo sssd-smartcard ca discover --from-card
```

It reports the chain with SHA-256 fingerprints, whether it reached a
self-signed root, which CRLs exist, whether OCSP works, and the revocation
configuration that implies. Nothing is written.

To write it — the trust bundle and the CRLs:

```bash
sudo sssd-smartcard ca discover --from-card --install
```

### Just the PKI address, with no card

For a PKI nobody has a certificate from yet, the address alone is enough. The
directory is listed, and everything it publishes is fetched and reported:

```bash
sudo sssd-smartcard ca discover --pki-url http://pki.example.com/PKI/
```

```
PKI at http://pki.example.com/PKI/
  http://pki.example.com/PKI/Example%20Issuing%20CA.crt
  http://pki.example.com/PKI/Example%20Issuing%20CA.crl
  ...

[PASS] PKI listing  2 certificate(s) and 2 CRL(s)
[INFO]   intermediate  CN=Example Issuing CA,DC=ad,DC=example,DC=com
[INFO]     SHA-256  11:11:...
[INFO]     valid until  2035-10-29 19:55:51+00:00
[INFO]   root  CN=Example Root CA
[PASS] chain  every intermediate's issuer is published here
[WARN] CA trust  these certificates were downloaded, not verified
[INFO]   CRL CN=Example Issuing CA...  next update 2026-10-19, 5 revoked
```

So you learn what the PKI is — how many tiers, which CAs, how long they are
valid, whether the chain closes, and whether the CRLs are current — before
touching a card. `--install` writes the certificates into the trust bundle.

Only links on the same host are followed, and only a bounded number: an address
someone typed is not a reason to crawl. The common AD CS paths (`PKI/`,
`CertEnroll/`, `certdata/`) are tried when the URL given has no listing of its
own, and a host with listings disabled is reported as such rather than having
its filenames guessed.

CRLs for the trust bundle still want a certificate, because a CA's own CRL URL
is advertised by the certificates it signed — Step 5.

With a certificate, `--pki-url` is instead a fallback for an AIA that is
missing or LDAP-only:

```bash
sudo sssd-smartcard ca discover --from-card --pki-url http://pki.example.com/PKI/
```

Two things it is careful to distinguish, because both decide the
configuration:

**Downloaded is not trusted.** The chain it fetches is a proposal. Anyone able
to answer the AIA URL could otherwise install themselves as a CA whose
certificates log in. Compare the printed fingerprints against the PKI out of
band before relying on them — `--install` prints them again at the moment of
import for exactly that.

**Advertised is not working.** An AIA OCSP URL only means the CA put a URL in
the certificate. SSSD fails closed on OCSP, so enabling it against a silent
responder stops every card login. A real OCSP request is therefore sent, and
`crl` is recommended when the responder does not answer — with the reason
stated: *advertises no responder* and *the advertised responder did not answer*
are different faults.

## Step 4 — Smart Card configuration

With the CA chain on the machine:

```bash
sudo sssd-smartcard-setup --dry-run --test-user someone@ad.example.com --ca /root/pki/root-ca.pem --ca /root/pki/issuing-ca.pem
```

```bash
sudo sssd-smartcard-setup --test-user someone@ad.example.com --ca /root/pki/root-ca.pem --ca /root/pki/issuing-ca.pem --yes
```

Then enable PAM and test without logging out:

```bash
sudo pam-auth-update --enable sss-smart-card-optional
```

```bash
pamtester -v login someone@ad.example.com authenticate
```

It must prompt for a **PIN**, not a password. A password prompt means the card
path was not taken — `sudo sssd-smartcard doctor --user someone@ad.example.com`
says which layer declined.

## Step 5 — Revocation, if the PKI publishes CRLs

```bash
sudo sssd-smartcard ca crl update --from-card
```

```bash
sudo sssd-smartcard ca crl timer --install
```

Run it once with the card inserted: the issuing CA's CRL URL is only advertised
by end-entity certificates, and the URL is then remembered so the timer can
refresh with no card present.

## Checking the result, at any point

```bash
sudo sssd-smartcard doctor --user someone@ad.example.com
```

One command covering every layer: SSSD, the certificate, the mapping, the CA
bundle, PAM, `local_auth_policy`, the home directory, Kerberos and the CRL.

---

# Reusing the machine for another domain

A second test domain on the same machine needs the first one gone. Not for
tidiness: the SSSD cache keeps answering for the old domain's users, the keytab
holds the old host principal, `krb5.conf` still names the old realm and KDC,
and the certmap rule still pins the old issuer DN — so a certificate from the
new PKI silently fails to match and login falls through to a password, which
looks like a Smart Card problem and is not.

See what is still there:

```bash
sudo ad-reset --check
```

Remove it, while the old domain controller is still reachable so the machine
account is deleted rather than orphaned:

```bash
sudo ad-reset --dry-run
```

```bash
sudo ad-reset --yes
```

Add `--remove-homes` to delete `/home/<user>@<old domain>` as well; it is off
by default because that is user data. Add `--local-only` when the old DC is
already gone — the machine account then stays behind in AD and has to be
deleted there by hand.

`ad-reset` deliberately leaves PAM, local accounts, SSH, sudo, DNS and the
hostname alone. DNS and the hostname belong to the *next* domain, and
`ad-prepare` sets them.

Then start again from Step 0 with a new environment file.

# Starting over completely

The machine was changed by three things; each undoes separately.

```bash
# configuration written by this tool (newest backup first)
sudo ls -1t /var/lib/sssd-smartcard/backups/
```

```bash
# the package
sudo apt-get remove -y sssd-smartcard        # keeps /etc/sssd-smartcard
sudo apt-get purge -y sssd-smartcard         # removes it too
```

```bash
# the domain membership
sudo realm leave ad.example.com
```

`apt remove` does not revert `/etc/sssd/sssd.conf` — that is deliberate, since
removing a management tool should not log everyone out. Restore it from the
backup directory above if that is what you want.
