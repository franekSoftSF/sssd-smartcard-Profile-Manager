# sssd-smartcard

Generate, validate and deploy the SSSD configuration needed to log in to Linux
with a Smart Card / PIV certificate.

The tool's central idea: **put a card in the reader and let it work out the
configuration for you.** It reads the certificate, sees what is actually in it,
ranks the mapping mechanisms that certificate can support, and prints a complete
profile plus the exact `sssd.conf` section to go with it.

```
sssd-smartcard cert inspect --from-card
```

```
Recommended mapping
-------------------
  Domain:      domain-a.local  (taken from the SAN UPN suffix)
  Mechanism:   san-upn  -- SAN otherName / Microsoft UPN
  Confidence:  95/100
  Resolves to: jan.kowalski@domain-a.local

Generated sssd.conf
-------------------
  [certmap/domain-b.local/DOMAIN-A-UPN]
  matchrule = KRB5:<ISSUER>^CN=Enterprise Issuing CA,DC=domain-a,DC=local$<EKU>clientAuth,msScLogin<SAN:ntPrincipalName>.*@domain-a\.local$
  maprule = LDAP:(|(userPrincipalName={subject_nt_principal})(sAMAccountName={subject_nt_principal.short_name}))
  domains = domain-a.local

  [domain/domain-b.local]
  local_auth_policy = enable:smartcard

  [pam]
  pam_cert_auth = True
```

Two details in that output are the difference between a working host and a
password prompt, and both are documented with their evidence in
[docs/sssd-reference.md](docs/sssd-reference.md): the `matchrule` components are
**concatenated with no operator** (an infix `" && "` makes SSSD reject the rule
and silently fall back), and `local_auth_policy = enable:smartcard` is what
allows SSSD to accept a card at all under the `ad` and `ldap` providers.

Verified end to end on Ubuntu 24.04 + SSSD 2.9.4 against a Samba AD domain with
a YubiKey PIV certificate — see [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md) for
the mechanism as it actually runs, and [docs/TUTORIAL.md](docs/TUTORIAL.md) for
the step-by-step walkthrough that produced it.

## Documentation

| Document | For |
|---|---|
| [DEPLOY.md](DEPLOY.md) | copying the package over, and a clean machine from nothing to a card login |
| [docs/COMMANDS.md](docs/COMMANDS.md) | every command and flag, with the reasoning |
| [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md) | the mechanism as it actually runs, and the failure modes met |
| [docs/sssd-reference.md](docs/sssd-reference.md) | every emitted option with its source, and the measured findings |
| [docs/TUTORIAL.md](docs/TUTORIAL.md) | the verified record of the first lab, against a specific domain |
| [STATUS.md](STATUS.md) | where the work stands and what is still open |

All but the tutorial ship inside the package, under
`/usr/share/doc/sssd-smartcard/`.

## The scenario it is built for

```
DOMAIN A -- Windows Active Directory          DOMAIN B -- Samba AD
  user accounts                                 the Linux host is a member here
  AD CS / EJBCA / Blinky / any X.509 PKI        SSSD, Kerberos, PAM
  Smart Card / PIV
                        one-way trust: B trusts A
```

The accounts are in DOMAIN A, the host is joined to DOMAIN B. That means the
`[certmap/...]` section belongs to **domain B** while the user search has to be
directed at **domain A** with `domains=`. When `sssd.conf` is readable the tool
notices the difference and writes the rule correctly by itself.

Nothing is tied to Microsoft AD CS. A mapping mechanism only cares about what is
*in* the certificate, so AD CS, EJBCA, Blinky or any other X.509 PKI all go
through the same code paths.

## Install

### Debian package (Ubuntu, Debian)

```bash
sudo apt install ./sssd-smartcard_0.2.0_all.deb
```

`apt` pulls in the `Recommends` — `sssd`, `sssd-ad`, `sssd-tools`, `libpam-sss`,
`opensc`, `opensc-pkcs11`, `p11-kit`, `pcscd`, `krb5-user`, `realmd`, `adcli` —
so one command gets you a host ready for the guided setup. `adsys`,
`certmonger`, `cepces`, `pamtester` and `softhsm2` are `Suggests`, because not
every host wants Group Policy, auto-enrolment or the test tooling.

| Path | Contents |
|---|---|
| `/usr/bin/sssd-smartcard` | the CLI |
| `/usr/sbin/sssd-smartcard-setup` | the guided setup script |
| `/usr/lib/python3/dist-packages/sssd_smartcard/` | the Python package |
| `/etc/sssd-smartcard/profiles/` | your profiles, searched first |
| `/usr/share/sssd-smartcard/profiles/` | the packaged examples |
| `/usr/share/man/man8/` | `sssd-smartcard(8)`, `sssd-smartcard-setup(8)` |
| `/usr/share/doc/sssd-smartcard/` | README, SSSD reference, the test lab |
| `/var/lib/sssd-smartcard/` | backups and generated profiles, mode 0700 |

Examples live under `/usr/share`, not `/etc`, so there are no conffiles and dpkg
never prompts about a modified example on upgrade. `apt remove` leaves your
`/etc` profiles and your backups alone; `apt purge` removes the directories only
if they are empty, and says so when it keeps them.

### On a minimized Ubuntu image, the man pages disappear

Ubuntu cloud and minimized server images ship
`/etc/dpkg/dpkg.cfg.d/excludes` containing:

```
path-exclude=/usr/share/man/*
path-exclude=/usr/share/doc/*
```

dpkg therefore **silently discards** this package's manual pages and its
reference documentation at install time — `dpkg -L sssd-smartcard` still lists
them, but they are not on disk. On top of that `/usr/bin/man` is a local
diversion to a stub script that only prints "This system has been minimized".

Nothing a package can do about that from the inside. To get the documentation on
such a host, re-include just this package rather than un-minimizing everything:

```bash
sudo tee /etc/dpkg/dpkg.cfg.d/zz-sssd-smartcard-docs >/dev/null <<'EOF'
path-include=/usr/share/man/man8/sssd-smartcard*
path-include=/usr/share/doc/sssd-smartcard/*
EOF
sudo apt install --reinstall ./sssd-smartcard_0.2.0_all.deb

# make `man` itself work again
sudo apt install -y man-db
sudo cp -a /usr/bin/man /root/man.minimized-stub.bak
sudo rm /usr/bin/man
sudo dpkg-divert --local --rename --remove /usr/bin/man
sudo mandb -q
```

The alternative is Ubuntu's own `sudo unminimize`, which restores documentation
for every installed package and costs considerably more disk.

Build it yourself:

```bash
bash packaging/build-deb.sh          # needs only dpkg-deb; no root, no debhelper
dpkg-buildpackage -b -us -uc         # canonical route, needs debhelper + dh-python
```

`build-deb.sh` reads `Depends`, `Recommends`, `Suggests` and the description
straight out of `debian/control`, so the two routes cannot drift apart. It runs
the test suite first and refuses to package a failing tree, then verifies the
result: expected paths, file modes, `root:root` ownership, and that the packaged
module actually imports and validates the shipped profiles. On Windows, build it
in WSL or a container — there is deliberately no "build a .deb without dpkg"
fallback, because a hand-rolled `ar` archive is easy to get subtly wrong and a
package that installs incorrectly on a server is worse than no package.

### Tarball (any distribution)

```bash
tar xzf sssd-smartcard-0.2.0.tar.gz
cd sssd-smartcard-0.2.0
sudo ./install.sh
```

`install.sh` uses your distribution's own `python3-cryptography` and
`python3-yaml`, so nothing is downloaded and nothing shadows a system package.
It installs the CLI to `/usr/local/bin/sssd-smartcard`, the guided setup script
to `/usr/local/sbin/sssd-smartcard-setup`, and example profiles to
`/etc/sssd-smartcard/profiles`. It never touches `sssd.conf`, the CA trust store
or PAM. Undo with `sudo ./install.sh --uninstall`.

Build the archive yourself with `bash packaging/build-tarball.sh` (works from
Git Bash on Windows too), or work from a checkout with `pip install -e .`.

Requires Python 3.10+ and bash 4.4+. The setup script installs the rest.

The tool runs on any platform for offline work -- inspecting a certificate,
authoring a profile, rendering and validating configuration. Anything that
touches a card, a service or the PAM stack reports `SKIP` off-host rather than
guessing.

## Setting a machine up

Step-by-step commands live in **[DEPLOY.md](DEPLOY.md)** — copying the package
over, installing it, and taking a clean machine from nothing to a card login,
including the two-machine layout (a desktop host for greeter logins, a server
host driven under `sudo`).

The short version, once the package is installed:

```bash
sudo ad-prepare --init-env          # describe the environment once, in JSON
sudo ad-prepare --yes               # DNS and hostname, then verify
sudo sssd-smartcard-setup --only packages,join,identity --yes
sudo sssd-smartcard ca discover --from-card --install
sudo sssd-smartcard-setup --yes     # the Smart Card configuration itself
sudo sssd-smartcard doctor --user someone@ad.example.com
```

Every one of those shows what it would do and stops; `--yes` applies. Reusing
the machine for a second domain starts with `sudo ad-reset --check`.

## Distributions

PAM is the part with no portable answer, and getting it wrong is how a setup
script bricks a login. The tool detects the distribution and never prints the
other family's command:

| | PAM mechanism | Smart Card optional | Smart Card only |
|---|---|---|---|
| RHEL / Fedora / Rocky / Alma | `authselect` | `enable-feature with-smartcard` | `+ with-smartcard-required` |
| Ubuntu 23.10+ | `pam-auth-update` | `--enable sss-smart-card-optional` | `--enable sss-smart-card-required` |
| Ubuntu 23.04 and older, Debian | by hand | `pam_sss.so … try_cert_auth` | `pam_sss.so … require_cert_auth` |

On the older releases there is no profile to enable, so the tool prints the exact
`/etc/pam.d/common-auth` line and refuses to edit it.

## Group Policy

Two unrelated things get called "GPO support" on Linux, and the profile keeps
them apart.

**SSSD's own logon-rights check** — `ad_gpo_access_control`, no extra package:

```yaml
gpo:
  manage: true
  access_control: permissive
  map_interactive_add: [cockpit]
```

`sssd-ad(5)` documents the default as **`enforcing`**, which means a freshly
joined host already denies login to anyone the domain's GPOs do not grant
`InteractiveLogonRight`. (Red Hat's older RHEL 7 guide says `permissive`; the
current man page wins.) That is why the tool warns when you leave this
unmanaged and defaults to `permissive` when you take control of it.

**Canonical's adsys** — the real Group Policy client, Ubuntu only:

```yaml
gpo:
  adsys: true
  cert_autoenroll: true
```

Joining AD and dconf policy are available to everyone; other adsys features need
an Ubuntu Pro subscription, free for up to five machines. `cert_autoenroll`
additionally installs `certmonger` and `cepces` for certificate auto-enrolment
from AD CS — you still switch it on in the GPO itself. Setting `gpo.adsys` on a
non-Ubuntu host is a warning, not a silent no-op.

## Test lab

`lab/` is a Vagrant environment that exercises the whole card path with **no
reader and no physical card**: a Samba AD domain controller with its own small
PKI, and an Ubuntu client whose smart card is a SoftHSM2 token.

```bash
cd lab
vagrant up
vagrant ssh client -c 'sudo /vagrant/run-tests.sh'
```

The acceptance suite asserts, among other things, that a dry run leaves
`sssd.conf` byte-identical, that the real run ends with mode 0600 and a working
certmap section, that running it twice changes nothing, that **SSSD's own
`p11_child` verifies the card**, that the InfoPipe `ListByCertificate` call
returns the right AD user, that the local matching engine agrees with `sssctl
cert-eval-rule`, that a certificate from a different CA is rejected, and that
PAM was **not** modified because `--pam` was not passed.

See [lab/README.md](lab/README.md), including why the lab is single-domain and
what a real one-way trust additionally needs.

## Walkthrough

[docs/TUTORIAL.md](docs/TUTORIAL.md) is a step-by-step run through a real
deployment: install, join, CA chain, inspect the card, prove the mapping, apply,
enable PAM, then Kerberos and Group Policy. Each step says what to run, what you
should see, and what it means if you do not — ordered so that a failure tells you
*where* the fault is instead of leaving you guessing at a login prompt.

It is written against a specific lab, so the domain and host names are literal.
Substitute your own. It is **not** shipped inside the `.deb`.

## Commands

**[docs/COMMANDS.md](docs/COMMANDS.md)** is the reference for all five programs
and every subcommand, with the flags each one takes and the reasoning behind
the non-obvious ones.

The one command worth remembering:

```bash
sudo sssd-smartcard doctor --user someone@ad.example.com
```

It covers every layer at once: SSSD and its version, the certificate, the
mapping, the CA bundle, PAM, `local_auth_policy`, the home directory, Kerberos,
the CRL and its refresh timer. Each finding names the option at fault and what
to do about it.

## Mapping mechanisms

`sssd-smartcard mapping types` prints these with their options.

| Type | What it binds on | Notes |
|---|---|---|
| `san-upn` | UPN in the SAN otherName | The standard AD/PIV mechanism |
| `san-pkinit` | Kerberos principal in the PKINIT SAN | IPA and MIT-issued certificates |
| `san-rfc822` | e-mail address in the SAN | For PKIs that issue no UPN |
| `sid-extension` | AD SID extension (KB5014754) | Strongest; needs SSSD >= 2.8.2 |
| `issuer-serial` | `altSecurityIdentities` `X509:<I>..<SR>..` | AD strong mapping; SSSD >= 2.8.2 |
| `subject-key-id` | `altSecurityIdentities` `X509:<SKI>..` | SSSD >= 2.8.2 |
| `issuer-subject` | `altSecurityIdentities` `X509:<I>..<S>..` | Classic form |
| `subject` | subject DN | Weak on its own -- pin the issuer |
| `subject-dn-component` | one DN attribute, e.g. CN | SSSD >= 2.8.2 |
| `certificate-binary` | the whole DER certificate | SSSD's own default rule |
| `custom` | your own `matchrule` / `maprule` | Escape hatch |

Ranking deliberately penalises mechanisms that cannot resolve anybody until an
administrator writes a value onto every user object (`altSecurityIdentities`,
a published certificate). A theoretically stronger mapping that nobody has
provisioned is worth less in practice than one that works against an untouched
directory -- and the penalty is shown, not hidden.

Adding a mechanism means subclassing `MappingMechanism` and decorating it with
`@register` in `certmap/mappings.py`. Nothing else enumerates mechanisms by
name, and profiles carry a free-form `options` dictionary only the mechanism
itself interprets.

## Profile format

```yaml
apiVersion: sssd-smartcard/v1
name: AD-PIV-UPN
description: PIV certificates with the UPN in the SAN

# The SSSD domain this host is joined to. This names the
# [certmap/<domain>/<name>] section -- not where the accounts live.
domain: domain-b.local
provider: ad            # ad | ldap | ipa

certificate:
  issuer: "CN=Enterprise Issuing CA,DC=domain-a,DC=local"
  eku:
    - clientAuth
    - smartCardLogon    # normalised to SSSD's msScLogin keyword
  # key_usage: [digitalSignature]
  # issuer_regex / subject_regex pass a real regex through verbatim

mapping:
  type: san-upn
  domains: [domain-a.local]    # search the trusted domain
  options:
    upn_suffix: domain-a.local
  priority: 10

validation:
  check_issuer: true
  check_eku: true
  check_expiration: true
  check_revocation: false
  partial_chain: false

authentication:
  mode: optional        # optional | required
  # local_smartcard: true       # local_auth_policy = enable:smartcard
  # local_auth_policy: "enable:smartcard, enable:passkey"
  # p11_uri, p11_child_timeout, allowed_services

ca_trust:
  bundle_path: /etc/sssd/pki/sssd_auth_ca_db.pem
  sources: []

revocation:
  enabled: false
  method: none          # none | crl | ocsp | ocsp+crl
  fail_mode: closed     # closed | open
  # crl_file, ocsp_responder, ocsp_digest

gpo:
  manage: false             # take control of ad_gpo_access_control
  access_control: permissive # enforcing | permissive | disabled
  # implicit_deny, ignore_unreadable
  # map_interactive_add / map_interactive_remove use the documented +/- syntax
  adsys: false              # Canonical's GPO client (Ubuntu only)
  cert_autoenroll: false    # certmonger + cepces; requires adsys
```

Profiles are looked up by name in `$SSSD_SMARTCARD_PROFILES`,
`~/.config/sssd-smartcard/profiles`, `/etc/sssd-smartcard/profiles` and the
bundled `profiles/` directory, or given directly by path. Unknown keys are
rejected with the list of accepted ones, so a typo never half-configures a host.

## SSSD version compatibility

`sssd-smartcard` detects the installed SSSD and gates every option on what that
version actually has. Override with `--sssd-version`, and turn refusals into
warnings with `--allow-degraded`.

| Feature | Since | Source |
|---|---|---|
| `[certmap/...]` for AD and LDAP providers | 2.0.0 | `sss-certmap(5)` |
| `p11_uri`, `crl_file` | 2.1.0 | SSSD 2.1.0 release notes |
| `ocsp_dgst` | 2.2.1 | SSSD 2.2.1 release notes |
| `soft_ocsp`, `soft_crl` | 2.2.3 | SSSD 2.2.3 release notes |
| `{serial_number}`, `{subject_key_id}`, `{sid}`, `{cert!DIGEST}`, `{*_dn_component}` | 2.8.2 | SSSD 2.8.2 release notes |
| `local_auth_policy` | 2.9.2 | SSSD 2.9.2 release notes |
| `local_auth_policy = enable:smartcard` | 2.9.3 | SSSD 2.9.3 release notes |

Options documented without an introduction version (`partial_chain`, `no_ocsp`,
`pam_cert_auth`, `pam_cert_verification`) are treated as always present, and the
feature table says so rather than inventing a version.

## What it deliberately does not do

- **It does not edit PAM files unless you ask.** A broken PAM stack locks you out
  of the machine, so the distro-correct command is printed and only run with
  `--pam`; `--require-smartcard` also demands an interactive confirmation. On the
  releases with no `pam-auth-update` profile it prints the exact `common-auth`
  line and refuses to write it. `sssd.conf` has no "Smart Card only" switch;
  enforcement genuinely lives in `pam_sss.so require_cert_auth`.
- **It does not touch private keys.** Ever, on any code path.
- **It does not handle PINs.** The PIN goes straight from your keyboard into
  the PKCS#11 or PAM mechanism that needs it. Nothing here stores, logs or
  forwards one.
- **It does not invent `sssd.conf` options.** Every key it writes comes from
  `sssd.conf(5)` or `sss-certmap(5)`. Where the documentation states a caveat --
  `ocsp_default_responder` is documented as currently ignored -- the tool warns
  instead of pretending it works.
- **It does not download CRLs.** SSSD reads a CRL from a local PEM file
  (`crl_file=`); it does not fetch the CRL distribution point. If you enable CRL
  checking, something has to refresh that file, and the tool tells you so.

## Local evaluation vs. sssctl

The local matching engine reads `&&` as binding tighter than `||`.
`sss-certmap(5)` documents both operators but neither precedence nor any
grouping syntax, so keep rules simple and confirm anything unusual with
`sssctl cert-eval-rule`, which the tool runs automatically when it is present.
DN rendering for `!ad_x500` and friends is likewise a local approximation of
libsss_certmap, good enough to preview a rule offline. Base64 matching keywords
(`<SAN:otherName>`, `<SAN:x400Address>`, `<SAN:ediPartyName>`) are left entirely
to `sssctl`, and the local engine says so rather than guessing.

## Development

```bash
pip install -e ".[dev]"
make test        # or: PYTHONPATH=src python -m pytest -q
make lint        # bash -n on every shell script
make shellcheck  # if shellcheck is installed
make package     # dist/sssd-smartcard-<version>.tar.gz
make deb         # dist/sssd-smartcard_<version>_all.deb
make deb-native  # the same, via dpkg-buildpackage
make lab-up lab-test
```

Bumping the version means editing `src/sssd_smartcard/__init__.py` and adding a
`debian/changelog` entry; `build-deb.sh` refuses to build if the two disagree.

The test suite builds synthetic certificates carrying the real extensions --
Microsoft UPN otherName, KRB5 PKINIT principal, the AD SID security extension,
EKUs, AIA and CRL distribution points -- and drives the whole
certificate → profile → `sssd.conf` path against them, including apply and
rollback against a temporary config file, the per-distribution PAM decisions, and
the GPO rendering.

## Sources

- [`sss-certmap(5)`](https://www.mankier.com/5/sss-certmap) -- matching and mapping rule syntax
- [`sssd.conf(5)`](https://www.mankier.com/5/sssd.conf) -- `[pam]`, `certificate_verification`, `[certmap/...]`
- [SSSD release notes](https://sssd.io/) -- when each option appeared
- [Configuring certificate mapping rules in IdM (RHEL 9)](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/managing_certificates_in_idm/conf-certmap-idm_managing-certificates-in-idm) -- `sssctl cert-eval-rule` usage
- [Configuring smart card authentication using authselect (RHEL 9)](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/managing_smart_card_authentication/configuring-smart-cards-using-authselect_managing-smart-card-authentication) -- `with-smartcard`, `with-smartcard-required`
- [Authenticating as an AD user using PKINIT with a smart card (RHEL 9)](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/managing_smart_card_authentication/authenticating-as-an-active-directory-user-using-pkinit-with-a-smart-card_managing-smart-card-authentication) -- `kinit -X X509_user_identity`
- [Smartcard authentication testing with AD](https://sssd.io/design-pages/smartcard_authentication_testing_with_ad.html) -- `ldap_user_certificate`, pre-auth marker
- [Smart card authentication -- Ubuntu Server documentation](https://ubuntu.com/server/docs/how-to/security/smart-card-authentication/) -- Ubuntu packages, `pam-auth-update` profiles, `p11_child`, InfoPipe test
- [`sssd-ad(5)`](https://www.mankier.com/5/sssd-ad) -- `ad_gpo_*` options and their defaults
- [ADSys documentation](https://documentation.ubuntu.com/adsys/) and [feature availability](https://ubuntu.com/docs/adsys/stable/reference/features/) -- Ubuntu GPO client, Ubuntu Pro scope, certificate auto-enrolment

Every fact the generator depends on is recorded with its source in
[docs/sssd-reference.md](docs/sssd-reference.md), including one place where Red
Hat's older documentation and the current man page disagree.
