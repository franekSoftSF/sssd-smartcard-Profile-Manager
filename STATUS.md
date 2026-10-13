# Status — 2026-10-12

End-of-session snapshot. Everything below was verified on the real lab host, not
inferred.

## Where things stand

**The whole chain works, end to end, and is documented.** Smart Card login,
graphical login, a Kerberos TGT via PKINIT, and CRL revocation enforced.

| Step | State |
|---|---|
| 0–3 join, CA trust bundle | ✅ verified |
| 4–7 certificate → profile → `sssd.conf`, mapping | ✅ verified |
| 8 PAM, card login (`pamtester` → PIN prompt) | ✅ verified |
| 8b home directories (`pam_mkhomedir`) | ✅ verified |
| 9 GDM graphical login | ✅ works (username must be full UPN) |
| 10 PKINIT / Kerberos ticket | ✅ verified, trace-confirmed |
| 11 CRL revocation | ✅ enforced, timer running |

- Version **0.2.2**, **398 tests** passing
- `dist/sssd-smartcard_0.2.2_all.deb` — sha256 `212498e40973c6eacce3f50a9634910f021ab76eb63b25bdde1aac3eddcdac80`
- `dist/sssd-smartcard-0.2.2.tar.gz` — sha256 `a746f42eca74089d9c92e381f2e37c0dca154176d8f34ee533424393d67f2010`

Documentation: [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md) (the mechanism as it
runs), [DEPLOY.md](DEPLOY.md) (a clean machine, step by step),
[docs/COMMANDS.md](docs/COMMANDS.md) (every command) and
[docs/sssd-reference.md](docs/sssd-reference.md) (every emitted option with its
source, and the measured findings).

`docs/TUTORIAL.md` is the record of this lab's own run. It keeps the real
hostnames, addresses and fingerprints, so it is deliberately **not** in the
repository and **not** in the package.

## Lab host 10.0.0.50 — final state

```
sssd                     active
/etc/sssd/sssd.conf      mode 0600
sssctl config-check      OK
debug_level              not set (0 lines)
sssd-smartcard-crl.timer enabled, next run 2026-10-13 00:10 CEST
sssd-smartcard           0.2.2
```

Effective configuration, the four lines that make card login work plus
revocation:

```ini
[sssd]
certificate_verification = no_ocsp, crl_file=/etc/sssd/pki/revocation.crl.pem

[domain/ad.example.com]
local_auth_policy = enable:smartcard

[certmap/ad.example.com/AD-PIV-UPN]
matchrule = KRB5:<ISSUER>^CN=Example Issuing CA,DC=ad,DC=example,DC=pl$<EKU>clientAuth,msScLogin<SAN:ntPrincipalName>.*@ad\.example\.pl$
maprule = LDAP:(|(userPrincipalName={subject_nt_principal})(sAMAccountName={subject_nt_principal.short_name}))

[pam]
pam_cert_auth = True
```

`/etc/krb5.conf` additionally carries `includedir`, `pkinit_anchors`,
`pkinit_eku_checking = kpServerAuth` and
`pkinit_kdc_hostname = DC01.ad.example.com`.

### Backups on the host

| Path | What |
|---|---|
| `/var/lib/sssd-smartcard/backups/2026101*` | every `config apply`, newest `20261012-000941` |
| `/root/AD-PIV-UPN.yaml.pre-crl` | profile before CRL was enabled |
| `/root/krb5.conf.pre-pkinit-eku` | krb5.conf before the PKINIT EKU options |
| `/root/sssd.conf.predebug` | sssd.conf before `debug_level` was raised (already reverted) |
| `/root/pam-backup-20261011-235026` | the whole PAM stack plus the debconf selection |

## Open threads

1. **A revoked certificate has not been tested.** This is the one gap that
   matters. Revocation is enabled and a *valid* certificate passes, but nothing
   has confirmed that a *revoked* one is actually refused. The issuing CA's CRL
   lists 5 revoked serials — a card holding one of those would close this. An
   artificial control is possible instead.
2. **`allow_missing_name` did not work at the GDM greeter.** The
   `gdm-smartcard-sssd-exclusive` stack carries it, so the user should have been
   identified from the certificate with nothing typed; the full UPN was still
   required. Login works either way, so this is recorded as unexplained rather
   than fixed.
3. **PKINIT works via a client-side relaxation, not a proper fix.** `dc01`
   presents a *Domain Controller* certificate (serverAuth + dNSName) rather than
   a *Kerberos Authentication* one (`id-pkinit-KPKdc` + `id-pkinit-san`).
   Reissuing it from the right template would let both `pkinit_eku_checking` and
   `pkinit_kdc_hostname` be removed.
4. **`fail_mode: closed`** is deliberate: an expired CRL stops every card login.
   That is what enforcing revocation means. `revocation.fail_mode: open` emits
   `soft_crl` and trades enforcement for availability — one line in the profile.
5. **`pam_mkhomedir` creates homes as `0750`**, so other members of
   `domain users` can read them. `doctor` warns; `chmod 0700` if unwanted.

## The five findings worth remembering

Each one is a case where a layer reported success while a layer beneath it had
failed. All are measured and sourced in `docs/sssd-reference.md`.

1. **Matching-rule components are concatenated, with no operator.** An infix
   `" && "` makes SSSD reject the rule (`[22][Invalid argument]`), skip it, fall
   back to its default mapping, find nobody, and drop to the password prompt.
2. **`local_auth_policy` defaults to `match`**, and the AD provider offers no
   local Smart Card authentication — so SSSD reads the card, verifies it, maps
   it to a real user, and then declines. Needs `enable:smartcard`.
3. **No home directory means a black screen**, after a completely successful
   authentication. `fallback_homedir` only names the path.
4. **A Kerberos ticket is not proof of PKINIT.** Without `krb5-pkinit`, `kinit`
   ignores `-X X509_user_identity`, asks for the account password and returns a
   valid TGT. The verdict must come from `KRB5_TRACE` showing `PA-PK-AS-REQ`.
5. **`crl_file` needs a CRL for every CA in the chain**, concatenated into one
   PEM. One short and no card works at all. `soft_crl` forgives expiry but never
   absence; OCSP does not relax it; `partial_chain` combined with `crl_file`
   breaks verification outright.

## Picking this up again

```bash
sudo sssd-smartcard doctor --user testuser@ad.example.com
```

That single command covers every layer above and is the right starting point.
Expect no failures and one warning (`SSSD reports no trusted domains`, which is
correct for a single-domain lab).
