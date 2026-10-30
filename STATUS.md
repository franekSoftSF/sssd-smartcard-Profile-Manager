# Status — 2026-10-30

End-of-session snapshot. Everything below was verified on the real lab host, not
inferred. Where something was not verified, it says so.

## Where things stand

**One certificate, four surfaces.** Each confirmed by the mechanism in the log,
never by a prompt alone — a prompt proved nothing three separate times in this
project's history.

| Surface | Evidence |
|---|---|
| Local login | `Backend cannot handle Smartcard authentication, trying local Smartcard authentication` |
| SSH | `Accepted key RSA … found at /usr/bin/sss_ssh_authorizedkeys:3` |
| `sudo`, locally | `PIN for <name>:` at a local console — observed 2026-10-30 |
| `sudo`, over SSH | `Running AuthorizedKeysCommand` → `ssh_rsa_verify: signature correct` |

All four resolve the same key, derived by SSSD from the same certificate in AD.
**One revocation closes all four.** That the CRL is load-bearing was proved by a
negative test: remove the file and the prompt changes from PIN to password;
restore it and the PIN returns.

- Version **0.3.4**, **619 tests** passing (4 skipped: three collector tests
  that only run on Linux, and a POSIX permission-bit assertion Windows cannot
  express)
- `sssd-smartcard_0.2.9_all.deb` — sha256
  `86a5eee44d1fd2d5a36f0795711ca9306ae3d6c11c24571b880e2e2d30a20f8d`
- `packaging/sanitise.py --check` clean; the Windows script, guide and PDF were
  additionally grepped by hand against 30 real identifiers, including the PDF's
  *extracted* text

## Tomorrow: the recording

Host and workstation are both in a clean, working state. Nothing needs to be
configured before filming.

Suggested order, because it builds the argument rather than listing features:

1. **Local card login** — `pamtester -v login <user> authenticate acct_mgmt`,
   then `doctor`. Note `acct_mgmt`: `authenticate` alone exercises only the auth
   phase and passed on a host where every real login was refused.
2. **Revocation enforced** — the negative test above. The strongest single
   moment, because it shows the control working rather than asserted.
3. **SSH with the same card** — `putty.exe -x509off -A -i CAPI:<thumbprint> -l
   <user> <host>`, then the server log line showing the key came from AD and not
   from any `authorized_keys` file.
4. **`sudo` from an AD group** — `sudo -l -U <user>`. The file names a group and
   no person; membership is managed in AD.
5. **PIN locally vs password over SSH** — the contrast explains the model
   better than a paragraph. Then `sudo` over the forwarded agent closes it.

The CRL timer is worth a sentence: on 2026-10-20 it refreshed the list at
**00:02 UTC, 59 minutes before expiry**, unattended and with no card present,
and the revoked count moved 65 → 66, so it was a real fetch rather than the same
file rewritten.

## Open, and honest about it

| Item | State |
|---|---|
| Stock PuTTY detection, negative side | inferred, not measured; stock PuTTY is not installed here |
| A third-vendor PIV token, end to end | generic path unit-tested, exercised on HID Crescendo; no third vendor |
| `MaxAuthTries` exhaustion as the cause of a refused key | asserted from OpenSSH's documented default; not reproduced |
| `touch-policy ALWAYS` forcing a gesture per `sudo` | asserted from Yubico's documented semantics; needs a card provisioned that way |
| GSSAPI delegation, the positive case | the workstation is not domain-joined, so only the negative was measured |
| Polish prose in the guides and the script catalogue | no native review |
| `pam_ssh_agent_auth` with a third-party key service | reported without a verdict by design |
| `krb5-pkinit`, `includedir`, anchors on this domain | not configured; `doctor` reports it, nothing depends on it |
| `dc02` | unreachable, being deprovisioned, deliberately ignored |

Closed since the last snapshot: the `AutoloadCerts = 1` and `AgentFwd = 0`
branches were exercised against the real registry and restored; the HID
Crescendo path was tested end to end with a second person's certificate; and
both Kerberos verdicts were observed rather than derived — `klist` in an SSH
session and, separately, in a local Wayland session on seat0.

## What a card login does not give you

A Kerberos ticket. `local_auth_policy = enable:smartcard` authenticates
locally and never contacts the KDC; SSH public-key authentication skips the PAM
`auth` stack altogether. A password login does obtain one, which is why tickets
appear to show up "sometimes". `doctor` reports both as INFO, and
`docs/sssd-reference.md` has the table across all four paths.

## Host state, for picking up cold

```
/etc/sssd/sssd.conf          certificate_verification = no_ocsp, crl_file=…
                             local_auth_policy = enable:smartcard
                             ad_gpo_access_control = permissive
                             [certmap/…] any UPN suffix, pinned issuer + EKU
/etc/sudoers.d/90-ad-…       %<group>@<domain> ALL=(ALL:ALL) ALL
/etc/sudoers.d/91-ssh-…      Defaults env_keep += "SSH_AUTH_SOCK"
/etc/pam.d/sudo              pam_ssh_agent_auth.so authorized_keys_command=…
                             backup at /root/pam.d-sudo.20261020-204602.bak
/etc/ssh/sshd_config.d/60-…  AuthorizedKeysCommand sss_ssh_authorizedkeys
debug logging                off; `debug status` confirms
```

`ad_gpo_access_control = permissive` is a **diagnostic, not a destination**:
while it is set, the AD logon rights are not enforced at all. One Group Policy
Container is unreadable by the machine account, which aborts the whole GPO list.
The route back to `enforcing` is `gpo.ignore_unreadable`, with the cost stated —
a skipped GPO's settings are not applied. Granting the machine account read
access on that object in AD is the clean fix.

## What today cost, and what it taught

Four causes produced the identical symptom `Server refused our key`, and three
of them were not the key: an `x509v3-ssh-rsa` offer OpenSSH does not implement,
a certificate that was not on the card, and a username typo. The fourth —
`MaxAuthTries` exhaustion from an over-full agent — is still only reasoned.

Two things I handed over without testing, and both cost time: the sudoers
syntax `%"group@domain"`, which is rejected as `empty group` despite the man
page's grammar, and printing `SSH_AUTH_SOCK` wrapped in brackets, which came
back as a shell assignment and produced a convincing false lead about socket
permissions. The socket's mode was never the problem; `0755` is fine.

Both misleading messages are now written down in `DEPLOY.md` and
`docs/sssd-reference.md`, with the exact text each produces.
