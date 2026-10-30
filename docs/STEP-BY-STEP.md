# Step by step: card login on a new Debian 13

Plain instructions, in order. Every command is typed **on the new Debian 13
machine** unless the step says otherwise. Polish version:
[STEP-BY-STEP.pl.md](STEP-BY-STEP.pl.md).

Two ways to get there:

* **Path A — copy a machine that already works.** Fastest. Steps 1–2, then A1–A4.
* **Path B — set it up from scratch.** Steps 1–2, then B1–B6.

Then, for both: step 9 (test) and, if this is a Horizon golden image, step 10.

---

## Where every file goes

| What | Where to put it on the new machine | Who uses it |
|---|---|---|
| `sssd-smartcard_<version>_all.deb` (this tool) | any folder, e.g. `/root/` or `/tmp/` | `apt-get install ./…deb` |
| The capture from the old machine (`*.tar.gz`) | `/root/` | `sssd-smartcard-capture --replay` |
| CA certificates (root and issuing CA, `.pem`) | `/root/pki/` — **only** if the tool cannot download them itself | `sssd-smartcard-setup --ca …` |
| Settings for this machine | `/etc/sssd-smartcard/environment.json` (written for you) | every script |
| Horizon Linux Agent `Omnissa-horizonagent-linux-x86_64-*.tar.gz` | `/opt/vdi-imagemaint/Horizon/` | `vdi-imagemaint.sh agent` (step 10) |
| Horizon Recording Agent `Horizon.Recording.Linux.Agent-*.tar.gz` (optional) | `/opt/vdi-imagemaint/Horizon/` | `vdi-imagemaint.sh recording` |
| CA certificates for True SSO on a Horizon image | `/opt/vdi-imagemaint/certs/` | `vdi-imagemaint.sh domain` |
| Windows helper `sssd-smartcard-windows-<version>.zip` | on the **Windows** PC, any folder | SSH with the card from Windows (step 9) |

Things you **never** copy between machines: `/etc/krb5.keytab`, `/var/lib/sss/`,
private keys. Every machine joins the domain under its own name.

---

## 1. Prepare Debian 13

Log in as `root` (or with `su -`). A fresh Debian has no `curl` and often no `sudo`:

```bash
apt-get update && apt-get install -y curl ca-certificates sudo python3
```

Give the machine its final name now. Changing it after joining the domain causes trouble:

```bash
hostnamectl set-hostname new-host
```

## 2. Install the tool

```bash
VER=0.3.0
cd /root
curl -sSfLO "https://github.com/franekSoftSF/sssd-smartcard-Profile-Manager/releases/download/v$VER/sssd-smartcard_${VER}_all.deb"
curl -sSfLO "https://github.com/franekSoftSF/sssd-smartcard-Profile-Manager/releases/download/v$VER/sssd-smartcard_${VER}_all.deb.sha256"
sha256sum -c "sssd-smartcard_${VER}_all.deb.sha256"
```

It must say `OK`. Then:

```bash
apt-get install -y "./sssd-smartcard_${VER}_all.deb"
sssd-smartcard --version
```

---

## Path A — copy a machine that already works

### A1. Take the configuration from the old machine

Type this on the new machine. Replace `admin@old-host` with your account and the
old machine's name. You will be asked for the SSH password and the `sudo`
password of the old machine:

```bash
cd /root
sssd-smartcard-capture --from admin@old-host --out old-host.tar.gz
```

Nothing is changed on the old machine. Passwords, keytabs and private keys are
never copied.

See what was taken:

```bash
sssd-smartcard-capture --show old-host.tar.gz
```

### A2. First replay: it writes the settings file

```bash
sssd-smartcard-capture --replay old-host.tar.gz
```

It writes `/etc/sssd-smartcard/environment.json` and stops, because this
machine has not joined the domain yet. Open the file and check two lines:

```bash
nano /etc/sssd-smartcard/environment.json
```

* `"hostname"` — the name of **this** machine;
* `"join_user"` — an AD account allowed to join computers to the domain.

### A3. Join the domain

```bash
ad-prepare --yes
sssd-smartcard-setup --only packages,join,identity --yes
```

The first command sets DNS and the host name. The second installs the packages
and joins the domain; it asks for the password of `join_user`.

### A4. Replay again: look first, then apply

Look (nothing is changed):

```bash
sssd-smartcard-capture --replay old-host.tar.gz
```

Open a **second root session** now (another SSH window or console) and leave it
open. If something goes wrong with logging in, you still have that one. Then apply:

```bash
sssd-smartcard-capture --replay old-host.tar.gz --yes --pam
```

At the end there is a list **"Not reproduced automatically — review"**. Each
line shows a file that is different here and the `diff -u` command to compare
it. Read it; copy over only what you understand.

Go to **step 9**.

---

## Path B — set it up from scratch

### B1. Describe the domain once

```bash
ad-prepare --init-env --domain ad.example.com
nano /etc/sssd-smartcard/environment.json
```

Fill in `join_user` (who may join computers) and `test_user` (a user with a card,
e.g. `someone@ad.example.com`). For the full setup also set:

```json
  "crl": true,
  "ssh": true,
  "sudo_group": "linux-admins@ad.example.com",
  "sudo_agent": true,
  "mkhomedir": true,
```

`sudo_group` is an AD group; its members get `sudo`. Leave it `""` if you do not want that.

### B2. DNS, host name, join

```bash
ad-prepare --yes
sssd-smartcard-setup --only packages,join,identity --yes
```

### B3. Put the card in the reader and let the tool find the PKI

```bash
sssd-smartcard ca discover --from-card
```

Compare the printed fingerprints (`SHA-256`) with what your PKI team gives you.
If they match:

```bash
sssd-smartcard ca discover --from-card --install
```

If the tool cannot download the CA certificates, copy them to `/root/pki/` and
add them to the settings file: `"ca": ["/root/pki/root-ca.pem", "/root/pki/issuing-ca.pem"]`.

### B4. Check the user name on the card

```bash
sssd-smartcard cert inspect --from-card
```

Read the `Domain:` line. If it is different from your AD domain, that is
normal (an alternative UPN suffix) — the tool handles it.

### B5. Look at the plan

```bash
sssd-smartcard-setup --dry-run
```

Nothing is changed. Read the stages.

### B6. Apply

Open a **second root session** and leave it open. Then:

```bash
sssd-smartcard-setup --yes --pam
```

This writes `sssd.conf`, the CRL and its daily refresh, SSH with the card, the
`sudo` rule and the PAM settings. Each step checks itself; if one fails,
everything from this run is put back.

---

## 9. Test (both paths)

With the card in the reader. It must ask for a **PIN**, not a password:

```bash
pamtester -v login someone@ad.example.com authenticate acct_mgmt
```

Check everything at once:

```bash
sssd-smartcard doctor --user someone@ad.example.com
```

`sudo` rules for a user (asks you to authenticate, not them):

```bash
sudo -l -U someone@ad.example.com
```

SSH keys the server takes from the card's certificate:

```bash
sss_ssh_authorizedkeys someone@ad.example.com
```

**From Windows:** unpack `sssd-smartcard-windows-<version>.zip`, run the script
in it in PowerShell; it checks PuTTY-CAC and the card and prints the command to
connect. Details: [windows-smartcard-ssh.md](windows-smartcard-ssh.md).

If something does not work, collect a report and send it:

```bash
sssd-smartcard debug bundle
```

---

## 10. Only for a Horizon VDI golden image (VDI-ImageMaint)

The Horizon side is done by the other tool, VDI-ImageMaint, which lives in
`/opt/vdi-imagemaint/`. Order matters:

1. Install VDI-ImageMaint:

   ```bash
   wget -qO- https://github.com/franekSoftSF/horizon-scripts/releases/latest/download/get-vdi-imagemaint.sh | sudo bash
   ```

2. Copy the files (from your PC with WinSCP, or a USB stick):
   * `Omnissa-horizonagent-linux-x86_64-*.tar.gz` → `/opt/vdi-imagemaint/Horizon/`
     (download from Omnissa Customer Connect; Debian 13 needs agent **2606 or newer**);
   * optional `Horizon.Recording.Linux.Agent-*.tar.gz` → `/opt/vdi-imagemaint/Horizon/`;
   * CA certificates for True SSO → `/opt/vdi-imagemaint/certs/`.

   The USB 3.0 driver source (`vhci-hcd-1.15.tar.gz`) is downloaded by the installer.

3. Run VDI-ImageMaint **first** — `prepare`, `domain`, `agent` (see its own
   guide, `docs/linux.md` in horizon-scripts).
4. **Then** run this tool (Path A or B above) for the card rules, CRL, SSH and sudo.
5. Test (step 9), then `vdi-imagemaint.sh seal`.

Two rules:

* `vdi-imagemaint.sh domain` rewrites `sssd.conf`. If you ever run it again,
  run `sssd-smartcard-setup --yes` again afterwards.
* A sealed image refuses package installs. Install or update this tool
  **before** `seal`, or run `vdi-imagemaint.sh unlock` first.

---

## Undo

* Configuration from one run: the backups are in `/var/lib/sssd-smartcard/backups/<date>/`.
* `sudo` and SSH files written by the tool: `/etc/sudoers.d/90-sssd-smartcard-admins`,
  `/etc/sudoers.d/91-sssd-smartcard-ssh-agent`, `/etc/ssh/sshd_config.d/60-sssd-smartcard.conf`.
* Leave the domain completely: `ad-reset --yes`.
