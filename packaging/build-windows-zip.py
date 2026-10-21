#!/usr/bin/env python3
"""Build the Windows-side archive: the helper script and its guide.

Why this exists separately from the .deb and the tarball: the person who needs
these two files runs Windows and has no use for a Debian package, and the
tarball is the whole project. Making them download either to get a PowerShell
script and a PDF is the kind of friction that ends with someone emailing the
script around instead.

The archive is deliberately small and flat -- unzip, read the PDF, run the
script. No installer, nothing to put on PATH, nothing to elevate.

Usage:
    python packaging/build-windows-zip.py
"""

from __future__ import annotations

import hashlib
import pathlib
import re
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"

#: (source, name inside the archive). Flat on purpose.
CONTENTS = [
    ("scripts/windows/New-SmartCardSshCommand.ps1", "New-SmartCardSshCommand.ps1"),
    ("docs/windows-smartcard-ssh.pdf", "windows-smartcard-ssh.pdf"),
    ("docs/windows-smartcard-ssh.pl.pdf", "windows-smartcard-ssh.pl.pdf"),
]

README = """sssd-smartcard -- Windows client helper, version {version}
{rule}

What is in here

  New-SmartCardSshCommand.ps1      Checks this workstation and prints the PuTTY
                                   command for SSH login with a PIV smart card.
  windows-smartcard-ssh.pdf        The same material as a guide, with the traps
                                   that cost us the most time written out.
  windows-smartcard-ssh.pl.pdf     The Polish version of that guide.

  The script speaks Polish too: add -Language pl.

Running it

  powershell -ExecutionPolicy Bypass -File New-SmartCardSshCommand.ps1 ^
      -User someone@ad.example.com -ComputerName linux-host.ad.example.com

  Read-only by default: it launches nothing, downloads nothing, installs
  nothing and changes nothing. The checks need no administrator rights.

  Add -ForwardAgent if sudo on the far end should be able to use the card.
  Add -Launch to apply what the checks found and then connect; it still
  refuses to install software, and stops before connecting if something has
  to be installed first.

  Get-Help .\\New-SmartCardSshCommand.ps1 -Full

What the server side needs

  Nothing copied to it. SSSD derives the SSH public key from the certificate
  in Active Directory and sshd fetches it through AuthorizedKeysCommand, so
  revoking the certificate revokes SSH access as well. The Linux side is the
  sssd-smartcard package, released alongside this archive.

Three traps, each of which produces a misleading message

  * ssh.exe from System32 accepts -I and silently ignores it. Microsoft's
    build has PKCS#11 compiled out, so the card is simply never used and it
    looks like a server problem. Use PuTTY-CAC.

  * PuTTY-CAC offers an X.509 certificate until -x509off is set. OpenSSH
    does not implement x509v3-ssh-rsa and refuses with "unsupported public
    key algorithm", which the client reports only as "Server refused our
    key" -- the same words as every other cause.

  * The certificate thumbprint must come from the card, not from the Windows
    certificate store. A store entry whose key container no longer exists
    produces "the smart card cannot perform the requested operation or the
    operation requires a different smart card", which is literally true: the
    key being asked for is not on that card.

  The script checks all three.

Source and issues

  https://github.com/franekSoftSF/sssd-smartcard-Profile-Manager
"""


def version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([0-9][^"]*)"$', text, re.MULTILINE)
    if not match:
        raise SystemExit("no version in pyproject.toml")
    return match.group(1)


def main() -> int:
    ver = version()
    missing = [src for src, _ in CONTENTS if not (ROOT / src).is_file()]
    if missing:
        # The PDF is generated, so a clean checkout can legitimately lack it.
        print("missing: " + ", ".join(missing), file=sys.stderr)
        print("build it first: python packaging/build-windows-guide.py", file=sys.stderr)
        return 1

    DIST.mkdir(exist_ok=True)
    dest = DIST / f"sssd-smartcard-windows-{ver}.zip"

    readme = README.format(version=ver, rule="=" * (len(ver) + 44))

    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for src, name in CONTENTS:
            zf.write(ROOT / src, name)
            print(f"  added {name}")
        # CRLF, because this is read in Notepad as often as not.
        zf.writestr("README.txt", readme.replace("\n", "\r\n"))
        print("  added README.txt")

    digest = hashlib.sha256(dest.read_bytes()).hexdigest()
    (dest.parent / (dest.name + ".sha256")).write_text(
        f"{digest}  {dest.name}\n", encoding="utf-8", newline="\n"
    )

    print(f"\nbuilt {dest} ({dest.stat().st_size} bytes)")
    print(f"sha256 {digest}")

    # A zip that does not contain the script is worse than no zip: it looks
    # like a release and delivers nothing.
    with zipfile.ZipFile(dest) as zf:
        names = set(zf.namelist())
    expected = {name for _, name in CONTENTS} | {"README.txt"}
    if names != expected:
        print(f"\nunexpected contents: {sorted(names)}", file=sys.stderr)
        return 1
    print("verified: archive holds exactly " + ", ".join(sorted(expected)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
