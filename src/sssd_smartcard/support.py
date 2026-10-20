"""Turning diagnostics on, and collecting what they produced.

Every failure in this project was diagnosed the same way: raise ``debug_level``,
reproduce, read the log, put it back.  Doing that by hand on a host that is
already half-configured is how a working ``sssd.conf`` gets broken, and leaving
it raised afterwards is how a disk fills up -- SSSD at level 9 logs the full
base64 of every certificate it reads, on every authentication.

So the raising is a change like any other here: backed up, validated with
``sssctl config-check`` before the service is restarted, and revertible by one
command.  A deadline can be armed as well, because the operator who most needs
debug logging is the one least likely to remember to turn it off.

What the bundle deliberately never contains:

* ``/etc/krb5.keytab`` or any other keytab -- machine credentials,
* anything under ``/var/lib/sss/db`` -- the cache holds credential material
  when ``cache_credentials`` is set,
* private keys of any kind, and
* the values of options whose names say they are secrets.

Certificates *are* included.  They are public, they are the thing being
diagnosed, and a bundle without them cannot answer the question it was made for.
"""

from __future__ import annotations

import io
import re
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

from .util import Check, is_linux, run, which

#: SSSD's own responders. Domain sections are added from the live config, since
#: their names are not known in advance.
SSSD_DEBUG_SECTIONS = ("sssd", "nss", "pam", "ssh", "sudo", "pac", "ifp")

#: 9 is the level that shows the certificate and the matching decision. Lower
#: levels are not worth raising for: they omit exactly the lines that answer
#: "which mechanism ran".
DEBUG_LEVEL = 9

#: A drop-in, so turning sshd's logging back down is deleting one file rather
#: than editing the distribution's config.
SSHD_DROPIN = Path("/etc/ssh/sshd_config.d/99-sssd-smartcard-debug.conf")
SSHD_DROPIN_BODY = (
    "# Written by 'sssd-smartcard debug on'. Remove with 'debug off'.\n"
    "# DEBUG logs the fingerprint of every key offered, which is what makes a\n"
    "# refused key tell you *which* key was refused.\n"
    "LogLevel VERBOSE\n"
)

#: Option names whose values are secrets. Matched on the name, so a value that
#: merely looks like a password is left alone and one in a field called
#: something new is still caught.
SECRET_NAME = re.compile(
    r"^(\s*[A-Za-z0-9_]*(?:authtok|password|passwd|secret|passphrase)"
    r"[A-Za-z0-9_]*\s*=\s*)(.*)$",
    re.IGNORECASE | re.MULTILINE,
)

#: Options whose names match SECRET_NAME but whose values are not secrets.
#: Deliberately a short, explicit list rather than a cleverer pattern: each
#: entry is a documented SSSD boolean, and each is diagnostic.
#: ``krb5_store_password_if_offline`` in particular says whether credentials
#: are cached, which is the reason the cache is on the refuse list below -- a
#: bundle that hid it would hide its own justification.
SECRET_NAME_EXCEPTIONS = frozenset({"krb5_store_password_if_offline"})

#: Never collected, whatever else is asked for.
NEVER_COLLECT = (
    "/etc/krb5.keytab",
    "/var/lib/sss/db",
    "/etc/sssd/pki/*.key",
)

#: Files worth having, in the order someone would read them.
BUNDLE_FILES = (
    "/etc/sssd/sssd.conf",
    "/etc/krb5.conf",
    "/etc/nsswitch.conf",
    "/etc/pam.d/sudo",
    "/etc/pam.d/common-auth",
    "/etc/pam.d/common-session",
    "/etc/pam.d/sshd",
    "/etc/pam.d/gdm-smartcard",
    "/etc/sudoers",
)

#: Commands whose output explains the state the files do not.
BUNDLE_COMMANDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("versions", ("dpkg-query", "-W", "-f=${Package} ${Version}\n",
                  "sssd", "sssd-common", "libsss-sudo", "opensc", "pcscd",
                  "openssh-server", "libpam-ssh-agent-auth")),
    ("sssd-service", ("systemctl", "status", "sssd", "--no-pager")),
    ("sssctl-config-check", ("sssctl", "config-check")),
    ("sssctl-domain-list", ("sssctl", "domain-list")),
    ("sshd-effective", ("sshd", "-T")),
    ("sudo-defaults", ("sudo", "-n", "-l")),
    ("nsswitch-sudoers", ("getent", "sudoers")),
    ("journal-sssd", ("journalctl", "-u", "sssd", "--no-pager", "-n", "2000")),
    ("journal-ssh", ("journalctl", "-u", "ssh", "--no-pager", "-n", "500")),
    ("journal-auth", ("journalctl", "_COMM=sudo", "--no-pager", "-n", "500")),
)

#: Where SSSD writes, and what in there is worth keeping.
SSSD_LOG_DIR = Path("/var/log/sssd")


def redact(text: str) -> str:
    """Replace the value of any option whose name says it is a secret.

    Matched on the name, not the value: a value that merely looks like a
    password is left alone, and one in a field named something this code has
    never heard of is still caught.
    """

    def replace(match: "re.Match[str]") -> str:
        name = match.group(1).split("=", 1)[0].strip().lower()
        if name in SECRET_NAME_EXCEPTIONS:
            return match.group(0)
        return match.group(1) + "<redacted>"

    return SECRET_NAME.sub(replace, text)


def debug_changes(sections: "list[str]", level: int = DEBUG_LEVEL) -> list[tuple[str, str, str]]:
    """``(section, key, value)`` for every section that should log verbosely."""
    return [(section, "debug_level", str(level)) for section in sections]


def sections_to_debug(domain_sections: "list[str]") -> list[str]:
    """Responder sections plus the domains this host actually has."""
    return list(SSSD_DEBUG_SECTIONS) + [f"domain/{name}" for name in domain_sections]


@dataclass
class BundleItem:
    """One thing collected, and whether collecting it worked."""

    name: str
    content: str
    ok: bool = True
    note: str = ""


@dataclass
class Bundle:
    """What was collected, before it is written out."""

    items: list[BundleItem] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    @property
    def size(self) -> int:
        return sum(len(i.content.encode("utf-8", "replace")) for i in self.items)


def collect(
    *,
    files: "tuple[str, ...]" = BUNDLE_FILES,
    commands: "tuple[tuple[str, tuple[str, ...]], ...]" = BUNDLE_COMMANDS,
    log_dir: Path = SSSD_LOG_DIR,
    max_log_bytes: int = 4 * 1024 * 1024,
) -> Bundle:
    """Gather the configuration, the logs and the state, redacting as it goes."""
    bundle = Bundle()

    for name in files:
        path = Path(name)
        if _is_never_collected(name):
            bundle.skipped.append(f"{name} (never collected)")
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            bundle.items.append(
                BundleItem(f"config{name}", "", ok=False, note=str(exc))
            )
            continue
        bundle.items.append(BundleItem(f"config{name}", redact(text)))

    for label, argv in commands:
        result = run(list(argv), timeout=60)
        if not result.found:
            bundle.items.append(
                BundleItem(f"commands/{label}.txt", "", ok=False,
                           note=f"{argv[0]} not installed")
            )
            continue
        header = "$ " + " ".join(argv) + f"\n# exit {result.returncode}\n\n"
        bundle.items.append(
            BundleItem(f"commands/{label}.txt", header + redact(result.output))
        )

    if log_dir.is_dir():
        for log in sorted(log_dir.glob("*.log")):
            try:
                data = log.read_bytes()
            except OSError as exc:
                bundle.items.append(
                    BundleItem(f"logs/{log.name}", "", ok=False, note=str(exc))
                )
                continue
            truncated = ""
            if len(data) > max_log_bytes:
                data = data[-max_log_bytes:]
                truncated = (
                    f"# truncated to the last {max_log_bytes} bytes of "
                    f"{log.name}\n\n"
                )
            bundle.items.append(
                BundleItem(
                    f"logs/{log.name}",
                    truncated + redact(data.decode("utf-8", "replace")),
                )
            )
    else:
        bundle.skipped.append(f"{log_dir} (no such directory)")

    for pattern in NEVER_COLLECT:
        bundle.skipped.append(f"{pattern} (never collected)")

    return bundle


def _is_never_collected(name: str) -> bool:
    """True when *name* is on the refuse list, by glob or by being under it.

    Matched with fnmatch rather than ``startswith`` so a pattern's wildcard can
    sit anywhere -- ``*.key`` is the shape that matters, and an earlier
    prefix-only version let it through.
    """
    from fnmatch import fnmatch

    for pattern in NEVER_COLLECT:
        if fnmatch(name, pattern):
            return True
        # A directory on the list takes everything beneath it with it.
        if name.startswith(pattern.rstrip("/") + "/"):
            return True
    return False


def write_bundle(bundle: Bundle, dest: str | Path) -> Path:
    """Write *bundle* as a tar.gz readable only by its owner.

    Mode first, contents second: a bundle holding an organisation's domain
    names, user names and PAM layout should never exist world-readable, not
    even for the moment between creating and chmod-ing it.
    """
    dest = Path(dest)
    manifest = [
        "sssd-smartcard support bundle",
        "",
        "Collected:",
        *[f"  {'ok  ' if i.ok else 'FAIL'} {i.name}"
          + (f"  -- {i.note}" if i.note else "")
          for i in bundle.items],
        "",
        "Deliberately not collected:",
        *[f"  {s}" for s in bundle.skipped],
        "",
        "Values of options named like secrets are replaced with <redacted>.",
        "Certificates are included: they are public, and they are the subject.",
        "",
    ]
    items = [BundleItem("MANIFEST.txt", "\n".join(manifest))] + list(bundle.items)

    # Created 0600 by os.open rather than opened and chmod-ed afterwards: the
    # second form leaves the file world-readable for as long as it takes to
    # write it, which on a slow disk is not nothing.
    import os

    handle = os.open(str(dest), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    fd = os.fdopen(handle, "wb")
    try:
        with tarfile.open(fileobj=fd, mode="w:gz") as tar:
            for item in items:
                payload = item.content.encode("utf-8", "replace")
                info = tarfile.TarInfo(name=item.name.lstrip("/"))
                info.size = len(payload)
                info.mode = 0o600
                tar.addfile(info, io.BytesIO(payload))
    finally:
        fd.close()
    return dest


def debug_state_checks(config_path: str | Path) -> list[Check]:
    """Report whether verbose logging is on, because leaving it on costs.

    At level 9 SSSD writes the full base64 of every certificate it reads, on
    every authentication.  On a host with real users that fills a disk, and the
    operator who needed the logging is the one who will not remember it.
    """
    from .sssdconf.conf import SssdConfig

    checks: list[Check] = []
    if not is_linux():
        return checks
    try:
        config = SssdConfig.load(config_path)
    except OSError:
        return checks

    raised = []
    for section in config.sections():
        value = config.get(section, "debug_level")
        level = _as_level(value)
        # Below 5 the log does not carry the lines that answer "which mechanism
        # ran", so nobody raises it that far on purpose and it is not worth a
        # warning. SSSD accepts hex as well as decimal.
        if level is not None and level >= 5:
            raised.append(f"{section}={value}")

    if not raised:
        return checks

    detail = ", ".join(sorted(raised))
    checks.append(
        Check(
            "debug logging",
            "WARN",
            f"verbose logging is on: {detail}",
            hint="At level 9 SSSD logs the full certificate on every "
            "authentication, which fills a disk on a host with real users. "
            "Turn it back down with 'sssd-smartcard debug off' once the "
            "mechanism is confirmed.",
        )
    )
    if SSHD_DROPIN.exists():
        checks.append(
            Check("debug logging", "WARN", f"{SSHD_DROPIN} is still in place")
        )
    return checks


def _as_level(value: str | None) -> int | None:
    """``debug_level`` as a number, or None when it is not one.

    SSSD accepts decimal and hexadecimal, so both are read; anything else is
    reported as "not a level" rather than guessed at.
    """
    if not value:
        return None
    try:
        return int(value.strip(), 0)
    except ValueError:
        return None


def sshd_reload_ok() -> tuple[bool, str]:
    """``sshd -t`` before any reload: never leave a service unable to parse."""
    for binary in ("sshd", "/usr/sbin/sshd"):
        if which(binary) or Path(binary).exists():
            result = run([binary, "-t"])
            if result.found:
                return result.ok, result.output.strip()
    return False, "sshd not found"
