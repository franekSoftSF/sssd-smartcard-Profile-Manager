#!/usr/bin/env python3
"""Read a configuration capture made by `sssd-smartcard-capture`.

The capture itself is collected by the shell script, with nothing but bash and
coreutils, so that the machine being captured needs nothing installed. Making
sense of it -- which domain, which PAM mode, which sudo groups, what replaying
it on another host would take -- happens here, where it can be tested.

A capture directory looks like this:

    files/<absolute path>     copies of the configuration files
    commands/<name>.txt       output of read-only commands (sshd -T, realm list)
    MANIFEST.txt              sha256 of every file, and what was refused
    host.txt                  key=value: host name, date, capture version

Usage:
    capture.py facts   DIR                    JSON facts
    capture.py summary DIR                    Markdown summary
    capture.py env     DIR HOSTNAME           environment.json for this host
    capture.py setup-args DIR                 sssd-smartcard-setup arguments
    capture.py review  DIR [ROOT]             captured files that differ here
    capture.py sssd-diff CAPTURED CURRENT     key-level sssd.conf differences
"""

from __future__ import annotations

import configparser
import json
import re
import sys
from pathlib import Path

DEFAULT_CA_DB = "/etc/sssd/pki/sssd_auth_ca_db.pem"
DEFAULT_CRL_FILE = "/etc/sssd/pki/revocation.crl.pem"
STATE_DIR = "/var/lib/sssd-smartcard"

#: sssd.conf options that describe THIS machine, not the configuration: copying
#: them to another host would be wrong, so a diff leaves them out.
HOST_SPECIFIC_KEYS = frozenset({
    "ad_hostname", "ad_server", "ad_backup_server", "ad_site", "krb5_keytab",
    "ldap_sasl_authid", "ipa_hostname", "dyndns_iface",
})

#: Diagnostics state is not configuration: it is turned on and off with
#: `sssd-smartcard debug`, never carried to a new host.
DEBUG_KEY = re.compile(r"^debug(_.*)?$")

#: sudo groups every distribution ships; not something anyone configured.
STOCK_SUDO_GROUPS = frozenset({"sudo", "admin", "wheel", "root"})

#: Files a replay reproduces through sssd-smartcard-setup, or that describe the
#: old host's identity (ad-prepare and realm join write those on the new one).
#: Everything else captured is listed for review when it differs here.
NOT_FOR_REVIEW = (
    "/etc/os-release", "/etc/hostname", "/etc/hosts", "/etc/resolv.conf",
    "/etc/nsswitch.conf", "/etc/sssd/sssd.conf", "/etc/sudoers",
    "/etc/ssh/sshd_config", "/etc/pam.d/sudo", "/etc/pam.d/common-auth",
    "/etc/pam.d/common-account", "/etc/pam.d/common-session",
    "/etc/pam.d/common-session-noninteractive", "/etc/pam.d/common-password",
    "/etc/sssd-smartcard/", "/var/lib/sssd-smartcard/", "/etc/sssd/pki/",
    "/etc/systemd/system/sssd-smartcard-crl.",
    "/etc/ssh/sshd_config.d/99-sssd-smartcard-debug.conf",
)


# ---------------------------------------------------------------------------
# Reading the capture
# ---------------------------------------------------------------------------
class Capture:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        if not (self.root / "files").is_dir():
            raise SystemExit(f"{self.root}: not a capture (no files/ directory)")

    def file(self, path: str) -> Path:
        return self.root / "files" / path.lstrip("/")

    def text(self, path: str) -> str:
        try:
            return self.file(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def has(self, path: str) -> bool:
        return self.file(path).is_file()

    def command(self, name: str) -> str:
        try:
            return (self.root / "commands" / f"{name}.txt").read_text(
                encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def host(self) -> dict[str, str]:
        out: dict[str, str] = {}
        try:
            text = (self.root / "host.txt").read_text(encoding="utf-8", errors="replace")
        except OSError:
            return out
        for line in text.splitlines():
            key, sep, value = line.partition("=")
            if sep:
                out[key.strip()] = value.strip()
        return out

    def captured_paths(self) -> list[str]:
        base = self.root / "files"
        return sorted("/" + p.relative_to(base).as_posix()
                      for p in base.rglob("*") if p.is_file())

    def glob_text(self, directory: str, pattern: str = "*") -> list[tuple[str, str]]:
        base = self.file(directory)
        if not base.is_dir():
            return []
        return [(f"{directory.rstrip('/')}/{p.name}",
                 p.read_text(encoding="utf-8", errors="replace"))
                for p in sorted(base.glob(pattern)) if p.is_file()]


def parse_ini(text: str) -> configparser.RawConfigParser:
    parser = configparser.RawConfigParser(
        strict=False, delimiters=("=",), comment_prefixes=("#", ";"),
        inline_comment_prefixes=None, interpolation=None,
    )
    parser.optionxform = str  # type: ignore[assignment]
    try:
        parser.read_string(text)
    except configparser.Error:
        pass
    return parser


def os_release(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def _option(text: str, name: str) -> str | None:
    """`name=value` inside a comma-separated option such as certificate_verification."""
    for part in text.split(","):
        key, sep, value = part.strip().partition("=")
        if sep and key.strip() == name:
            return value.strip()
    return None


def _uncommented(text: str) -> list[str]:
    return [line for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def sudo_groups(texts: list[str]) -> list[str]:
    """Group names granted something in sudoers, %name or %name@domain."""
    groups: list[str] = []
    for text in texts:
        for line in _uncommented(text):
            line = line.strip()
            if not line.startswith("%") or line.startswith("%#"):
                continue
            # A name may contain escaped spaces ('\ '); the rule starts at the
            # first unescaped whitespace.
            match = re.match(r"%((?:\\.|[^\s\\])+)", line)
            if not match:
                continue
            name = match.group(1).replace("\\ ", " ").strip('"')
            if name not in STOCK_SUDO_GROUPS and name not in groups:
                groups.append(name)
    return groups


def pam_card_mode(text: str) -> str:
    lines = [l for l in _uncommented(text) if "pam_sss.so" in l]
    if any("require_cert_auth" in l for l in lines):
        return "required"
    if any("try_cert_auth" in l for l in lines):
        return "optional"
    return "none"


# ---------------------------------------------------------------------------
# Facts
# ---------------------------------------------------------------------------
def facts(cap: Capture) -> dict:
    host = cap.host()
    release = os_release(cap.text("/etc/os-release"))
    conf = parse_ini(cap.text("/etc/sssd/sssd.conf"))

    domains: list[str] = []
    if conf.has_section("sssd"):
        domains = [d.strip() for d in conf.get("sssd", "domains", fallback="").split(",")
                   if d.strip()]
    domain = domains[0] if domains else ""
    dsec = f"domain/{domain}"
    realm = ""
    if conf.has_section(dsec):
        realm = conf.get(dsec, "krb5_realm", fallback="") or ""
    if not realm:
        realm_list = cap.command("realm-list")
        match = re.search(r"^\s*realm-name:\s*(\S+)", realm_list, re.M)
        realm = match.group(1) if match else domain.upper()

    ca_db = conf.get("pam", "pam_cert_db_path", fallback=None) if conf.has_section("pam") else None
    ca_db = ca_db or DEFAULT_CA_DB
    verification = conf.get("sssd", "certificate_verification", fallback="") \
        if conf.has_section("sssd") else ""
    crl_file = _option(verification or "", "crl_file")

    common_auth = cap.text("/etc/pam.d/common-auth") or cap.text("/etc/pam.d/system-auth")
    common_session = cap.text("/etc/pam.d/common-session") or cap.text("/etc/pam.d/system-auth")
    pam_sudo = cap.text("/etc/pam.d/sudo")
    agent_lines = [l for l in _uncommented(pam_sudo) if "pam_ssh_agent_auth.so" in l]
    agent_command = None
    for line in agent_lines:
        match = re.search(r"authorized_keys_command=(\S+)", line)
        if match:
            agent_command = match.group(1)

    sudoers = [cap.text("/etc/sudoers")] + [t for _, t in cap.glob_text("/etc/sudoers.d")]
    env_keep_agent = any(re.search(r"env_keep\s*\+?=.*SSH_AUTH_SOCK", t) for t in sudoers)

    sshd_t = cap.command("sshd-T")
    ssh_akc = None
    match = re.search(r"^authorizedkeyscommand\s+(\S+)", sshd_t, re.M)
    if match and match.group(1) != "none":
        ssh_akc = match.group(1)
    ssh_file = None
    for path, text in [("/etc/ssh/sshd_config", cap.text("/etc/ssh/sshd_config"))] + \
            cap.glob_text("/etc/ssh/sshd_config.d"):
        found = re.search(r"^\s*AuthorizedKeysCommand\s+(\S+)", text, re.M | re.I)
        if found:
            ssh_file = path
            ssh_akc = ssh_akc or found.group(1)
            break

    resolv = cap.text("/etc/resolv.conf")
    dns = re.findall(r"^\s*nameserver\s+(\S+)", resolv, re.M)
    search: list[str] = []
    for match in re.finditer(r"^\s*(?:search|domain)\s+(.+)$", resolv, re.M):
        search += [s for s in match.group(1).split() if s not in search]
    # systemd-resolved: resolv.conf names the stub; the real servers are in resolvectl.
    if dns == ["127.0.0.53"] or not dns:
        found = re.findall(r"DNS Servers?:\s*(.+)", cap.command("resolvectl-status"))
        servers = [s for line in found for s in line.split()]
        if servers:
            dns = list(dict.fromkeys(servers))

    profile = None
    for name in ("effective-profile.yaml", "generated-profile.yaml"):
        if cap.has(f"{STATE_DIR}/{name}"):
            profile = f"{STATE_DIR}/{name}"
            break

    env_path = "/etc/sssd-smartcard/environment.json"
    environment = None
    if cap.has(env_path):
        try:
            environment = json.loads(cap.text(env_path))
        except ValueError:
            environment = None

    pam_section = dict(conf.items("pam")) if conf.has_section("pam") else {}
    dom_items = dict(conf.items(dsec)) if conf.has_section(dsec) else {}

    return {
        "host": host.get("host", ""),
        "fqdn": host.get("fqdn", ""),
        "captured_at": host.get("date", ""),
        "capture_version": host.get("version", ""),
        "distro": {
            "id": release.get("ID", ""),
            "version_id": release.get("VERSION_ID", ""),
            "pretty_name": release.get("PRETTY_NAME", ""),
        },
        "sssd_version": cap.command("sssd-version").strip(),
        "tool_version": cap.command("sssd-smartcard-version").strip(),
        "domain": domain,
        "domains": domains,
        "realm": realm,
        "joined": bool(cap.command("realm-list").strip()),
        "dns": dns,
        "search": search,
        "ca_db": ca_db,
        "ca_db_captured": cap.has(ca_db),
        "certificate_verification": verification,
        "crl_file": crl_file,
        "crl_captured": bool(crl_file and cap.has(crl_file)),
        "crl_sources": cap.has(f"{STATE_DIR}/crl-sources.json"),
        "crl_timer": cap.has("/etc/systemd/system/sssd-smartcard-crl.timer"),
        "local_auth_policy": pam_section.get("local_auth_policy"),
        "pam_cert_auth": pam_section.get("pam_cert_auth"),
        "gpo_access_control": dom_items.get("ad_gpo_access_control"),
        "use_fully_qualified_names": dom_items.get("use_fully_qualified_names"),
        "certmap_sections": [s for s in conf.sections() if s.startswith("certmap/")],
        "profile": profile,
        "environment": environment,
        "pam_card": pam_card_mode(common_auth),
        "mkhomedir": "pam_mkhomedir.so" in "\n".join(_uncommented(common_session)),
        "ssh_akc": ssh_akc,
        "ssh_akc_file": ssh_file,
        "ssh_via_sssd": bool(ssh_akc and ssh_akc.endswith("sss_ssh_authorizedkeys")),
        "sudo_groups": sudo_groups(sudoers),
        "sudo_agent": bool(agent_lines),
        "sudo_agent_command": agent_command,
        "sudo_env_keep_agent": env_keep_agent,
        "refused": [l for l in (cap.root / "MANIFEST.txt").read_text(
            encoding="utf-8", errors="replace").splitlines() if l.startswith("refused ")]
        if (cap.root / "MANIFEST.txt").is_file() else [],
    }


# ---------------------------------------------------------------------------
# What a replay does with it
# ---------------------------------------------------------------------------
def environment_for(cap: Capture, hostname: str) -> dict:
    """An environment.json for the NEW host, from the old host's capture.

    The host name is this machine's: copying the old one would make the join
    take over the old machine's account in AD (a KVNO mismatch later).
    """
    f = facts(cap)
    base = dict(f["environment"] or {})
    base["domain"] = base.get("domain") or f["domain"]
    if f["realm"]:
        base["realm"] = base.get("realm") or f["realm"]
    if f["dns"] and not base.get("dns"):
        base["dns"] = f["dns"]
    if f["search"] and not base.get("search"):
        base["search"] = f["search"]
    base["hostname"] = hostname
    base.setdefault("crl", bool(f["crl_file"]))
    base["ssh"] = f["ssh_via_sssd"]
    base["sudo_agent"] = f["sudo_agent"]
    base["mkhomedir"] = f["mkhomedir"]
    base["smartcard_required"] = f["pam_card"] == "required"
    if f["sudo_groups"]:
        base["sudo_group"] = f["sudo_groups"][0]
    # The CA files are carried in the capture and passed to setup explicitly.
    base["ca"] = []
    note = f"from a capture of {f['host'] or 'another host'}"
    if f["captured_at"]:
        note += f" ({f['captured_at']})"
    base["notes"] = note
    return base


def setup_args(cap: Capture) -> list[str]:
    """Arguments for sssd-smartcard-setup that reproduce the capture.

    The join is not reproduced: the new host joins with its own name and
    account (ad-prepare, then setup --only packages,join,identity).
    """
    f = facts(cap)
    args = ["--skip", "join"]
    if f["profile"]:
        args += ["--profile", str(cap.file(f["profile"]))]
    if f["ca_db_captured"]:
        args += ["--ca", str(cap.file(f["ca_db"]))]
    if f["crl_file"]:
        args += ["--crl", "--crl-file", f["crl_file"]]
    else:
        args += ["--no-crl"]
    if f["ssh_via_sssd"]:
        args += ["--ssh"]
    if f["sudo_groups"]:
        args += ["--sudo-group", f["sudo_groups"][0]]
    if f["sudo_agent"]:
        args += ["--sudo-agent"]
    if f["mkhomedir"]:
        args += ["--mkhomedir"]
    if f["pam_card"] == "required":
        args += ["--require-smartcard"]
    env = f["environment"] or {}
    if env.get("test_user"):
        args += ["--test-user", str(env["test_user"])]
    return args


def review(cap: Capture, root: str = "/") -> list[dict]:
    """Captured files a replay does not reproduce and that differ on this host."""
    out = []
    for path in cap.captured_paths():
        if any(path == p or (p.endswith(("/", ".")) and path.startswith(p))
               for p in NOT_FOR_REVIEW):
            continue
        local = Path(root) / path.lstrip("/")
        captured = cap.file(path)
        if not local.is_file():
            state = "missing here"
        else:
            try:
                same = local.read_bytes() == captured.read_bytes()
            except OSError:
                same = False
            if same:
                continue
            state = "differs"
        out.append({"path": path, "state": state, "captured": str(captured)})
    return out


def sssd_diff(captured_text: str, current_text: str) -> list[dict]:
    """Key-level differences, without host-specific and debug options."""
    old, new = parse_ini(captured_text), parse_ini(current_text)
    out = []
    for section in sorted(set(old.sections()) | set(new.sections())):
        o = dict(old.items(section)) if old.has_section(section) else {}
        n = dict(new.items(section)) if new.has_section(section) else {}
        for key in sorted(set(o) | set(n)):
            if key in HOST_SPECIFIC_KEYS or DEBUG_KEY.match(key):
                continue
            if o.get(key) != n.get(key):
                out.append({"section": section, "key": key,
                            "captured": o.get(key), "here": n.get(key)})
    return out


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
def summary(cap: Capture) -> str:
    f = facts(cap)
    yes = lambda b: "yes" if b else "no"  # noqa: E731
    lines = [
        f"# Capture of {f['fqdn'] or f['host'] or 'unknown host'}",
        "",
        f"Captured {f['captured_at'] or '?'} by sssd-smartcard-capture {f['capture_version'] or '?'}.",
        "",
        "| | |",
        "|---|---|",
        f"| System | {f['distro']['pretty_name'] or '?'} |",
        f"| SSSD | {f['sssd_version'] or '?'} |",
        f"| sssd-smartcard | {f['tool_version'] or 'not installed'} |",
        f"| Domain / realm | {f['domain'] or '?'} / {f['realm'] or '?'} |",
        f"| DNS | {', '.join(f['dns']) or '?'} |",
        f"| CA bundle | {f['ca_db']} ({'captured' if f['ca_db_captured'] else 'NOT captured'}) |",
        f"| certificate_verification | `{f['certificate_verification'] or '(default: OCSP)'}` |",
        f"| CRL file | {f['crl_file'] or '-'}"
        f"{' (captured)' if f['crl_captured'] else ''}; remembered URLs: {yes(f['crl_sources'])}; "
        f"timer: {yes(f['crl_timer'])} |",
        f"| certmap rules | {', '.join(f['certmap_sections']) or '-'} |",
        f"| local_auth_policy | {f['local_auth_policy'] or '(default)'} |",
        f"| ad_gpo_access_control | {f['gpo_access_control'] or '(default: enforcing)'} |",
        f"| Card in PAM | {f['pam_card']}; mkhomedir: {yes(f['mkhomedir'])} |",
        f"| SSH keys | {f['ssh_akc'] or 'no AuthorizedKeysCommand'}"
        f"{' (' + f['ssh_akc_file'] + ')' if f['ssh_akc_file'] else ''} |",
        f"| sudo groups | {', '.join(f['sudo_groups']) or '-'} |",
        f"| sudo over SSH (agent) | {yes(f['sudo_agent'])}"
        f"{', keys from ' + f['sudo_agent_command'] if f['sudo_agent_command'] else ''}; "
        f"env_keep SSH_AUTH_SOCK: {yes(f['sudo_env_keep_agent'])} |",
        f"| Profile | {f['profile'] or 'none (setup derives one from the card)'} |",
        "",
    ]
    if f["gpo_access_control"] == "permissive":
        lines += ["**ad_gpo_access_control = permissive** is a diagnostic: AD logon rights "
                  "are not enforced while it is set. The profile carries it to the new host.", ""]
    if f["sudo_agent"] and not f["sudo_agent_command"]:
        lines += ["**pam_ssh_agent_auth reads a key file**, which outlives revoking the "
                  "certificate; the replay uses authorized_keys_command instead.", ""]
    if len(f["sudo_groups"]) > 1:
        lines += [f"Several sudo groups; the replay writes the first ({f['sudo_groups'][0]}). "
                  "The others are in the review list.", ""]
    lines += ["## Replay on a new host", "", "```"]
    lines += ["sudo sssd-smartcard-capture --replay <capture>            # plan, changes nothing",
              "sudo sssd-smartcard-capture --replay <capture> --yes      # apply",
              "sudo sssd-smartcard-capture --replay <capture> --yes --pam"]
    lines += ["```", "", "Setup arguments: `" + " ".join(setup_args(cap)) + "`", ""]
    if f["refused"]:
        lines += ["## Never collected", ""] + [f"- {r[len('refused '):]}" for r in f["refused"]] + [""]
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    cmd = argv[1]
    if cmd == "sssd-diff":
        if len(argv) != 4:
            return 2
        captured = Path(argv[2]).read_text(encoding="utf-8", errors="replace")
        try:
            current = Path(argv[3]).read_text(encoding="utf-8", errors="replace")
        except OSError:
            current = ""
        for d in sssd_diff(captured, current):
            print(f"[{d['section']}] {d['key']}: captured={d['captured']!s}  here={d['here']!s}")
        return 0
    cap = Capture(argv[2])
    if cmd == "facts":
        print(json.dumps(facts(cap), indent=2, ensure_ascii=False))
    elif cmd == "summary":
        print(summary(cap))
    elif cmd == "env":
        if len(argv) != 4:
            return 2
        print(json.dumps(environment_for(cap, argv[3]), indent=2, ensure_ascii=False))
    elif cmd == "setup-args":
        print("\n".join(setup_args(cap)))
    elif cmd == "review":
        for item in review(cap, argv[3] if len(argv) > 3 else "/"):
            print(f"{item['state']}\t{item['path']}\t{item['captured']}")
    else:
        print(f"unknown command: {cmd}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
