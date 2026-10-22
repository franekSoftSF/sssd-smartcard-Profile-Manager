"""sssd-smartcard-capture: reading a capture, and what a replay makes of it.

The collector is shell (the source host needs nothing installed); the reading
is `scripts/lib/capture.py`, exercised here directly on a fabricated capture
shaped like the lab host in STATUS.md. The collector itself is run at the end,
on Linux only, against a fake root.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CAPTURE_PY = ROOT / "scripts" / "lib" / "capture.py"
CAPTURE_SH = ROOT / "scripts" / "sssd-smartcard-capture.sh"

spec = importlib.util.spec_from_file_location("capture", CAPTURE_PY)
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)  # type: ignore[union-attr]


SSSD_CONF = """\
[sssd]
domains = ad.example.com
config_file_version = 2
services = nss, pam
certificate_verification = no_ocsp, crl_file=/etc/sssd/pki/revocation.crl.pem

[pam]
pam_cert_auth = True
local_auth_policy = enable:smartcard

[domain/ad.example.com]
ad_domain = ad.example.com
krb5_realm = AD.EXAMPLE.COM
ad_hostname = oldhost.ad.example.com
use_fully_qualified_names = True
ad_gpo_access_control = permissive
debug_level = 9

[certmap/ad.example.com/smartcard]
matchrule = <ISSUER>^CN=Example Issuing CA$
maprule = (userPrincipalName={subject_principal})
"""


def make_capture(tmp_path: pathlib.Path, **override: str) -> pathlib.Path:
    files = {
        "/etc/os-release": 'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nID=ubuntu\nVERSION_ID="24.04"\n',
        "/etc/sssd/sssd.conf": SSSD_CONF,
        "/etc/sssd/pki/sssd_auth_ca_db.pem": "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n",
        "/etc/sssd/pki/revocation.crl.pem": "-----BEGIN X509 CRL-----\nAA==\n-----END X509 CRL-----\n",
        "/var/lib/sssd-smartcard/crl-sources.json": '{"CN=Example Issuing CA": "http://pki/x.crl"}\n',
        "/var/lib/sssd-smartcard/effective-profile.yaml": "name: smartcard\n",
        "/etc/systemd/system/sssd-smartcard-crl.timer": "[Timer]\nOnCalendar=daily\n",
        "/etc/pam.d/common-auth": (
            "auth [success=3 default=ignore] pam_sss.so allow_missing_name try_cert_auth\n"
            "auth [success=2 default=ignore] pam_unix.so nullok try_first_pass\n"),
        "/etc/pam.d/common-session": "session optional pam_mkhomedir.so umask=0077\n",
        "/etc/pam.d/sudo": (
            "#%PAM-1.0\n"
            "auth    sufficient  pam_ssh_agent_auth.so authorized_keys_command=/usr/bin/sss_ssh_authorizedkeys\n"
            "@include common-auth\n"),
        "/etc/sudoers": "%sudo ALL=(ALL:ALL) ALL\n",
        "/etc/sudoers.d/90-ad-admins": "%linux-admins@ad.example.com ALL=(ALL:ALL) ALL\n",
        "/etc/sudoers.d/92-more": "%domain\\ admins@ad.example.com ALL=(ALL) ALL\n# %commented ALL=(ALL) ALL\n",
        "/etc/sudoers.d/91-ssh-agent": 'Defaults env_keep += "SSH_AUTH_SOCK"\n',
        "/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n",
        "/etc/ssh/sshd_config.d/60-sssd.conf": (
            "AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys\n"
            "AuthorizedKeysCommandUser nobody\n"),
        "/etc/resolv.conf": "nameserver 10.0.0.10\nsearch ad.example.com\n",
        "/etc/sssd-smartcard/environment.json": json.dumps({
            "domain": "ad.example.com", "hostname": "oldhost", "join_user": "joiner",
            "test_user": "someone@ad.example.com", "role": "server"}),
        "/etc/krb5.conf": "[libdefaults]\n default_realm = AD.EXAMPLE.COM\n",
    }
    files.update(override)
    base = tmp_path / "cap"
    for path, text in files.items():
        target = base / "files" / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    (base / "commands").mkdir()
    (base / "commands" / "realm-list.txt").write_text(
        "ad.example.com\n  realm-name: AD.EXAMPLE.COM\n", encoding="utf-8")
    (base / "commands" / "sssd-version.txt").write_text("2.9.4\n", encoding="utf-8")
    (base / "host.txt").write_text(
        "host=oldhost\nfqdn=oldhost.ad.example.com\ndate=2026-10-20T20:00:00+02:00\nversion=0.3.0\n",
        encoding="utf-8")
    (base / "MANIFEST.txt").write_text(
        "refused /etc/krb5.keytab (never collected)\n", encoding="utf-8")
    return base


@pytest.fixture
def cap(tmp_path):
    return capture.Capture(make_capture(tmp_path))


class TestFacts:
    def test_domain_realm_and_distribution(self, cap):
        f = capture.facts(cap)
        assert f["domain"] == "ad.example.com"
        assert f["realm"] == "AD.EXAMPLE.COM"
        assert f["joined"] is True
        assert f["distro"]["id"] == "ubuntu"

    def test_revocation(self, cap):
        f = capture.facts(cap)
        assert f["crl_file"] == "/etc/sssd/pki/revocation.crl.pem"
        assert f["crl_captured"] and f["crl_sources"] and f["crl_timer"]
        assert f["ca_db_captured"]

    def test_pam_card_mode_and_mkhomedir(self, cap):
        f = capture.facts(cap)
        assert f["pam_card"] == "optional"
        assert f["mkhomedir"] is True
        assert f["local_auth_policy"] == "enable:smartcard"
        assert f["gpo_access_control"] == "permissive"

    def test_required_mode(self, tmp_path):
        c = capture.Capture(make_capture(tmp_path, **{
            "/etc/pam.d/common-auth":
                "auth [success=done default=die] pam_sss.so allow_missing_name require_cert_auth\n"}))
        assert capture.facts(c)["pam_card"] == "required"

    def test_sudo_groups_skip_stock_and_comments_and_unescape(self, cap):
        groups = capture.facts(cap)["sudo_groups"]
        assert groups == ["linux-admins@ad.example.com", "domain admins@ad.example.com"]

    def test_sudo_agent_uses_the_sssd_helper(self, cap):
        f = capture.facts(cap)
        assert f["sudo_agent"] is True
        assert f["sudo_agent_command"] == "/usr/bin/sss_ssh_authorizedkeys"
        assert f["sudo_env_keep_agent"] is True

    def test_ssh_from_the_dropin_when_sshd_T_is_absent(self, cap):
        f = capture.facts(cap)
        assert f["ssh_via_sssd"] is True
        assert f["ssh_akc_file"] == "/etc/ssh/sshd_config.d/60-sssd.conf"

    def test_sshd_T_wins_when_present(self, tmp_path):
        base = make_capture(tmp_path)
        (base / "commands" / "sshd-T.txt").write_text(
            "authorizedkeyscommand none\n", encoding="utf-8")
        f = capture.facts(capture.Capture(base))
        # sshd -T says none, but a file names the command: the file is reported.
        assert f["ssh_akc"] == "/usr/bin/sss_ssh_authorizedkeys"

    def test_profile_prefers_the_effective_one(self, cap):
        assert capture.facts(cap)["profile"].endswith("effective-profile.yaml")

    def test_dns_from_resolvectl_behind_the_stub(self, tmp_path):
        base = make_capture(tmp_path, **{"/etc/resolv.conf": "nameserver 127.0.0.53\n"})
        (base / "commands" / "resolvectl-status.txt").write_text(
            "Link 2 (eth0)\n  DNS Servers: 10.0.0.10 10.0.0.11\n", encoding="utf-8")
        assert capture.facts(capture.Capture(base))["dns"] == ["10.0.0.10", "10.0.0.11"]


class TestReplayInputs:
    def test_environment_takes_this_hosts_name(self, cap):
        env = capture.environment_for(cap, "newhost")
        assert env["hostname"] == "newhost"
        assert env["domain"] == "ad.example.com"
        assert env["join_user"] == "joiner"
        assert env["sudo_group"] == "linux-admins@ad.example.com"
        assert env["ssh"] is True and env["sudo_agent"] is True and env["mkhomedir"] is True
        assert env["ca"] == []

    def test_environment_keys_are_ones_the_loader_accepts(self, cap):
        import re
        text = (ROOT / "scripts" / "lib" / "env.sh").read_text(encoding="utf-8")
        known = set()
        for name in ("ENV_SCALAR_KEYS", "ENV_LIST_KEYS", "ENV_BOOL_KEYS"):
            match = re.search(rf"^{name}=\((.*?)\)", text, re.S | re.M)
            known |= set(match.group(1).split())
        assert set(capture.environment_for(cap, "h")) <= known

    def test_setup_args(self, cap):
        args = capture.setup_args(cap)
        assert args[:2] == ["--skip", "join"]
        assert "--profile" in args and "--ca" in args
        assert args[args.index("--crl-file") + 1] == "/etc/sssd/pki/revocation.crl.pem"
        assert "--ssh" in args and "--sudo-agent" in args and "--mkhomedir" in args
        assert args[args.index("--sudo-group") + 1] == "linux-admins@ad.example.com"
        assert args[args.index("--test-user") + 1] == "someone@ad.example.com"
        assert "--require-smartcard" not in args

    def test_no_crl_is_said_explicitly(self, tmp_path):
        conf = SSSD_CONF.replace(
            "certificate_verification = no_ocsp, crl_file=/etc/sssd/pki/revocation.crl.pem\n", "")
        c = capture.Capture(make_capture(tmp_path, **{"/etc/sssd/sssd.conf": conf}))
        assert "--no-crl" in capture.setup_args(c)

    def test_review_lists_only_what_differs_and_is_not_replayed(self, cap, tmp_path):
        local = tmp_path / "local"
        (local / "etc").mkdir(parents=True)
        (local / "etc" / "krb5.conf").write_text("[libdefaults]\n", encoding="utf-8")
        paths = {i["path"]: i["state"] for i in capture.review(cap, str(local))}
        assert paths["/etc/krb5.conf"] == "differs"
        assert paths["/etc/sudoers.d/92-more"] == "missing here"
        # Reproduced by setup, or host identity: never in the review list.
        for handled in ("/etc/sssd/sssd.conf", "/etc/pam.d/sudo", "/etc/resolv.conf",
                        "/etc/sssd/pki/revocation.crl.pem",
                        "/var/lib/sssd-smartcard/crl-sources.json"):
            assert handled not in paths

    def test_review_is_quiet_when_identical(self, cap, tmp_path):
        local = tmp_path / "local"
        (local / "etc").mkdir(parents=True)
        shutil.copy(cap.file("/etc/krb5.conf"), local / "etc" / "krb5.conf")
        assert "/etc/krb5.conf" not in {i["path"] for i in capture.review(cap, str(local))}


class TestSssdDiff:
    def test_host_specific_and_debug_options_are_left_out(self):
        here = SSSD_CONF.replace("oldhost", "newhost").replace("debug_level = 9\n", "")
        assert capture.sssd_diff(SSSD_CONF, here) == []

    def test_a_real_difference_is_reported(self):
        here = SSSD_CONF.replace("ad_gpo_access_control = permissive",
                                 "ad_gpo_access_control = enforcing")
        diff = capture.sssd_diff(SSSD_CONF, here)
        assert diff == [{"section": "domain/ad.example.com", "key": "ad_gpo_access_control",
                         "captured": "permissive", "here": "enforcing"}]


class TestSummary:
    def test_names_what_matters(self, cap):
        text = capture.summary(cap)
        assert "ad.example.com / AD.EXAMPLE.COM" in text
        assert "linux-admins@ad.example.com" in text
        assert "permissive" in text and "diagnostic" in text
        assert "Several sudo groups" in text
        assert "/etc/krb5.keytab" in text  # the refused list is shown
        assert "--replay" in text


# ---------------------------------------------------------------------------
# The collector, end to end, on a fake root (Linux: GNU tools, sha256sum)
# ---------------------------------------------------------------------------
linux_only = pytest.mark.skipif(
    sys.platform != "linux" or shutil.which("bash") is None,
    reason="the collector is exercised on Linux")


@linux_only
class TestCollector:
    def run(self, *args, cwd):
        return subprocess.run(["bash", str(CAPTURE_SH), *args], cwd=cwd,
                              capture_output=True, text=True, check=False,
                              env={**os.environ, "NO_COLOR": "1"})

    def fake_root(self, tmp_path) -> pathlib.Path:
        root = tmp_path / "root"
        for path, text in {
            "etc/sssd/sssd.conf": SSSD_CONF + "ldap_default_authtok = hunter2\n"
                                  "krb5_store_password_if_offline = True\n",
            "etc/krb5.keytab": "SECRET KEYTAB",
            "etc/sssd/pki/sssd_auth_ca_db.pem": "CERT\n",
            "etc/sssd/pki/host.key": "PRIVATE",
            "etc/sudoers.d/90-ad-admins": "%linux-admins@ad.example.com ALL=(ALL:ALL) ALL\n",
            "etc/os-release": "ID=debian\nVERSION_ID=13\n",
        }.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        return root

    def test_collects_redacts_and_refuses(self, tmp_path):
        root = self.fake_root(tmp_path)
        out = tmp_path / "c.tar.gz"
        result = self.run("--local", "--root", str(root), "--out", str(out), cwd=tmp_path)
        assert result.returncode == 0, result.stdout + result.stderr
        with tarfile.open(out) as tar:
            names = tar.getnames()
            conf = tar.extractfile(next(n for n in names if n.endswith("etc/sssd/sssd.conf"))).read().decode()
        assert not any(n.endswith("krb5.keytab") for n in names)
        assert not any(n.endswith(".key") for n in names)
        assert "hunter2" not in conf
        assert "ldap_default_authtok = <removed by sssd-smartcard-capture>" in conf
        assert "krb5_store_password_if_offline = True" in conf
        assert any(n.endswith("sudoers.d/90-ad-admins") for n in names)

    def test_show_verifies_the_manifest(self, tmp_path):
        root = self.fake_root(tmp_path)
        out = tmp_path / "c.tar.gz"
        assert self.run("--local", "--root", str(root), "--out", str(out), cwd=tmp_path).returncode == 0
        shown = self.run("--show", str(out), cwd=tmp_path)
        assert shown.returncode == 0, shown.stderr
        assert "verified against its manifest" in shown.stdout
        assert "ad.example.com" in shown.stdout

    def test_a_changed_capture_is_refused(self, tmp_path):
        root = self.fake_root(tmp_path)
        out = tmp_path / "c.tar.gz"
        assert self.run("--local", "--root", str(root), "--out", str(out), cwd=tmp_path).returncode == 0
        unpacked = tmp_path / "u"
        with tarfile.open(out) as tar:
            tar.extractall(unpacked)
        capdir = next(unpacked.iterdir())
        (capdir / "files" / "etc" / "sudoers.d" / "90-ad-admins").write_text("ALL ALL=(ALL) NOPASSWD: ALL\n")
        shown = self.run("--show", str(capdir), cwd=tmp_path)
        assert shown.returncode != 0
        assert "do not match MANIFEST" in shown.stderr
