"""Turning diagnostics on, and collecting what they produced.

Every failure in this project was found the same way: raise `debug_level`,
reproduce, read the log, put it back. Two things make that risky to do by hand
on a host that is already half-configured, and both are what this covers.

**Leaving it on costs.** At level 9 SSSD writes the full base64 of every
certificate it reads, on every authentication - measured, the lines are in this
project's own transcripts. On a host with real users that fills a disk, and the
operator who needed the logging is the one who will not remember it.

**A bundle is sent somewhere.** So what it must never contain matters more than
what it does: no keytab, no SSSD cache (it holds credential material when
`cache_credentials` is set), no private keys, and no values of options whose
names say they are secrets. Certificates *are* included - they are public, and a
bundle without them cannot answer the question it was made for.
"""

from __future__ import annotations

import os
import tarfile

import pytest

from sssd_smartcard import support
from sssd_smartcard.util import CommandResult

SECRETS = """[domain/ad.example.com]
id_provider = ad
ldap_default_authtok = hunter2
ldap_default_bind_dn = CN=svc,DC=ad,DC=example,DC=com
krb5_store_password_if_offline = True
some_password = letmein
MY_SECRET_VALUE = abc123
ldap_uri = ldaps://dc.ad.example.com
"""


class TestRedaction:
    def test_secret_values_are_replaced(self):
        out = support.redact(SECRETS)
        assert "hunter2" not in out
        assert "letmein" not in out
        assert "abc123" not in out

    def test_the_option_names_survive(self):
        """Knowing an option is set is diagnostic; its value is not."""
        out = support.redact(SECRETS)
        assert "ldap_default_authtok = <redacted>" in out
        assert "some_password = <redacted>" in out

    def test_non_secrets_are_untouched(self):
        out = support.redact(SECRETS)
        assert "ldap_uri = ldaps://dc.ad.example.com" in out
        assert "CN=svc,DC=ad,DC=example,DC=com" in out
        # Named for storing a password, but a boolean -- and diagnostic.
        assert "krb5_store_password_if_offline = True" in out

    def test_matching_is_on_the_name_not_the_value(self):
        """A value that looks like a secret in a field that is not one stays."""
        out = support.redact("comment = the password is on the whiteboard\n")
        assert "whiteboard" in out

    def test_case_is_ignored(self):
        assert "<redacted>" in support.redact("LDAP_DEFAULT_AUTHTOK = x\n")


class TestWhatIsNeverCollected:
    @pytest.mark.parametrize(
        "path",
        [
            "/etc/krb5.keytab",
            "/var/lib/sss/db",
            "/var/lib/sss/db/cache_ad.example.com.ldb",
            "/etc/sssd/pki/private.key",
        ],
    )
    def test_refused_outright(self, path):
        assert support._is_never_collected(path) is True

    @pytest.mark.parametrize(
        "path", ["/etc/sssd/sssd.conf", "/etc/krb5.conf", "/etc/sssd/pki/ca.pem"]
    )
    def test_ordinary_configuration_is_collected(self, path):
        assert support._is_never_collected(path) is False

    def test_the_keytab_is_refused_even_if_listed(self, tmp_path, monkeypatch):
        """Belt and braces: a caller passing it in is still refused."""
        monkeypatch.setattr(support, "run", lambda *a, **k: CommandResult(
            list(a[0]), 0, "", "", found=False))
        bundle = support.collect(
            files=("/etc/krb5.keytab",), commands=(), log_dir=tmp_path / "absent"
        )
        assert bundle.items == []
        assert any("krb5.keytab" in s for s in bundle.skipped)


class TestCollecting:
    def test_a_missing_file_is_recorded_not_fatal(self, tmp_path, monkeypatch):
        monkeypatch.setattr(support, "run", lambda *a, **k: CommandResult(
            list(a[0]), 0, "", "", found=False))
        bundle = support.collect(
            files=(str(tmp_path / "absent.conf"),), commands=(),
            log_dir=tmp_path / "nologs",
        )
        assert len(bundle.items) == 1
        assert bundle.items[0].ok is False

    def test_file_contents_are_redacted_on_the_way_in(self, tmp_path, monkeypatch):
        conf = tmp_path / "sssd.conf"
        conf.write_text(SECRETS, encoding="utf-8")
        monkeypatch.setattr(support, "run", lambda *a, **k: CommandResult(
            list(a[0]), 0, "", "", found=False))
        bundle = support.collect(
            files=(str(conf),), commands=(), log_dir=tmp_path / "nologs"
        )
        assert "hunter2" not in bundle.items[0].content

    def test_command_output_is_redacted_too(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            support, "run",
            lambda *a, **k: CommandResult(list(a[0]), 0, "ldap_default_authtok = hunter2\n", ""),
        )
        bundle = support.collect(
            files=(), commands=(("x", ("echo",)),), log_dir=tmp_path / "nologs"
        )
        assert "hunter2" not in bundle.items[0].content
        # The command that produced it is kept, so the reader knows the source.
        assert "$ echo" in bundle.items[0].content

    def test_a_large_log_is_truncated_from_the_end(self, tmp_path, monkeypatch):
        """The end is where the failure is; the start is where the boot was."""
        logs = tmp_path / "logs"
        logs.mkdir()
        (logs / "sssd_pam.log").write_text("old\n" * 1000 + "THE-FAILURE\n", encoding="utf-8")
        monkeypatch.setattr(support, "run", lambda *a, **k: CommandResult(
            list(a[0]), 0, "", "", found=False))
        bundle = support.collect(files=(), commands=(), log_dir=logs, max_log_bytes=200)
        content = bundle.items[0].content
        assert "THE-FAILURE" in content
        assert "truncated" in content


class TestTheArchive:
    @pytest.mark.skipif(
        os.name != "posix",
        reason="POSIX permission bits; Windows has no equivalent to assert, and "
        "asserting the host's idea of a mode would measure the test machine "
        "rather than the code -- the member modes below are checked everywhere",
    )
    def test_it_is_readable_only_by_its_owner(self, tmp_path):
        dest = tmp_path / "b.tar.gz"
        support.write_bundle(support.Bundle(items=[support.BundleItem("a.txt", "x")]), dest)
        assert oct(dest.stat().st_mode)[-3:] == "600"

    def test_every_member_is_also_0600(self, tmp_path):
        dest = tmp_path / "b.tar.gz"
        support.write_bundle(support.Bundle(items=[support.BundleItem("a.txt", "x")]), dest)
        with tarfile.open(dest) as tar:
            assert all(m.mode == 0o600 for m in tar.getmembers())

    def test_the_manifest_says_what_was_left_out(self, tmp_path):
        dest = tmp_path / "b.tar.gz"
        bundle = support.Bundle(
            items=[support.BundleItem("a.txt", "x")],
            skipped=["/etc/krb5.keytab (never collected)"],
        )
        support.write_bundle(bundle, dest)
        with tarfile.open(dest) as tar:
            manifest = tar.extractfile("MANIFEST.txt").read().decode()
        assert "krb5.keytab" in manifest
        # A reader has to know redaction happened, or they will trust a blank.
        assert "<redacted>" in manifest

    def test_no_leading_slash_escapes_the_archive(self, tmp_path):
        dest = tmp_path / "b.tar.gz"
        support.write_bundle(
            support.Bundle(items=[support.BundleItem("config/etc/sssd/sssd.conf", "x")]), dest
        )
        with tarfile.open(dest) as tar:
            assert all(not m.name.startswith("/") for m in tar.getmembers())


class TestDebugStateIsNoticed:
    def write(self, tmp_path, body):
        p = tmp_path / "sssd.conf"
        p.write_text(body, encoding="utf-8")
        return p

    @pytest.fixture(autouse=True)
    def linux(self, monkeypatch):
        monkeypatch.setattr(support, "is_linux", lambda: True)

    def test_a_raised_level_warns(self, tmp_path):
        path = self.write(tmp_path, "[sssd]\ndebug_level = 9\n")
        checks = support.debug_state_checks(path)
        assert checks and checks[0].status == "WARN"
        assert "fills a disk" in checks[0].hint

    def test_hexadecimal_is_understood(self, tmp_path):
        """sssd.conf accepts 0x0070; a decimal-only parser would miss it."""
        path = self.write(tmp_path, "[sssd]\ndebug_level = 0x0070\n")
        assert support.debug_state_checks(path)

    def test_a_default_configuration_is_quiet(self, tmp_path):
        path = self.write(tmp_path, "[sssd]\nservices = nss, pam\n")
        assert support.debug_state_checks(path) == []

    def test_a_low_level_is_not_worth_warning_about(self, tmp_path):
        path = self.write(tmp_path, "[sssd]\ndebug_level = 2\n")
        assert support.debug_state_checks(path) == []

    def test_a_nonsense_value_is_not_guessed_at(self, tmp_path):
        path = self.write(tmp_path, "[sssd]\ndebug_level = verbose\n")
        assert support.debug_state_checks(path) == []


class TestSectionsChosen:
    def test_the_responders_and_the_live_domains(self):
        sections = support.sections_to_debug(["ad.example.com", "other.example.com"])
        assert "pam" in sections and "sssd" in sections
        assert "domain/ad.example.com" in sections
        assert "domain/other.example.com" in sections

    def test_a_host_with_no_domain_still_gets_the_responders(self):
        assert support.sections_to_debug([]) == list(support.SSSD_DEBUG_SECTIONS)

    def test_the_level_is_carried_through(self):
        changes = support.debug_changes(["pam"], 7)
        assert changes == [("pam", "debug_level", "7")]
