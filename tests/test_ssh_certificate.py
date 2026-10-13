"""SSH with a Smart Card is not the local login path, and must not be assumed.

Measured on the lab host after card login worked locally: `sshd -T` reported
`authorizedkeyscommand none`, so SSH with the card did not work at all. Nothing
in the local configuration says so, because the two share almost nothing -- the
token is on the *client*, so the server never sees a PIN and `pam_cert_auth`
and `local_auth_policy` take no part.

What they do share is the part this tool configures. `sss_ssh_authorizedkeys(1)`
validates the certificates it derives keys from using `ca_db` and
`certificate_verification` and filters them through the certmap rules, so the
bundle, the CRL and the rule already cover SSH -- which is exactly why the one
missing directive is worth a check rather than a paragraph in a document.
"""

from __future__ import annotations

import pytest

from sssd_smartcard.sssdconf import runtime
from sssd_smartcard.util import CommandResult

CARD_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDeKtB6x5"
OTHER_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDqMmOeITQ"

SSHD_WITH = "usepam yes\nauthorizedkeyscommand /usr/bin/sss_ssh_authorizedkeys\n"
SSHD_WITHOUT = "usepam yes\nauthorizedkeyscommand none\nauthorizedkeycommanduser none\n"
SSHD_OTHER = "usepam yes\nauthorizedkeyscommand /opt/corp/keys.sh\n"


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(runtime, "is_linux", lambda: True)
    monkeypatch.setattr(runtime, "which", lambda n: f"/usr/bin/{n}")


def fake_run(sshd_output: str, keys: str = "", keys_ok: bool = True):
    def _run(argv, **kw):
        if argv[0].endswith("sshd"):
            if not sshd_output:
                return CommandResult(argv, 1, "", "need root", found=True)
            return CommandResult(argv, 0, sshd_output, "")
        if argv[0].endswith("sss_ssh_authorizedkeys"):
            code = 0 if keys_ok else 1
            return CommandResult(argv, code, keys, "" if keys_ok else "No such user")
        raise AssertionError(f"unexpected command: {argv}")
    return _run


def named(checks, name):
    for c in checks:
        if c.name == name:
            return c
    return None


class TestTheSshdDirective:
    def test_missing_directive_warns_and_gives_the_command(self, linux, monkeypatch):
        monkeypatch.setattr(runtime, "run", fake_run(SSHD_WITHOUT))
        check = named(runtime.ssh_certificate_checks(), "sshd AuthorizedKeysCommand")
        assert check.status == "WARN"
        assert "sshd_config.d" in check.hint
        # The reader has to know why the working local login proves nothing here.
        assert "locally" in check.hint

    def test_a_configured_directive_passes(self, linux, monkeypatch):
        monkeypatch.setattr(runtime, "run", fake_run(SSHD_WITH))
        check = named(runtime.ssh_certificate_checks(), "sshd AuthorizedKeysCommand")
        assert check.status == "PASS"

    def test_someone_elses_command_is_not_mistaken_for_ours(self, linux, monkeypatch):
        """A host may already answer AuthorizedKeysCommand with its own script."""
        monkeypatch.setattr(runtime, "run", fake_run(SSHD_OTHER))
        check = named(runtime.ssh_certificate_checks(), "sshd AuthorizedKeysCommand")
        assert check.status == "WARN"
        assert "/opt/corp/keys.sh" in check.detail

    def test_unreadable_config_skips_rather_than_guessing(self, linux, monkeypatch):
        """sshd -T needs root; an unknown answer is not a passing one."""
        monkeypatch.setattr(runtime, "run", fake_run(""))
        check = named(runtime.ssh_certificate_checks(), "sshd AuthorizedKeysCommand")
        assert check.status == "SKIP"


class TestKeysDerivedFromTheCertificate:
    def test_keys_are_counted_for_the_named_user(self, linux, monkeypatch):
        monkeypatch.setattr(
            runtime, "run", fake_run(SSHD_WITH, CARD_KEY + "\n" + OTHER_KEY + "\n")
        )
        check = named(runtime.ssh_certificate_checks("u@example.com"), "ssh keys from certificate")
        assert check.status == "PASS"
        assert "2 key" in check.detail

    def test_no_keys_explains_both_causes(self, linux, monkeypatch):
        """An empty answer means no certificate, or every one rejected."""
        monkeypatch.setattr(runtime, "run", fake_run(SSHD_WITH, ""))
        check = named(runtime.ssh_certificate_checks("u@example.com"), "ssh keys from certificate")
        assert check.status == "WARN"
        assert "userCertificate" in check.hint
        assert "revoked" in check.hint

    def test_a_failing_helper_is_not_read_as_no_keys(self, linux, monkeypatch):
        monkeypatch.setattr(runtime, "run", fake_run(SSHD_WITH, "", keys_ok=False))
        check = named(runtime.ssh_certificate_checks("u@example.com"), "ssh keys from certificate")
        assert check.status == "WARN"
        assert "failed" in check.detail

    def test_output_that_is_not_a_key_is_not_counted(self, linux, monkeypatch):
        """sss_ssh_authorizedkeys prints nothing else, but counting lines would
        turn any future banner or warning into a passing key."""
        monkeypatch.setattr(
            runtime, "run", fake_run(SSHD_WITH, "# comment\n\n" + CARD_KEY + "\n")
        )
        check = named(runtime.ssh_certificate_checks("u@example.com"), "ssh keys from certificate")
        assert check.status == "PASS"
        assert "1 key" in check.detail

    def test_no_user_means_no_lookup(self, linux, monkeypatch):
        monkeypatch.setattr(runtime, "run", fake_run(SSHD_WITH))
        names = [c.name for c in runtime.ssh_certificate_checks()]
        assert "ssh keys from certificate" not in names


class TestItStaysQuiet:
    def test_without_the_helper_there_is_nothing_to_configure(self, linux, monkeypatch):
        monkeypatch.setattr(runtime, "which", lambda n: None)
        checks = runtime.ssh_certificate_checks("u@example.com")
        assert [c.status for c in checks] == ["SKIP"]

    def test_off_linux_says_nothing(self, monkeypatch):
        monkeypatch.setattr(runtime, "is_linux", lambda: False)
        assert runtime.ssh_certificate_checks("u@example.com") == []
