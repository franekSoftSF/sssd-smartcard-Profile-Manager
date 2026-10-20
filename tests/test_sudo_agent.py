"""sudo can use a card held by an SSH client -- and the sound way differs.

`pam_sss` cannot do this: over SSH the token is on the client, the server never
sees it, so `try_cert_auth` finds no certificate and the stack falls through to
a password. Measured, with SSSD naming it: "try_cert_auth flag set but no
certificate available". `pam_ssh_agent_auth` closes the gap by verifying a
signature from the *forwarded* agent.

Two things decide whether it works, and each fails silently alone: the module
must be in the stack, and SSH_AUTH_SOCK must survive sudo's env_reset. Measured:
with env_reset stripping it, the module logged "No ssh-agent could be contacted"
and sudo asked for a password with nothing shown to the user.

A third decides whether it is *sound*. Most guides say to paste the key into
~/.ssh/authorized_keys; that copy outlives revoking the certificate, so sudo
would keep working after login and SSH had stopped. `authorized_keys_command=`
with sss_ssh_authorizedkeys asks the same source sshd asks, and one revocation
then covers all three.
"""

from __future__ import annotations

import pytest

from sssd_smartcard.sssdconf import runtime

HELPER = "/usr/bin/sss_ssh_authorizedkeys"

BASE = """#%PAM-1.0
session    required   pam_limits.so
@include common-auth
@include common-account
"""

def stack(auth_line: str = "") -> str:
    if not auth_line:
        return BASE
    return BASE.replace("@include common-auth", auth_line + "\n@include common-auth")


FROM_AD = f"auth    sufficient  pam_ssh_agent_auth.so authorized_keys_command={HELPER}"
FROM_FILE = "auth    sufficient  pam_ssh_agent_auth.so file=%h/.ssh/authorized_keys"
FROM_OTHER = "auth sufficient pam_ssh_agent_auth.so authorized_keys_command=/opt/corp/keys.sh"
WITH_DEBUG = f"auth sufficient pam_ssh_agent_auth.so debug authorized_keys_command={HELPER}"
COMMENTED = "# auth sufficient pam_ssh_agent_auth.so authorized_keys_command=" + HELPER


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(runtime, "is_linux", lambda: True)


def write(tmp_path, body):
    p = tmp_path / "sudo"
    p.write_text(body, encoding="utf-8")
    return p


def named(checks, name):
    return [c for c in checks if c.name == name]


class TestTheKeySource:
    def test_keys_from_ad_pass(self, linux, tmp_path):
        checks = runtime.sudo_agent_checks(write(tmp_path, stack(FROM_AD)), ["SSH_AUTH_SOCK"])
        agent = named(checks, "sudo via SSH agent")[0]
        assert agent.status == "PASS"
        assert HELPER in agent.detail

    def test_a_static_file_warns_about_outliving_revocation(self, linux, tmp_path):
        checks = runtime.sudo_agent_checks(write(tmp_path, stack(FROM_FILE)), ["SSH_AUTH_SOCK"])
        agent = named(checks, "sudo via SSH agent")[0]
        assert agent.status == "WARN"
        # The reason matters more than the fact: a copy of the key on the host.
        assert "outlive" in agent.hint
        assert "authorized_keys_command" in agent.hint

    def test_someone_elses_command_is_reported_without_a_verdict(self, linux, tmp_path):
        """A site may have its own key service; that is not this tool's business."""
        checks = runtime.sudo_agent_checks(write(tmp_path, stack(FROM_OTHER)), ["SSH_AUTH_SOCK"])
        agent = named(checks, "sudo via SSH agent")[0]
        assert agent.status == "INFO"
        assert "/opt/corp/keys.sh" in agent.detail

    def test_a_commented_line_is_not_configuration(self, linux, tmp_path):
        assert runtime.sudo_agent_checks(write(tmp_path, stack(COMMENTED)), ["SSH_AUTH_SOCK"]) == []


class TestTheEnvironment:
    def test_a_stripped_variable_is_a_failure(self, linux, tmp_path):
        checks = runtime.sudo_agent_checks(write(tmp_path, stack(FROM_AD)), ["PATH", "TERM"])
        env = named(checks, "sudo agent environment")[0]
        assert env.status == "FAIL"
        # It must say the symptom, because the user is shown nothing at all.
        assert "password prompt" in env.hint

    def test_an_unreadable_sudo_config_does_not_invent_a_verdict(self, linux, tmp_path, monkeypatch):
        monkeypatch.setattr(runtime, "_sudoers_env_keep", lambda: None)
        checks = runtime.sudo_agent_checks(write(tmp_path, stack(FROM_AD)))
        env = named(checks, "sudo agent environment")[0]
        assert env.status == "WARN"
        assert "cannot read" in env.detail


class TestItStaysQuiet:
    def test_a_host_not_using_this_at_all_says_nothing(self, linux, tmp_path):
        """Not configured is the default, not a fault."""
        assert runtime.sudo_agent_checks(write(tmp_path, stack()), ["SSH_AUTH_SOCK"]) == []

    def test_a_missing_pam_file_is_not_a_crash(self, linux, tmp_path):
        assert runtime.sudo_agent_checks(tmp_path / "absent", ["SSH_AUTH_SOCK"]) == []

    def test_off_linux_says_nothing(self, monkeypatch, tmp_path):
        monkeypatch.setattr(runtime, "is_linux", lambda: False)
        assert runtime.sudo_agent_checks(write(tmp_path, stack(FROM_AD)), ["SSH_AUTH_SOCK"]) == []


class TestDebugIsNoticed:
    def test_debug_left_on_is_reported(self, linux, tmp_path):
        checks = runtime.sudo_agent_checks(write(tmp_path, stack(WITH_DEBUG)), ["SSH_AUTH_SOCK"])
        notes = [c for c in checks if "debug" in c.detail]
        assert notes and notes[0].status == "INFO"

    def test_without_debug_nothing_is_said_about_it(self, linux, tmp_path):
        checks = runtime.sudo_agent_checks(write(tmp_path, stack(FROM_AD)), ["SSH_AUTH_SOCK"])
        assert not [c for c in checks if "debug" in c.detail]
