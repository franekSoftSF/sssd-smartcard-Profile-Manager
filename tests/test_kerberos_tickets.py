"""Logging in with the card and holding a Kerberos identity are different.

Measured on a host where card login, SSH and sudo all worked: `klist` inside an
SSH session reported *No credentials cache found*, and the host had no
credential cache at all. Two separate reasons, neither of them a fault:

* `local_auth_policy = enable:smartcard` is **local** authentication. SSSD
  verifies the certificate against the CA bundle and the certmap rule without
  contacting the KDC, so there is nothing to put in a cache. `doctor` already
  says as much in a different check: "Card login does not need it -- that is
  local authentication." A ticket needs PKINIT, which needs the MIT plugin, and
  on that host `krb5-pkinit` was not installed.
* SSH public-key authentication skips the PAM `auth` stack altogether, so
  `pam_sss` never runs and nothing obtains credentials.

A password login *does* yield a ticket through SSSD's Kerberos auth provider,
which is almost certainly what someone has seen when they report that tickets
"sometimes" appear.

All of it is INFO. None of it is misconfiguration -- it is what the chosen
mechanisms do. The only reason to say it is that the consequence surprises
people *after* everything else works, which is the worst moment to be surprised.
"""

from __future__ import annotations

import pytest

from sssd_smartcard.sssdconf import runtime

CARD_LOCAL = """[sssd]
domains = ad.example.com
services = nss, pam

[domain/ad.example.com]
id_provider = ad
local_auth_policy = enable:smartcard
"""

NO_CARD = """[sssd]
domains = ad.example.com

[domain/ad.example.com]
id_provider = ad
"""

SSH_ON = {"authorizedkeyscommand": "/usr/bin/sss_ssh_authorizedkeys",
          "gssapiauthentication": "no"}
SSH_WITH_GSSAPI = {"authorizedkeyscommand": "/usr/bin/sss_ssh_authorizedkeys",
                   "gssapiauthentication": "yes"}
SSH_PLAIN = {"authorizedkeyscommand": "none", "gssapiauthentication": "no"}


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(runtime, "is_linux", lambda: True)


def write(tmp_path, body):
    p = tmp_path / "sssd.conf"
    p.write_text(body, encoding="utf-8")
    return p


def named(checks, name):
    return [c for c in checks if c.name == name]


class TestCardLogin:
    def test_local_card_auth_without_pkinit_says_no_ticket(self, linux, tmp_path, monkeypatch):
        monkeypatch.setattr(runtime, "pkinit_plugin_present", lambda: False)
        checks = runtime.kerberos_ticket_checks(write(tmp_path, CARD_LOCAL), sshd={})
        c = named(checks, "Kerberos ticket on card login")[0]
        assert c.status == "INFO"
        # The distinction is the whole point, so it has to be stated.
        assert "different things" in c.hint

    def test_with_the_plugin_present_nothing_is_claimed(self, linux, tmp_path, monkeypatch):
        """PKINIT installed means a ticket is at least possible; do not assert
        that it is not, since whether it works depends on anchors and the KDC."""
        monkeypatch.setattr(runtime, "pkinit_plugin_present", lambda: True)
        checks = runtime.kerberos_ticket_checks(write(tmp_path, CARD_LOCAL), sshd={})
        assert named(checks, "Kerberos ticket on card login") == []

    def test_a_host_not_doing_local_card_auth_is_not_told_about_it(self, linux, tmp_path, monkeypatch):
        monkeypatch.setattr(runtime, "pkinit_plugin_present", lambda: False)
        checks = runtime.kerberos_ticket_checks(write(tmp_path, NO_CARD), sshd={})
        assert named(checks, "Kerberos ticket on card login") == []

    def test_the_password_route_is_mentioned_as_the_alternative(self, linux, tmp_path, monkeypatch):
        """Because it is usually what someone has already seen working."""
        monkeypatch.setattr(runtime, "pkinit_plugin_present", lambda: False)
        checks = runtime.kerberos_ticket_checks(write(tmp_path, CARD_LOCAL), sshd={})
        assert "password login obtains one" in named(
            checks, "Kerberos ticket on card login"
        )[0].hint


class TestSsh:
    def test_keys_from_sssd_without_gssapi_says_no_ticket(self, linux, tmp_path, monkeypatch):
        monkeypatch.setattr(runtime, "pkinit_plugin_present", lambda: True)
        checks = runtime.kerberos_ticket_checks(write(tmp_path, NO_CARD), sshd=SSH_ON)
        c = named(checks, "Kerberos ticket over SSH")[0]
        assert c.status == "INFO"
        assert "klist" in c.hint

    def test_gssapi_enabled_means_nothing_is_claimed(self, linux, tmp_path, monkeypatch):
        monkeypatch.setattr(runtime, "pkinit_plugin_present", lambda: True)
        checks = runtime.kerberos_ticket_checks(write(tmp_path, NO_CARD), sshd=SSH_WITH_GSSAPI)
        assert named(checks, "Kerberos ticket over SSH") == []

    def test_a_host_not_serving_keys_from_sssd_is_not_told_about_it(self, linux, tmp_path, monkeypatch):
        monkeypatch.setattr(runtime, "pkinit_plugin_present", lambda: True)
        checks = runtime.kerberos_ticket_checks(write(tmp_path, NO_CARD), sshd=SSH_PLAIN)
        assert named(checks, "Kerberos ticket over SSH") == []


class TestItStaysQuiet:
    def test_both_at_once_are_reported_separately(self, linux, tmp_path, monkeypatch):
        """They have different causes and different remedies."""
        monkeypatch.setattr(runtime, "pkinit_plugin_present", lambda: False)
        checks = runtime.kerberos_ticket_checks(write(tmp_path, CARD_LOCAL), sshd=SSH_ON)
        assert len(checks) == 2
        assert all(c.status == "INFO" for c in checks)

    def test_nothing_is_ever_a_failure(self, linux, tmp_path, monkeypatch):
        """These are consequences of the chosen mechanisms, not faults."""
        monkeypatch.setattr(runtime, "pkinit_plugin_present", lambda: False)
        checks = runtime.kerberos_ticket_checks(write(tmp_path, CARD_LOCAL), sshd=SSH_ON)
        assert not [c for c in checks if c.status in ("FAIL", "WARN")]

    def test_an_unreadable_config_is_not_a_crash(self, linux, tmp_path):
        assert runtime.kerberos_ticket_checks(tmp_path / "absent", sshd={}) == []

    def test_off_linux_says_nothing(self, monkeypatch, tmp_path):
        monkeypatch.setattr(runtime, "is_linux", lambda: False)
        assert runtime.kerberos_ticket_checks(write(tmp_path, CARD_LOCAL), sshd=SSH_ON) == []
