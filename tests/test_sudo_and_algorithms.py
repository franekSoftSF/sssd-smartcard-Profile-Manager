"""Two configurations that read as finished and ask nobody anything.

**sudo** needs the `sudoers: ... sss` line in nsswitch.conf *and* the
libsss-sudo package that implements that source. Neither half complains when
the other is missing: with the line alone sudo quietly uses the local file and
every rule in the directory is ignored; with the package alone sudo never asks
SSSD. Measured on the lab host, which had the package absent.

**SSH key algorithms**: a client offering the right RSA key as
`x509v3-ssh-rsa` was refused with `unsupported public key algorithm`, and PuTTY
printed "Server refused our key" -- the same words it prints when the key is
genuinely not authorised. The server half of that is checkable before anyone
spends an evening on it.
"""

from __future__ import annotations

import pytest

from sssd_smartcard.sssdconf import runtime

NSS = """# comment
passwd:         files systemd sss
group:          files systemd sss
sudoers:        files sss
netgroup:       nis
"""
NSS_NO_SUDOERS = "passwd: files sss\ngroup: files sss\n"
NSS_COMMENTED = NSS_NO_SUDOERS + "# sudoers: files sss\n"

# OpenSSH 9.x defaults: plain ssh-rsa (RSA/SHA-1) is absent, rsa-sha2-* are not.
MODERN = "rsa-sha2-512,rsa-sha2-256,ssh-ed25519,ecdsa-sha2-nistp256"
NO_RSA = "ssh-ed25519,ecdsa-sha2-nistp256"
SHA1_ONLY = "ssh-rsa,ssh-ed25519"


@pytest.fixture
def linux(monkeypatch):
    monkeypatch.setattr(runtime, "is_linux", lambda: True)


def write_nss(tmp_path, body):
    p = tmp_path / "nsswitch.conf"
    p.write_text(body, encoding="utf-8")
    return p


class TestReadingNsswitch:
    def test_the_sudoers_line_is_found(self, tmp_path):
        p = write_nss(tmp_path, NSS)
        assert runtime.nsswitch_sources("sudoers", p) == ["files", "sss"]

    def test_a_commented_line_does_not_count(self, tmp_path):
        p = write_nss(tmp_path, NSS_COMMENTED)
        assert runtime.nsswitch_sources("sudoers", p) == []

    def test_a_missing_file_is_not_a_crash(self, tmp_path):
        assert runtime.nsswitch_sources("sudoers", tmp_path / "absent") == []

    def test_another_database_is_not_confused_with_it(self, tmp_path):
        p = write_nss(tmp_path, NSS)
        assert runtime.nsswitch_sources("passwd", p) == ["files", "systemd", "sss"]


class TestSudoCoherence:
    def test_line_without_package_is_a_failure(self, linux, monkeypatch):
        monkeypatch.setattr(runtime, "nsswitch_sources", lambda db, path=None: ["files", "sss"])
        monkeypatch.setattr(runtime, "package_installed", lambda name: False)
        check = runtime.sudo_rules_checks()[0]
        assert check.status == "FAIL"
        assert "libsss-sudo" in check.detail
        # The operator has to know the rules are being ignored, not just missing.
        assert "ignored" in check.hint

    def test_package_without_line_warns(self, linux, monkeypatch):
        monkeypatch.setattr(runtime, "nsswitch_sources", lambda db, path=None: ["files"])
        monkeypatch.setattr(runtime, "package_installed", lambda name: True)
        check = runtime.sudo_rules_checks()[0]
        assert check.status == "WARN"
        assert "sudoers: files sss" in check.hint

    def test_both_halves_present_passes(self, linux, monkeypatch):
        monkeypatch.setattr(runtime, "nsswitch_sources", lambda db, path=None: ["files", "sss"])
        monkeypatch.setattr(runtime, "package_installed", lambda name: True)
        check = runtime.sudo_rules_checks()[0]
        assert check.status == "PASS"

    def test_a_host_using_only_local_sudoers_is_not_nagged(self, linux, monkeypatch):
        """Local rules are a legitimate choice, so say what is true and stop."""
        monkeypatch.setattr(runtime, "nsswitch_sources", lambda db, path=None: [])
        monkeypatch.setattr(runtime, "package_installed", lambda name: False)
        check = runtime.sudo_rules_checks()[0]
        assert check.status == "INFO"
        assert "local" in check.detail

    def test_no_dpkg_does_not_invent_a_verdict(self, linux, monkeypatch):
        monkeypatch.setattr(runtime, "nsswitch_sources", lambda db, path=None: ["files", "sss"])
        monkeypatch.setattr(runtime, "package_installed", lambda name: None)
        check = runtime.sudo_rules_checks()[0]
        assert check.status == "WARN"
        assert "cannot determine" in check.detail


class TestKeyAlgorithms:
    def test_an_rsa_key_passes_on_a_modern_server(self):
        checks = runtime.ssh_key_algorithm_checks(["ssh-rsa"], MODERN)
        assert [c.status for c in checks] == ["PASS"]
        # It must name rsa-sha2, not claim ssh-rsa works.
        assert "rsa-sha2-512" in checks[0].detail

    def test_sha1_only_server_still_accepts_the_same_key(self):
        """ssh-rsa is deprecated, not forbidden; a host that kept it works."""
        checks = runtime.ssh_key_algorithm_checks(["ssh-rsa"], SHA1_ONLY)
        assert checks[0].status == "PASS"

    def test_a_server_accepting_no_rsa_name_is_a_failure(self):
        checks = runtime.ssh_key_algorithm_checks(["ssh-rsa"], NO_RSA)
        assert checks[0].status == "FAIL"
        assert "never be used" in checks[0].detail
        # The point of the check: the client cannot tell this apart.
        assert "refused" in checks[0].hint

    def test_each_key_type_is_reported_once(self):
        checks = runtime.ssh_key_algorithm_checks(
            ["ssh-rsa", "ssh-rsa", "ssh-ed25519"], MODERN
        )
        assert len(checks) == 2

    def test_an_unknown_type_is_not_guessed_at(self):
        checks = runtime.ssh_key_algorithm_checks(["ssh-dss"], MODERN)
        assert checks[0].status == "INFO"

    def test_an_unreadable_server_config_says_nothing(self):
        """sshd -T needs root; silence beats a fabricated FAIL."""
        assert runtime.ssh_key_algorithm_checks(["ssh-rsa"], "") == []
