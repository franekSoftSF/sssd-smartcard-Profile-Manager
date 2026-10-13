"""Authenticating is not the same as being able to log in.

On the verified lab host a Smart Card login succeeded -- correct PIN, session
created, `loginctl` showed it active on seat0 -- and GNOME presented a **black
screen**. There was no home directory. `fallback_homedir = /home/%u@%d` only
*names* the path; nothing creates it, and `pam_mkhomedir.so` was absent from
`common-session`. The journal said it plainly:

    gsd-keyboard: Failed to create directory
        /home/testuser@ad.example.com/.local/share/...: Permission denied
    nautilus: Failed to create file ".../.config/dconf/user.LOGUW3":
        No such file or directory

`doctor` checked identity, certificate, mapping, PAM and local_auth_policy and
reported everything green, because nothing checked whether the user had
anywhere to log in to. These tests cover that gap.
"""

from __future__ import annotations

import pytest

from sssd_smartcard.sssdconf import runtime
from sssd_smartcard.sssdconf.runtime import UserLookup

MKHOMEDIR_SESSION = (
    "session\t[default=1]\t\t\tpam_permit.so\n"
    "session\trequired\tpam_unix.so \n"
    "session\toptional\t\t\tpam_sss.so \n"
    "session\toptional\tpam_systemd.so \n"
    "session\toptional\t\t\tpam_mkhomedir.so \n"
)

BARE_SESSION = (
    "session\t[default=1]\t\t\tpam_permit.so\n"
    "session\trequired\tpam_unix.so \n"
    "session\toptional\t\t\tpam_sss.so \n"
    "session\toptional\tpam_systemd.so \n"
)

COMMENTED_OUT = BARE_SESSION + "# session optional pam_mkhomedir.so\n"


@pytest.fixture
def pam_dir(tmp_path, monkeypatch):
    """Point the module at a throwaway /etc/pam.d."""
    monkeypatch.setattr(runtime, "PAM_DIR", tmp_path)
    monkeypatch.setattr(runtime, "is_linux", lambda: True)
    return tmp_path


class TestHomeProvisioningDetection:
    def test_mkhomedir_is_found(self, pam_dir):
        (pam_dir / "common-session").write_text(MKHOMEDIR_SESSION, encoding="utf-8")
        assert runtime.home_provisioning() == ("pam_mkhomedir.so", "common-session")

    def test_a_session_stack_without_it_reports_nothing(self, pam_dir):
        (pam_dir / "common-session").write_text(BARE_SESSION, encoding="utf-8")
        assert runtime.home_provisioning() == ("", "")

    def test_a_commented_line_does_not_count(self, pam_dir):
        """This is the exact state that produced the black screen."""
        (pam_dir / "common-session").write_text(COMMENTED_OUT, encoding="utf-8")
        assert runtime.home_provisioning() == ("", "")

    def test_the_rhel_module_is_recognised_too(self, pam_dir):
        (pam_dir / "system-auth").write_text(
            "session optional pam_oddjob_mkhomedir.so umask=0077\n", encoding="utf-8"
        )
        module, where = runtime.home_provisioning()
        assert module == "pam_oddjob_mkhomedir.so"
        assert where == "system-auth"

    def test_a_missing_pam_directory_is_not_a_crash(self, tmp_path, monkeypatch):
        monkeypatch.setattr(runtime, "PAM_DIR", tmp_path / "absent")
        assert runtime.home_provisioning() == ("", "")


class TestProvisioningCheck:
    def test_absent_provisioning_warns_and_names_both_fixes(self, pam_dir):
        (pam_dir / "common-session").write_text(BARE_SESSION, encoding="utf-8")
        checks = runtime.home_directory_checks(UserLookup(user=""))
        provisioning = [c for c in checks if c.name == "home provisioning"][0]
        assert provisioning.status == "WARN"
        assert "pam-auth-update --enable mkhomedir" in provisioning.hint
        assert "authselect" in provisioning.hint

    def test_the_hint_explains_the_actual_symptom(self, pam_dir):
        (pam_dir / "common-session").write_text(BARE_SESSION, encoding="utf-8")
        checks = runtime.home_directory_checks(UserLookup(user=""))
        hint = [c for c in checks if c.name == "home provisioning"][0].hint
        assert "black screen" in hint
        assert "fallback_homedir" in hint

    def test_present_provisioning_passes(self, pam_dir):
        (pam_dir / "common-session").write_text(MKHOMEDIR_SESSION, encoding="utf-8")
        checks = runtime.home_directory_checks(UserLookup(user=""))
        provisioning = [c for c in checks if c.name == "home provisioning"][0]
        assert provisioning.status == "PASS"

    def test_it_works_with_no_user_at_all(self, pam_dir):
        """doctor runs this host-level check even without --user."""
        (pam_dir / "common-session").write_text(BARE_SESSION, encoding="utf-8")
        checks = runtime.home_directory_checks(UserLookup(user=""))
        assert [c.name for c in checks] == ["home provisioning"]


class FakeStat:
    """Just the two fields the check reads."""

    def __init__(self, uid: int, mode: int):
        self.st_uid = uid
        self.st_mode = 0o040000 | mode


class TestHomeDirectoryState:
    """Ownership and mode logic, independent of the host filesystem.

    These were POSIX-only (and therefore skipped on Windows) until the stat
    result was faked. The logic is the thing worth testing; whether the dev
    machine can chown is not.
    """

    def _lookup(self, home, uid="1000001101", gid="1000000513"):
        return UserLookup(
            user="testuser@ad.example.com",
            resolved=True,
            uid=uid,
            gid=gid,
            home=str(home),
        )

    def _patch_home(self, monkeypatch, *, exists: bool, stat: FakeStat | None = None):
        from pathlib import Path

        monkeypatch.setattr(Path, "is_dir", lambda self: exists)
        if stat is not None:
            monkeypatch.setattr(Path, "stat", lambda self, **kw: stat)

    def _home_check(self, checks):
        return [c for c in checks if c.name == "home directory"][0]

    def test_a_missing_home_with_provisioning_is_fine(self, pam_dir, monkeypatch):
        (pam_dir / "common-session").write_text(MKHOMEDIR_SESSION, encoding="utf-8")
        self._patch_home(monkeypatch, exists=False)
        home = self._home_check(
            runtime.home_directory_checks(self._lookup("/home/testuser@ad.x"))
        )
        assert home.status == "PASS"
        assert "created on first login" in home.detail

    def test_a_missing_home_without_provisioning_is_the_black_screen(
        self, pam_dir, monkeypatch
    ):
        (pam_dir / "common-session").write_text(BARE_SESSION, encoding="utf-8")
        self._patch_home(monkeypatch, exists=False)
        home = self._home_check(
            runtime.home_directory_checks(self._lookup("/home/testuser@ad.x"))
        )
        assert home.status == "FAIL"
        assert "nothing will create it" in home.detail
        # The exact command, with the real uid and gid substituted in.
        assert "install -d -m 0700 -o 1000001101 -g 1000000513" in home.hint

    def test_a_correct_home_passes(self, pam_dir, monkeypatch):
        (pam_dir / "common-session").write_text(MKHOMEDIR_SESSION, encoding="utf-8")
        self._patch_home(
            monkeypatch, exists=True, stat=FakeStat(uid=1000001101, mode=0o700)
        )
        home = self._home_check(
            runtime.home_directory_checks(self._lookup("/home/testuser@ad.x"))
        )
        assert home.status == "PASS"
        assert "mode 0o700" in home.detail

    def test_a_home_owned_by_someone_else_fails(self, pam_dir, monkeypatch):
        """Exactly what a hand-made directory with the wrong chown looks like."""
        (pam_dir / "common-session").write_text(MKHOMEDIR_SESSION, encoding="utf-8")
        self._patch_home(monkeypatch, exists=True, stat=FakeStat(uid=0, mode=0o700))
        home = self._home_check(
            runtime.home_directory_checks(self._lookup("/home/testuser@ad.x"))
        )
        assert home.status == "FAIL"
        assert "uid is 1000001101" in home.detail
        assert "chown -R 1000001101:1000000513" in home.hint

    def test_a_world_readable_home_warns(self, pam_dir, monkeypatch):
        (pam_dir / "common-session").write_text(MKHOMEDIR_SESSION, encoding="utf-8")
        self._patch_home(
            monkeypatch, exists=True, stat=FakeStat(uid=1000001101, mode=0o755)
        )
        home = self._home_check(
            runtime.home_directory_checks(self._lookup("/home/testuser@ad.x"))
        )
        assert home.status == "WARN"
        assert "chmod 0700" in home.hint

    def test_the_0750_mkhomedir_default_also_warns(self, pam_dir, monkeypatch):
        """pam_mkhomedir leaves 0750 here; group members can still read it."""
        (pam_dir / "common-session").write_text(MKHOMEDIR_SESSION, encoding="utf-8")
        self._patch_home(
            monkeypatch, exists=True, stat=FakeStat(uid=1000001101, mode=0o750)
        )
        home = self._home_check(
            runtime.home_directory_checks(self._lookup("/home/testuser@ad.x"))
        )
        assert home.status == "WARN"

    def test_an_unresolved_user_gets_no_home_verdict(self, pam_dir):
        (pam_dir / "common-session").write_text(MKHOMEDIR_SESSION, encoding="utf-8")
        checks = runtime.home_directory_checks(UserLookup(user="nobody"))
        assert [c.name for c in checks] == ["home provisioning"]
