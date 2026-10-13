"""sssd.conf editing, the profile model, and the apply/rollback contract."""

from __future__ import annotations

import os
import stat

import pytest

from sssd_smartcard.backup import new_backup_set, write_atomic
from sssd_smartcard.errors import ApplyError, ProfileError
from sssd_smartcard.model.profile import SmartCardProfile
from sssd_smartcard.model.store import load_profile_text
from sssd_smartcard.sssdconf.apply import apply_plan, build_plan
from sssd_smartcard.sssdconf.conf import SssdConfig

SAMPLE = """\
[sssd]
config_file_version = 2
# the domain this host is joined to
domains = domain-b.local
services = nss, pam

[domain/domain-b.local]
id_provider = ad
ad_domain = domain-b.local
"""

PROFILE_YAML = """\
apiVersion: sssd-smartcard/v1
name: TEST-UPN
domain: domain-b.local
certificate:
  issuer: "CN=CA,DC=domain-a,DC=local"
  eku: [clientAuth]
mapping:
  type: san-upn
  domains: [domain-a.local]
  options:
    upn_suffix: domain-a.local
"""


class TestSssdConfigEditing:
    def test_reads_sections_and_values(self):
        config = SssdConfig.parse(SAMPLE)
        assert config.domains() == ["domain-b.local"]
        assert config.get("domain/domain-b.local", "id_provider") == "ad"
        assert config.domain_sections() == ["domain-b.local"]

    def test_comments_and_ordering_survive_an_edit(self):
        config = SssdConfig.parse(SAMPLE)
        config.set("sssd", "services", "nss, pam, ssh")
        rendered = config.render()
        assert "# the domain this host is joined to" in rendered
        assert rendered.index("[sssd]") < rendered.index("[domain/domain-b.local]")

    def test_setting_an_unchanged_value_reports_no_change(self):
        config = SssdConfig.parse(SAMPLE)
        assert config.set("sssd", "services", "nss, pam") is False

    def test_a_new_key_lands_inside_its_section(self):
        config = SssdConfig.parse(SAMPLE)
        config.set("domain/domain-b.local", "ldap_user_certificate", "userCertificate;binary")
        section = config.items("domain/domain-b.local")
        assert section["ldap_user_certificate"] == "userCertificate;binary"

    def test_a_new_section_is_appended(self):
        config = SssdConfig.parse(SAMPLE)
        config.set("certmap/domain-b.local/X", "maprule", "LDAP:(uid=x)")
        assert config.certmap_sections() == ["certmap/domain-b.local/X"]
        assert config.render().rstrip().endswith("maprule = LDAP:(uid=x)")

    def test_unset_and_remove_section(self):
        config = SssdConfig.parse(SAMPLE)
        assert config.unset("sssd", "services")
        assert "services" not in config.items("sssd")
        assert config.remove_section("domain/domain-b.local")
        assert "domain/domain-b.local" not in config.sections()

    def test_missing_file_yields_an_empty_config(self, tmp_path):
        config = SssdConfig.load(tmp_path / "nope.conf")
        assert config.sections() == []

    def test_diff_header_has_no_double_slash_for_absolute_paths(self):
        from sssd_smartcard.sssdconf.conf import unified_diff

        diff = unified_diff("a\n", "b\n", path="/etc/sssd/sssd.conf")
        assert "a/etc/sssd/sssd.conf" in diff
        assert "b/etc/sssd/sssd.conf" in diff
        assert "//" not in diff

    def test_diff_header_still_works_for_a_relative_path(self):
        from sssd_smartcard.sssdconf.conf import unified_diff

        diff = unified_diff("a\n", "b\n", path="sssd.conf")
        assert "a/sssd.conf" in diff


class TestProfileModel:
    def test_a_typo_is_rejected_with_the_valid_keys(self):
        with pytest.raises(ProfileError) as excinfo:
            load_profile_text("apiVersion: sssd-smartcard/v1\nname: X\ndomain: d\nvalidaton: {}\n")
        assert "validaton" in str(excinfo.value) and "validation" in str(excinfo.value)

    def test_name_must_not_contain_section_syntax(self):
        with pytest.raises(ProfileError):
            load_profile_text("apiVersion: sssd-smartcard/v1\nname: a/b\ndomain: d\n")

    def test_domain_is_required(self):
        with pytest.raises(ProfileError):
            load_profile_text("apiVersion: sssd-smartcard/v1\nname: X\n")

    def test_unsupported_api_version_is_rejected(self):
        with pytest.raises(ProfileError):
            load_profile_text("apiVersion: sssd-smartcard/v99\nname: X\ndomain: d\n")

    def test_smartcard_required_shorthand_maps_to_mode(self):
        profile = load_profile_text(
            "apiVersion: sssd-smartcard/v1\nname: X\ndomain: d\n"
            "authentication:\n  smartcard_required: true\n"
        )
        assert profile.authentication.mode == "required"
        assert profile.authentication.smartcard_required

    def test_nested_mechanism_settings_fold_into_options(self):
        # The design brief nests mapping settings under their own key.
        profile = load_profile_text(
            "apiVersion: sssd-smartcard/v1\nname: X\ndomain: d\n"
            "mapping:\n  type: san-upn\n  san:\n    type: ntPrincipalName\n"
        )
        assert profile.mapping.options["san"] == {"type": "ntPrincipalName"}

    def test_unknown_mapping_type_lists_the_available_ones(self):
        from sssd_smartcard.certmap.mappings import build_rule

        profile = SmartCardProfile(name="X", domain="d")
        profile.mapping.type = "telepathy"
        with pytest.raises(ProfileError) as excinfo:
            build_rule(profile)
        assert "san-upn" in str(excinfo.value)

    def test_custom_mapping_without_a_maprule_is_rejected(self):
        from sssd_smartcard.certmap.mappings import build_rule

        profile = SmartCardProfile(name="X", domain="d")
        profile.mapping.type = "custom"
        with pytest.raises(ProfileError):
            build_rule(profile)


class TestProfileSearchPath:
    """Where profiles are looked up, which the Debian package depends on."""

    def test_order_is_most_specific_first(self):
        from sssd_smartcard.model.store import profile_dirs

        paths = [str(p).replace("\\", "/") for p in profile_dirs()]
        etc = next(i for i, p in enumerate(paths) if p == "/etc/sssd-smartcard/profiles")
        share = next(
            i for i, p in enumerate(paths) if p == "/usr/share/sssd-smartcard/profiles"
        )
        # The administrator's own profiles must win over the packaged examples.
        assert etc < share

    def test_the_packaged_location_is_searched(self):
        from sssd_smartcard.model.store import profile_dirs

        paths = {str(p).replace("\\", "/") for p in profile_dirs()}
        assert "/usr/share/sssd-smartcard/profiles" in paths

    def test_env_override_is_searched_first(self, monkeypatch, tmp_path):
        monkeypatch.setenv("SSSD_SMARTCARD_PROFILES", str(tmp_path))
        import importlib

        from sssd_smartcard.model import store

        importlib.reload(store)
        try:
            assert store.profile_dirs()[0] == tmp_path
        finally:
            monkeypatch.delenv("SSSD_SMARTCARD_PROFILES", raising=False)
            importlib.reload(store)

    def test_a_profile_is_found_in_the_packaged_location(self, monkeypatch, tmp_path):
        """Proves `profile show NAME` works off an installed package layout."""
        import importlib

        packaged = tmp_path / "usr" / "share" / "sssd-smartcard" / "profiles"
        packaged.mkdir(parents=True)
        (packaged / "PKG-TEST.yaml").write_text(PROFILE_YAML.replace("TEST-UPN", "PKG-TEST"))
        monkeypatch.setenv("SSSD_SMARTCARD_PROFILES", str(packaged))

        from sssd_smartcard.model import store

        importlib.reload(store)
        try:
            assert store.find_profile("PKG-TEST").name == "PKG-TEST"
        finally:
            monkeypatch.delenv("SSSD_SMARTCARD_PROFILES", raising=False)
            importlib.reload(store)


class TestIdOutputParsing:
    """The group list must not include the user's own account.

    Seen on a real host: `id testuser@…` prints uid=…(testuser@…) gid=…(domain
    users@…) groups=…, and scanning the whole line for `N(name)` picked up the
    uid parenthesis too, so the mapping test listed the user as one of their
    own groups.
    """

    ID_LINE = (
        "uid=1000001101(testuser@ad.example.com) "
        "gid=1000000513(domain users@ad.example.com) "
        "groups=1000000513(domain users@ad.example.com),"
        "1052001115(grphorizonusers@ad.example.com),"
        "1052001140(grpworkspaceoneuser@ad.example.com)"
    )

    def _groups(self, line: str) -> list[str]:
        import re

        groups: list[str] = []
        part = re.search(r"\bgroups=(.*)$", line.strip())
        if part:
            for match in re.finditer(r"\d+\(([^)]+)\)", part.group(1)):
                if match.group(1) not in groups:
                    groups.append(match.group(1))
        return groups

    def test_user_is_not_listed_as_their_own_group(self):
        groups = self._groups(self.ID_LINE)
        assert "testuser@ad.example.com" not in groups

    def test_real_groups_are_all_captured(self):
        assert self._groups(self.ID_LINE) == [
            "domain users@ad.example.com",
            "grphorizonusers@ad.example.com",
            "grpworkspaceoneuser@ad.example.com",
        ]

    def test_line_without_groups_segment_yields_nothing(self):
        assert self._groups("uid=0(root) gid=0(root)") == []


class TestProfileNameFromFilename:
    """`--save-profile x.yaml` must produce a profile named x.

    The name inside the profile becomes the [certmap/<domain>/<name>] section.
    When it differed from the file name, `mapping test AD-PIV-UPN` worked (the
    file resolved) but the section was called AD-UPN, which is a confusing place
    to leave somebody.
    """

    def _derive(self, save_profile: str | None, explicit: str | None) -> str | None:
        from pathlib import Path

        name = explicit
        if not name and save_profile:
            stem = Path(save_profile).stem
            if stem and not any(c in stem for c in "/[] \t"):
                name = stem
        return name

    def test_stem_becomes_the_name(self):
        assert (
            self._derive("/etc/sssd-smartcard/profiles/AD-PIV-UPN.yaml", None)
            == "AD-PIV-UPN"
        )

    def test_explicit_name_wins(self):
        assert self._derive("/tmp/whatever.yaml", "CHOSEN") == "CHOSEN"

    def test_no_save_path_leaves_the_derived_name_alone(self):
        assert self._derive(None, None) is None

    def test_a_stem_that_cannot_be_a_section_name_is_rejected(self):
        # Spaces and brackets would break the [certmap/...] section header.
        assert self._derive("/tmp/my profile.yaml", None) is None


class TestBackupAndAtomicWrite:
    def test_write_atomic_applies_the_mode_and_content(self, tmp_path):
        target = tmp_path / "sssd.conf"
        write_atomic(target, "hello\n", mode=0o600)
        assert target.read_text() == "hello\n"
        if os.name != "nt":
            assert stat.S_IMODE(target.stat().st_mode) == 0o600

    def test_rollback_restores_a_modified_file(self, tmp_path):
        target = tmp_path / "sssd.conf"
        target.write_text("original\n")
        backups = new_backup_set(tmp_path / "backups")
        backups.add(target)
        write_atomic(target, "broken\n")
        backups.rollback()
        assert target.read_text() == "original\n"

    def test_a_timestamped_base_is_used_directly(self, tmp_path):
        """One run must not report backups at <stamp>/<stamp>.

        The setup script backs up into its own run directory and passes that
        same directory to the CLI, which used to append a second timestamp.
        """
        run_dir = tmp_path / "20261011-224003"
        assert new_backup_set(run_dir).directory == run_dir

    def test_a_plain_base_still_gets_its_own_timestamp(self, tmp_path):
        directory = new_backup_set(tmp_path / "backups").directory
        assert directory.parent == tmp_path / "backups"
        assert directory.name != "backups"

    def test_rollback_deletes_a_file_that_did_not_exist(self, tmp_path):
        target = tmp_path / "new.conf"
        backups = new_backup_set(tmp_path / "backups")
        backups.add(target)
        write_atomic(target, "created\n")
        backups.rollback()
        assert not target.exists()


class TestApply:
    def _setup(self, tmp_path):
        config = tmp_path / "sssd.conf"
        config.write_text(SAMPLE)
        profile = load_profile_text(PROFILE_YAML)
        return config, profile

    def test_plan_produces_a_diff_without_touching_the_file(self, tmp_path):
        config, profile = self._setup(tmp_path)
        before = config.read_text()
        plan = build_plan(profile, config_path=config)
        assert plan.changed
        assert "+[certmap/domain-b.local/TEST-UPN]" in plan.diff
        assert config.read_text() == before

    def test_dry_run_writes_nothing(self, tmp_path):
        config, profile = self._setup(tmp_path)
        before = config.read_text()
        result = apply_plan(build_plan(profile, config_path=config), dry_run=True)
        assert not result.applied
        assert config.read_text() == before

    def test_apply_writes_and_is_idempotent(self, tmp_path):
        config, profile = self._setup(tmp_path)
        apply_plan(
            build_plan(profile, config_path=config),
            dry_run=False,
            restart=False,
            validate=False,
            backup_dir=tmp_path / "backups",
        )
        text = config.read_text()
        assert "[certmap/domain-b.local/TEST-UPN]" in text
        assert "domains = domain-a.local" in text
        assert "pam_cert_auth = True" in text

        second = apply_plan(
            build_plan(profile, config_path=config),
            dry_run=False,
            restart=False,
            validate=False,
            backup_dir=tmp_path / "backups",
        )
        assert config.read_text() == text
        assert "already matches" in " ".join(second.log)

    def test_apply_leaves_a_backup(self, tmp_path):
        config, profile = self._setup(tmp_path)
        result = apply_plan(
            build_plan(profile, config_path=config),
            dry_run=False,
            restart=False,
            validate=False,
            backup_dir=tmp_path / "backups",
        )
        saved = result.backups.entries[0].saved
        assert saved.read_text() == SAMPLE

    def test_wrong_domain_blocks_the_apply(self, tmp_path):
        config, _ = self._setup(tmp_path)
        profile = load_profile_text(PROFILE_YAML.replace("domain: domain-b.local", "domain: nope.local"))
        plan = build_plan(profile, config_path=config)
        assert plan.blocking
        with pytest.raises(ApplyError):
            apply_plan(plan, dry_run=False, restart=False, validate=False)
        assert "certmap" not in config.read_text()

    def test_force_overrides_a_failed_check(self, tmp_path):
        config, _ = self._setup(tmp_path)
        profile = load_profile_text(PROFILE_YAML.replace("domain: domain-b.local", "domain: nope.local"))
        apply_plan(
            build_plan(profile, config_path=config),
            dry_run=False,
            restart=False,
            validate=False,
            backup_dir=tmp_path / "backups",
            force=True,
        )
        assert "certmap/nope.local/TEST-UPN" in config.read_text()

    def test_existing_section_is_flagged(self, tmp_path):
        config, profile = self._setup(tmp_path)
        config.write_text(SAMPLE + "\n[certmap/domain-b.local/TEST-UPN]\npriority = 1\n")
        plan = build_plan(profile, config_path=config)
        assert any("already exists" in w for w in plan.warnings)
