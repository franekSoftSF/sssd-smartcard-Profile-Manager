"""Plan, diff, apply and roll back configuration changes.

The contract this module keeps:

* nothing is written before a backup exists;
* ``sssd.conf`` is written atomically and never loses mode 0600;
* the new configuration is validated with ``sssctl config-check`` and the
  service is restarted only after that passes;
* any failure -- validation, restart, or the service not coming back -- rolls
  every touched file back to exactly what it was;
* the PAM stack is never edited, only reported on, because a bad PAM file locks
  the administrator out of the machine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..backup import BackupSet, check_mode, new_backup_set, write_atomic
from ..ca.trust import BundlePlan, apply_bundle, plan_bundle
from ..certmap.compat import DEFAULT_VERSION, Version
from ..certmap.renderer import ConfigChange, RenderedConfig, render
from ..errors import ApplyError
from ..model.profile import SmartCardProfile
from ..util import Check, is_linux
from .conf import DEFAULT_CONFIG, SssdConfig, unified_diff
from .runtime import config_check, restart_sssd, service_active

#: sssd.conf must not be readable by anyone but its owner.
CONFIG_MODE = 0o600


@dataclass
class ApplyPlan:
    """Everything that would change, computed without touching the system."""

    profile: SmartCardProfile
    rendered: RenderedConfig
    config_path: Path
    before: str
    after: str
    applied_changes: list[ConfigChange] = field(default_factory=list)
    unchanged: list[ConfigChange] = field(default_factory=list)
    bundle: BundlePlan | None = None
    checks: list[Check] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def diff(self) -> str:
        return unified_diff(self.before, self.after, path=str(self.config_path))

    @property
    def changed(self) -> bool:
        return self.before != self.after or bool(self.bundle and self.bundle.changed)

    @property
    def blocking(self) -> list[Check]:
        return [c for c in self.checks if c.failed]

    def to_dict(self) -> dict:
        return {
            "profile": self.profile.name,
            "config_path": str(self.config_path),
            "changed": self.changed,
            "diff": self.diff,
            "applied_changes": [c.to_dict() for c in self.applied_changes],
            "already_present": [c.to_dict() for c in self.unchanged],
            "ca_bundle": self.bundle.to_dict() if self.bundle else None,
            "manual_steps": [s.to_dict() for s in self.rendered.manual_steps],
            "notes": self.rendered.notes,
            "warnings": self.warnings + self.rendered.warnings,
            "checks": [
                {"name": c.name, "status": c.status, "detail": c.detail, "hint": c.hint}
                for c in self.checks
            ],
        }


def _merge_local_auth_policy(config: SssdConfig, rendered: RenderedConfig) -> list[str]:
    """Keep any ``local_auth_policy`` methods the host already enabled.

    Overwriting the value would silently turn off, say, ``enable:passkey`` that
    somebody else configured.  The rendered change is rewritten in place to the
    union of both, and the caller is told what happened.
    """
    notes: list[str] = []
    refused: list[ConfigChange] = []
    for change in rendered.changes:
        if change.key != "local_auth_policy":
            continue
        current = config.get(change.section, change.key)
        if not current:
            continue
        existing = [t.strip() for t in current.split(",") if t.strip()]
        lowered = {t.lower() for t in existing}
        wanted = [t.strip() for t in change.value.split(",") if t.strip()]
        extra = [t for t in wanted if t.lower() not in lowered]
        if not extra:
            continue
        if "only" in lowered or any(t.lower() == "only" for t in wanted):
            # Leave the existing value untouched: 'only' decides which methods
            # are offered at all, and guessing at that could lock people out.
            refused.append(change)
            notes.append(
                f"[{change.section}] local_auth_policy is left at {current!r}. "
                f"It would have become {change.value!r}, but 'only' changes which "
                "methods are offered at all, so it is not merged automatically -- "
                "set authentication.local_auth_policy explicitly to the value you "
                "want. Until then the Smart Card is not authenticated locally."
            )
            continue
        merged = ", ".join(existing + extra)
        change.value = merged
        notes.append(
            f"[{change.section}] local_auth_policy was already {current!r}; the "
            f"Smart Card method is added rather than replacing it, giving {merged!r}."
        )
    for change in refused:
        rendered.changes.remove(change)
    return notes


def build_plan(
    profile: SmartCardProfile,
    *,
    config_path: str | Path = DEFAULT_CONFIG,
    version: Version = DEFAULT_VERSION,
    verification_scope: str = "sssd",
    allow_degraded: bool = False,
    import_ca: bool = True,
) -> ApplyPlan:
    """Compute the full change set for *profile*."""
    config_path = Path(config_path)
    rendered = render(
        profile,
        version=version,
        verification_scope=verification_scope,
        allow_degraded=allow_degraded,
    )
    config = SssdConfig.load(config_path)
    before = config.render()

    working = config.copy()
    applied: list[ConfigChange] = []
    unchanged: list[ConfigChange] = []
    merge_notes = _merge_local_auth_policy(config, rendered)
    for change in rendered.changes:
        if working.set(change.section, change.key, change.value):
            applied.append(change)
        else:
            unchanged.append(change)
    after = working.render()

    checks: list[Check] = []
    warnings: list[str] = list(merge_notes)

    # Mode of the existing file.
    if config_path.exists():
        ok, mode = check_mode(config_path, CONFIG_MODE)
        checks.append(
            Check(
                "sssd.conf permissions",
                "PASS" if ok else "WARN",
                f"mode {oct(mode) if mode is not None else 'unknown'}",
                hint="" if ok else f"SSSD refuses a world/group readable sssd.conf; "
                f"this tool will write it back as {oct(CONFIG_MODE)}.",
            )
        )
    else:
        checks.append(
            Check(
                "sssd.conf",
                "WARN",
                f"{config_path} does not exist; a new file would be created",
                hint="A Smart Card profile alone is not a working SSSD configuration -- "
                "the host still needs its domain joined and configured.",
            )
        )

    # The domain the rule attaches to should actually be configured.
    configured = config.domains()
    if configured and profile.domain not in configured:
        checks.append(
            Check(
                "domain",
                "FAIL",
                f"[sssd] domains = {', '.join(configured)} does not include "
                f"{profile.domain}",
                hint="The certmap section is keyed on an SSSD domain. Use the domain "
                "this host is joined to, and put the account's domain in "
                "mapping.domains instead.",
            )
        )
    elif configured:
        checks.append(Check("domain", "PASS", f"{profile.domain} is a configured domain"))

    # access_provider = ad brings GPO-based access control with it, and
    # ad_gpo_access_control defaults to enforcing.  Measured: a card login whose
    # auth phase succeeded was refused in the *account* phase because one Group
    # Policy Container was unreadable, so the GPO list could not be built --
    # "Unable to get GPO list ... [14](Bad address)", and enforcing turns that
    # into a denial.  GDM reports the whole thing as "smart card authentication
    # didn't work", which sends the operator looking at the card.  realm join
    # writes access_provider = ad, so this is the default state of a freshly
    # joined host, and nothing in a Smart Card profile touches it.
    domain_section = f"domain/{profile.domain}"
    if (
        working.get(domain_section, "access_provider") == "ad"
        and not working.get(domain_section, "ad_gpo_access_control")
    ):
        checks.append(
            Check(
                "GPO access control",
                "WARN",
                f"[{domain_section}] has access_provider = ad and no "
                "ad_gpo_access_control, so it defaults to enforcing",
                hint="SSSD will evaluate the Windows logon rights through GPO after "
                "the card has already authenticated. If the GPO list cannot be "
                "built -- an unreadable Group Policy Container is enough -- the "
                "login is denied in the account phase, and the greeter blames the "
                "card. Set gpo.manage with gpo.access_control: permissive in the "
                "profile to see what it would decide without being denied, then "
                "move to enforcing once the GPOs are readable (gpo.ignore_unreadable "
                "skips one that is not). Verify both phases: "
                "pamtester login <user> authenticate acct_mgmt",
            )
        )

    # A pre-existing section with the same name is overwritten key by key.
    if config.has_section(profile.section):
        existing = config.items(profile.section)
        warnings.append(
            f"[{profile.section}] already exists with "
            f"{len(existing)} setting(s); matching keys will be overwritten and any "
            "other keys left alone."
        )

    # Other certmap rules can win on priority.
    others = [s for s in config.certmap_sections() if s != profile.section]
    if others:
        checks.append(
            Check(
                "other certmap rules",
                "INFO",
                ", ".join(others),
                hint="Rules are tried by priority (0 highest). Set mapping.priority if "
                "ordering matters.",
            )
        )

    bundle = None
    if import_ca and profile.ca_trust.sources:
        bundle = plan_bundle(profile.ca_trust.sources, profile.ca_trust.bundle_path)
        warnings.extend(bundle.warnings)

    return ApplyPlan(
        profile=profile,
        rendered=rendered,
        config_path=config_path,
        before=before,
        after=after,
        applied_changes=applied,
        unchanged=unchanged,
        bundle=bundle,
        checks=checks,
        warnings=warnings,
    )


@dataclass
class ApplyResult:
    """What actually happened."""

    plan: ApplyPlan
    dry_run: bool
    applied: bool = False
    rolled_back: bool = False
    backups: BackupSet | None = None
    log: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "dry_run": self.dry_run,
            "applied": self.applied,
            "rolled_back": self.rolled_back,
            "backups": self.backups.to_dict() if self.backups else None,
            "log": self.log,
            "error": self.error,
            "plan": self.plan.to_dict(),
        }


def apply_plan(
    plan: ApplyPlan,
    *,
    dry_run: bool = True,
    restart: bool = True,
    validate: bool = True,
    backup_dir: str | Path | None = None,
    force: bool = False,
) -> ApplyResult:
    """Apply *plan*, rolling back on any failure."""
    result = ApplyResult(plan=plan, dry_run=dry_run)

    blocking = plan.blocking
    if blocking and not force:
        raise ApplyError(
            "refusing to apply, these checks failed:\n"
            + "\n".join(f"  - {c.name}: {c.detail}" for c in blocking)
            + "\nRe-run with --force to override."
        )

    if dry_run:
        result.log.append("dry run: nothing was written")
        return result

    if not plan.changed:
        result.log.append("configuration already matches the profile; nothing to do")
        result.applied = True
        return result

    backups = new_backup_set(backup_dir)
    result.backups = backups

    try:
        backups.add(plan.config_path)
        write_atomic(plan.config_path, plan.after, mode=CONFIG_MODE)
        result.log.append(f"wrote {plan.config_path} (mode {oct(CONFIG_MODE)})")

        if plan.bundle and plan.bundle.changed:
            apply_bundle(plan.bundle, backups)
            result.log.append(
                f"updated CA bundle {plan.bundle.path} "
                f"(+{len(plan.bundle.added)} certificate(s))"
            )

        if validate and is_linux():
            check = config_check(str(plan.config_path))
            if check.found and not check.ok:
                raise ApplyError(
                    "sssctl config-check rejected the new configuration:\n"
                    + (check.output or "(no output)")
                )
            result.log.append(
                "sssctl config-check passed"
                if check.found
                else "sssctl not installed; skipped config-check"
            )

        if restart and is_linux():
            restarted = restart_sssd()
            if restarted.found and not restarted.ok:
                raise ApplyError(
                    "systemctl restart sssd failed:\n" + (restarted.output or "")
                )
            if restarted.found:
                active, state = service_active()
                if active is False:
                    raise ApplyError(f"sssd did not come back up (state: {state})")
                result.log.append(f"sssd restarted (state: {state})")
            else:
                result.log.append("systemctl not available; SSSD was not restarted")
        elif restart:
            result.log.append("not running on the SSSD host; SSSD was not restarted")

        result.applied = True
        return result

    except Exception as exc:
        result.error = str(exc)
        result.log.append(f"FAILED: {exc}")
        result.log.extend(backups.rollback())
        result.rolled_back = True
        if is_linux() and restart:
            back = restart_sssd()
            result.log.append(
                "sssd restarted with the previous configuration"
                if back.ok
                else f"could not restart sssd after rollback: {back.output}"
            )
        raise ApplyError(
            f"{exc}\n\nEverything was rolled back:\n"
            + "\n".join(f"  {line}" for line in result.log)
        ) from exc
