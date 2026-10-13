"""Exception hierarchy.

Every error that is expected during normal operation (bad profile, missing
tool, unreadable certificate) derives from ``SmartCardError`` so the CLI can
print it without a traceback.
"""

from __future__ import annotations


class SmartCardError(Exception):
    """Base class for all expected errors."""

    exit_code = 1


class ProfileError(SmartCardError):
    """Profile file is missing, malformed or semantically invalid."""


class UnsupportedFeature(SmartCardError):
    """The requested feature is not available in the target SSSD version."""

    exit_code = 3


class CertificateError(SmartCardError):
    """Certificate could not be read or parsed."""


class RuleSyntaxError(SmartCardError):
    """A certmap matchrule/maprule could not be parsed."""


class ToolMissing(SmartCardError):
    """An external helper (sssctl, pkcs11-tool, ...) is not installed."""

    exit_code = 4


class PlatformUnsupported(SmartCardError):
    """Operation only makes sense on the SSSD host itself."""

    exit_code = 5


class ApplyError(SmartCardError):
    """Configuration could not be applied; a rollback may have happened."""

    exit_code = 6
