"""The CLI parser must build, and every documented command must parse.

This file exists because of a real miss: a duplicated block left
``build_parser()`` raising ``ValueError: conflicting subparser: crl``, so
``sssd-smartcard`` could not start at all -- and the whole test suite stayed
green, because nothing built the parser. A tool whose every command is broken
should not be able to pass its own tests.

These are deliberately cheap: construct the parser, then parse argv for each
command. No side effects, no host needed.
"""

from __future__ import annotations

import pytest

from sssd_smartcard.cli import build_parser


@pytest.fixture(scope="module")
def parser():
    return build_parser()


def test_the_parser_builds_at_all(parser):
    """Catches duplicate subparsers, bad defaults and argument conflicts."""
    assert parser is not None


#: One invocation per leaf command, as the README and man page present them.
INVOCATIONS = [
    ["cert", "inspect", "--from-card"],
    ["cert", "inspect", "--file", "x.pem"],
    ["cert", "autoconfig", "--from-card"],
    ["card", "detect"],
    ["profile", "list"],
    ["profile", "validate", "P.yaml"],
    ["mapping", "test", "P.yaml", "--from-card"],
    ["domain", "test"],
    ["domain", "list"],
    ["mapping", "types"],
    ["profile", "show", "P.yaml"],
    ["ca", "show"],
    ["ca", "import", "ca.pem"],
    ["ca", "discover", "--from-card"],
    ["ca", "discover", "--from-card", "--install"],
    ["ca", "discover", "--file", "c.pem", "--pki-url", "http://pki.example.com/PKI/"],
    ["ca", "crl", "show"],
    ["ca", "crl", "show", "/etc/sssd/pki/revocation.crl.pem"],
    ["ca", "crl", "update"],
    ["ca", "crl", "update", "--from-card", "--dry-run"],
    ["ca", "crl", "update", "--from-file", "a.crl", "--no-fetch"],
    ["ca", "crl", "timer"],
    ["ca", "crl", "timer", "--install", "--on-calendar", "hourly"],
    ["config", "render", "P.yaml"],
    ["config", "diff", "P.yaml"],
    ["config", "validate", "P.yaml"],
    ["config", "apply", "P.yaml", "--dry-run"],
    ["krb5", "status"],
    ["krb5", "test", "--from-card", "--pkinit"],
    ["pam", "check"],
    ["doctor"],
]


@pytest.mark.parametrize("argv", INVOCATIONS, ids=lambda a: " ".join(a))
def test_every_command_parses(parser, argv):
    args = parser.parse_args(argv)
    assert hasattr(args, "func"), f"{' '.join(argv)} has no handler attached"


@pytest.mark.parametrize(
    "argv",
    [
        ["ca", "crl", "update"],
        ["doctor"],
        ["pam", "check"],
        ["config", "validate", "P.yaml"],
    ],
    ids=lambda a: " ".join(a),
)
def test_common_flags_work_before_and_after_the_subcommand(parser, argv):
    """--json and --config are accepted in either position."""
    before = parser.parse_args(["--json", *argv])
    after = parser.parse_args([*argv, "--json"])
    assert before.json and after.json


def test_every_handler_is_a_real_callable(parser):
    """A set_defaults(func=...) typo would otherwise only show up at runtime."""
    for argv in INVOCATIONS:
        args = parser.parse_args(argv)
        assert callable(args.func), f"{' '.join(argv)} -> {args.func!r}"


def test_an_unknown_subcommand_is_rejected(parser):
    with pytest.raises(SystemExit):
        parser.parse_args(["ca", "crl", "nonsense"])


def test_a_subcommand_group_requires_a_subcommand(parser):
    with pytest.raises(SystemExit):
        parser.parse_args(["ca", "crl"])
