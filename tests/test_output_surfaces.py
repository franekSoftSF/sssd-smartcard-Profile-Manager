"""Every surface that shows the renderer's warnings must show its notes too.

`config apply` printed `rendered.warnings` and dropped `rendered.notes`.  The
notes are where the renderer explains the options it just wrote -- that SSSD
never refreshes `crl_file` and needs a timer, that enabling OCSP does not relax
the per-CA CRL requirement -- so all of it was visible in `config render` and
`cert autoconfig` and invisible in the one command that changes the system.

The bug is not a missing string, it is a surface forgetting a field, which is
why this checks the shape of the code rather than one message: a function that
reaches for `.warnings` and never for `.notes` has almost certainly dropped
them.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

CLI = pathlib.Path(__file__).resolve().parent.parent / "src" / "sssd_smartcard" / "cli.py"


def attribute_names(node: ast.AST) -> set[str]:
    return {n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)}


def command_functions() -> list[ast.FunctionDef]:
    tree = ast.parse(CLI.read_text(encoding="utf-8"))
    return [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name.startswith("cmd_")
    ]


def surfaces_that_print_warnings() -> list[ast.FunctionDef]:
    out = []
    for fn in command_functions():
        attrs = attribute_names(fn)
        # "warnings" reached through a rendered config, not doctor's own checks.
        if "warnings" in attrs and {"rendered", "to_ini", "manual_steps"} & attrs:
            out.append(fn)
    return out


def test_there_is_something_to_check():
    """Guard the guard: a renamed field would make this file silently vacuous."""
    names = [fn.name for fn in surfaces_that_print_warnings()]
    assert names, "no command surfaces found -- has RenderedConfig been renamed?"
    assert "cmd_config_apply" in names, names


@pytest.mark.parametrize(
    "name", [fn.name for fn in surfaces_that_print_warnings()]
)
def test_a_surface_showing_warnings_also_shows_notes(name):
    fn = next(f for f in surfaces_that_print_warnings() if f.name == name)
    assert "notes" in attribute_names(fn), (
        f"{name} prints the renderer's warnings but not its notes; the notes "
        "carry what the renderer knows about the options it just wrote"
    )
