"""The Windows helper's message catalogue must stay complete.

``scripts/windows/New-SmartCardSshCommand.ps1`` emits every translatable line
through a catalogue keyed by message id, with an ``en`` string and either a
``pl`` translation or an explicit ``EnglishOnly`` marker. The marker is what
separates "we decided this stays English" from "somebody forgot", and without a
test the distinction decays the first time a message is added.

The script carries its own ``-SelfTest`` switch, which is the authoritative
check because it runs against the real parsed hashtable. This test parses the
same block so the invariant is enforced by ``pytest`` on any platform, with no
PowerShell installed -- the suite runs on Linux, where -SelfTest cannot.

It also checks the ``{0}``-style placeholders agree between the two languages.
A Polish string with a placeholder the English one lacks throws at runtime when
``-f`` is applied, and only on the code path that emits it, which is exactly the
sort of fault that reaches an operator rather than a test.
"""

from __future__ import annotations

import pathlib
import re

import pytest

SCRIPT = (
    pathlib.Path(__file__).resolve().parent.parent
    / "scripts"
    / "windows"
    / "New-SmartCardSshCommand.ps1"
)

ENTRY_RE = re.compile(r"^\s*'([^']+)' = @\{\s*$")
VALUE_RE = re.compile(r"^\s*(en|pl) = '(.*)'\s*$")
ENGLISH_ONLY_RE = re.compile(r"^\s*EnglishOnly = \$true\s*$")
CLOSE_RE = re.compile(r"^\s*\}\s*$")
PLACEHOLDER_RE = re.compile(r"\{(\d+)\}")


def parse_catalogue() -> dict[str, dict[str, object]]:
    """Pull the catalogue out of the PowerShell source.

    Deliberately simple: the catalogue is written one key per line with one
    value per line precisely so this stays a dozen lines of regex rather than a
    PowerShell parser.
    """
    text = SCRIPT.read_text(encoding="utf-8-sig")
    lines = text.split("\n")

    start = None
    for i, line in enumerate(lines):
        if line.strip().startswith("$script:Messages = @{"):
            start = i + 1
            break
    assert start is not None, "could not find $script:Messages in the script"

    entries: dict[str, dict[str, object]] = {}
    current_id = None
    current: dict[str, object] = {}

    for line in lines[start:]:
        if current_id is None and line.startswith("}"):
            break  # end of the hashtable

        m = ENTRY_RE.match(line)
        if m and current_id is None:
            current_id = m.group(1)
            current = {}
            continue

        if current_id is not None:
            mv = VALUE_RE.match(line)
            if mv:
                # '' is how a literal single quote is escaped in PowerShell.
                current[mv.group(1)] = mv.group(2).replace("''", "'")
                continue
            if ENGLISH_ONLY_RE.match(line):
                current["EnglishOnly"] = True
                continue
            if CLOSE_RE.match(line):
                entries[current_id] = current
                current_id = None
                current = {}
                continue

    return entries


#: Any line that opens a catalogue entry, in whatever shape. Used only to check
#: that the parser above saw everything -- a format it cannot read would
#: otherwise be skipped in silence, and the invariant would quietly stop
#: covering it. Measured: an entry written on one line as
#: ``'id' = @{ en = '...' }`` was invisible to ENTRY_RE and every test still
#: passed, which is the exact failure this guards.
ANY_ENTRY_RE = re.compile(r"^\s*'([^']+)'\s*=\s*@\{")


def catalogue_ids_in_source() -> set[str]:
    """Every id the file declares, independent of how it is laid out."""
    text = SCRIPT.read_text(encoding="utf-8-sig")
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip().startswith("$script:Messages = @{"):
            start = i + 1
            break
    assert start is not None
    ids: set[str] = set()
    depth = 0
    for line in lines[start:]:
        m = ANY_ENTRY_RE.match(line)
        if m:
            ids.add(m.group(1))
        if line.startswith("}") and depth == 0:
            break
    return ids


def test_the_parser_sees_every_entry_the_file_declares():
    """Otherwise an entry in an unparsed shape escapes every other test here.

    This is the guard on the guard. Without it the invariant covers only the
    entries written the way the parser expects, and PowerShell accepts several
    other shapes without complaint.
    """
    parsed = set(parse_catalogue())
    declared = catalogue_ids_in_source()
    missed = declared - parsed
    assert not missed, (
        "the catalogue declares entries the test parser did not read, so they "
        "are exempt from every check in this file: " + ", ".join(sorted(missed))
    )


@pytest.fixture(scope="module")
def catalogue() -> dict[str, dict[str, object]]:
    return parse_catalogue()


def test_the_catalogue_is_found_and_not_trivially_small(catalogue):
    """Guards against a parser that silently matches nothing."""
    assert len(catalogue) > 50, f"only parsed {len(catalogue)} messages"


def test_every_message_has_an_english_string(catalogue):
    missing = sorted(k for k, v in catalogue.items() if not v.get("en"))
    assert not missing, f"messages with no English text: {missing}"


def test_every_message_is_translated_or_marked_english_only(catalogue):
    """The invariant this file exists for."""
    missing = sorted(
        k
        for k, v in catalogue.items()
        if not v.get("pl") and not v.get("EnglishOnly")
    )
    assert not missing, (
        "messages with no Polish translation and no EnglishOnly marker: "
        f"{missing}"
    )


def test_english_only_messages_have_no_stray_translation(catalogue):
    """A message cannot be both deliberately English and translated."""
    both = sorted(
        k for k, v in catalogue.items() if v.get("EnglishOnly") and v.get("pl")
    )
    assert not both, f"marked EnglishOnly but also translated: {both}"


def test_placeholders_agree_between_languages(catalogue):
    """``-f`` throws when the argument count does not cover the placeholders."""
    bad = []
    for key, value in sorted(catalogue.items()):
        if not value.get("pl"):
            continue
        en = set(PLACEHOLDER_RE.findall(str(value["en"])))
        pl = set(PLACEHOLDER_RE.findall(str(value["pl"])))
        if en != pl:
            bad.append(f"{key}: en={sorted(en)} pl={sorted(pl)}")
    assert not bad, "placeholder mismatch:\n  " + "\n  ".join(bad)


def test_the_script_is_utf8_with_a_bom():
    """Windows PowerShell 5.1 assumes the ANSI code page without one.

    A BOM-less UTF-8 file renders the Polish diacritics as mojibake on 5.1 --
    the same class of failure that made a non-ASCII test fail elsewhere in this
    suite. Cheap to assert, expensive to rediscover.
    """
    raw = SCRIPT.read_bytes()
    assert raw[:3] == b"\xef\xbb\xbf", (
        "the script must be saved as UTF-8 with BOM for PowerShell 5.1"
    )


def test_polish_strings_actually_use_diacritics(catalogue):
    """A catalogue of ASCII-ised Polish would pass every test above.

    Polish prose of this volume cannot plausibly avoid the diacritics, so their
    near-absence means somebody stripped them rather than typed them.
    """
    polish_chars = set("ąćęłńóśźżĄĆĘŁŃÓŚŹŻ")
    with_diacritics = [
        k
        for k, v in catalogue.items()
        if v.get("pl") and polish_chars & set(str(v["pl"]))
    ]
    translated = [k for k, v in catalogue.items() if v.get("pl")]
    assert translated, "no translated messages found"
    ratio = len(with_diacritics) / len(translated)
    assert ratio > 0.5, (
        f"only {len(with_diacritics)} of {len(translated)} Polish strings "
        f"contain diacritics ({ratio:.0%}) -- they look ASCII-ised"
    )
