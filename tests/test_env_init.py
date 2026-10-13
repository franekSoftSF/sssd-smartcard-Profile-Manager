"""The environment-file generator behind `ad-prepare --init-env`.

`scripts/lib/env.py` is a helper the shell scripts call, not part of the
importable package, so it is exercised the way they call it: as a subprocess.

What matters here is that anything derivable from the domain actually gets
derived. A file carrying a real domain next to the example realm is worse than
one that is obviously untouched: the placeholder guard would pass it, and the
operator would be left wondering which half of the file is theirs.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

ENV_PY = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "lib" / "env.py"


def init(*pairs: str) -> dict:
    result = subprocess.run(
        [sys.executable, str(ENV_PY), "--init", *pairs],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def init_fails(*pairs: str) -> str:
    result = subprocess.run(
        [sys.executable, str(ENV_PY), "--init", *pairs],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    return result.stderr


class TestTemplate:
    def test_the_bare_template_is_valid_json_with_every_key(self):
        data = init()
        for key in (
            "domain", "realm", "dns", "search", "hostname", "role",
            "join_user", "test_user", "ca", "crl", "ocsp", "desktop",
            "smartcard_required", "notes",
        ):
            assert key in data, key

    def test_types_are_what_the_loader_expects(self):
        data = init()
        assert isinstance(data["dns"], list)
        assert isinstance(data["ca"], list)
        assert isinstance(data["crl"], bool)
        assert isinstance(data["domain"], str)

    def test_the_bare_template_is_obviously_unfilled(self):
        """So the placeholder guard catches it rather than applying it."""
        data = init()
        assert data["domain"] == "ad.example.com"
        assert data["dns"] == ["10.0.0.10"]


class TestDerivedFromDomain:
    def test_realm_search_and_test_user_follow_the_domain(self):
        data = init("domain=ad.corp.test")
        assert data["realm"] == "AD.CORP.TEST"
        assert data["search"] == ["ad.corp.test"]
        assert data["test_user"] == "someone@ad.corp.test"

    def test_an_explicit_realm_is_not_overwritten(self):
        data = init("domain=ad.corp.test", "realm=OTHER.REALM")
        assert data["realm"] == "OTHER.REALM"

    def test_an_explicit_search_is_not_overwritten(self):
        data = init("domain=ad.corp.test", "search=a.test,b.test")
        assert data["search"] == ["a.test", "b.test"]

    def test_nothing_is_derived_without_a_domain(self):
        """A template nobody has touched must stay recognisably a template."""
        data = init("hostname=srv01")
        assert data["realm"] == "AD.EXAMPLE.COM"
        assert data["hostname"] == "srv01"


class TestValues:
    def test_a_list_takes_a_comma_separated_value(self):
        data = init("dns=10.1.1.1,10.1.1.2 , 10.1.1.3")
        assert data["dns"] == ["10.1.1.1", "10.1.1.2", "10.1.1.3"]

    def test_a_single_value_still_becomes_a_list(self):
        assert init("dns=10.1.1.1")["dns"] == ["10.1.1.1"]

    @pytest.mark.parametrize(
        "value,expected",
        [("true", True), ("True", True), ("yes", True), ("1", True),
         ("false", False), ("no", False), ("0", False), ("off", False)],
    )
    def test_booleans_accept_the_usual_spellings(self, value, expected):
        assert init(f"crl={value}")["crl"] is expected

    def test_an_empty_value_keeps_the_default(self):
        """So a discovery that found nothing does not blank the field."""
        assert init("dns=")["dns"] == ["10.0.0.10"]

    def test_an_unknown_key_is_refused(self):
        assert "unknown key" in init_fails("nonsense=1")

    def test_a_value_with_spaces_survives(self):
        data = init("notes=second test PKI, two machines")
        assert data["notes"] == "second test PKI, two machines"

    def test_non_ascii_survives(self):
        data = init("notes=środowisko testowe")
        assert data["notes"] == "środowisko testowe"


class TestLoaderAgreement:
    """What --init writes, the loader must accept."""

    def test_a_generated_file_loads_back_without_complaint(self, tmp_path):
        data = init("domain=ad.corp.test", "dns=10.1.1.1", "hostname=srv01")
        path = tmp_path / "environment.json"
        path.write_text(json.dumps(data), encoding="utf-8")

        scalars = ("domain realm hostname join_user test_user account_domain "
                   "sssd_domain desktop_package crl_file role notes")
        lists = "dns search ca"
        bools = "desktop gpo adsys crl ocsp smartcard_required"
        result = subprocess.run(
            [sys.executable, str(ENV_PY), str(path), scalars, lists, bools],
            capture_output=True, text=True, check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "ENV_DOMAIN=ad.corp.test" in result.stdout
        assert "ENV_REALM=AD.CORP.TEST" in result.stdout
        # shlex.quote leaves a value needing no quoting alone, so this is the
        # literal form the shell eval sees.
        assert "ENV_DNS=(10.1.1.1)" in result.stdout

    def test_every_generated_key_is_one_the_loader_knows(self, tmp_path):
        """A key --init emits but the loader refuses would be a hard failure."""
        data = init("domain=ad.corp.test")
        path = tmp_path / "environment.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        scalars = ("domain realm hostname join_user test_user account_domain "
                   "sssd_domain desktop_package crl_file role notes")
        result = subprocess.run(
            [sys.executable, str(ENV_PY), str(path), scalars, "dns search ca",
             "desktop gpo adsys crl ocsp smartcard_required"],
            capture_output=True, text=True, check=False,
        )
        assert result.returncode == 0, result.stderr
