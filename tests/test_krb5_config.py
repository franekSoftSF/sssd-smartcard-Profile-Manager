"""Kerberos client configuration: includedir and PKINIT anchors.

Both of these were found on the verified lab host after card login already
worked, which is the point: a host can authenticate with a Smart Card perfectly
and still be unable to obtain a ticket, because login is local authentication
and a TGT needs PKINIT. The two mechanisms share nothing but the certificate.

The lab host's `/etc/krb5.conf` was the stock MIT sample plus a `default_realm`
line. SSSD had written `domain_realm_*` and `localauth_plugin` snippets into
`/var/lib/sss/pubconf/krb5.include.d/`, and krb5.conf never included that
directory, so they did nothing at all.
"""

from __future__ import annotations

from sssd_smartcard.krb5 import check as krb5

STOCK = (
    "[libdefaults]\n"
    "default_realm = AD.EXAMPLE.COM\n"
    "\tkdc_timesync = 1\n"
    "\tccache_type = 4\n"
    "[realms]\n"
    "\tATHENA.MIT.EDU = {\n"
    "\t\tkdc = kerberos.mit.edu\n"
    "\t}\n"
)

WITH_INCLUDE = f"includedir {krb5.SSSD_KRB5_INCLUDE_DIR}/\n" + STOCK


def write(tmp_path, text: str, name: str = "krb5.conf"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


class TestIncludedir:
    def test_the_stock_file_includes_nothing(self, tmp_path):
        assert krb5.included_dirs(write(tmp_path, STOCK)) == []

    def test_an_includedir_line_is_found(self, tmp_path):
        dirs = krb5.included_dirs(write(tmp_path, WITH_INCLUDE))
        assert dirs == [krb5.SSSD_KRB5_INCLUDE_DIR + "/"]

    def test_a_trailing_slash_does_not_defeat_the_comparison(self, tmp_path):
        """The check compares with rstrip('/'), because both spellings occur."""
        dirs = krb5.included_dirs(write(tmp_path, WITH_INCLUDE))
        assert any(
            d.rstrip("/") == krb5.SSSD_KRB5_INCLUDE_DIR.rstrip("/") for d in dirs
        )

    def test_several_includedirs_are_all_returned(self, tmp_path):
        text = "includedir /etc/krb5.conf.d/\n" + WITH_INCLUDE
        assert len(krb5.included_dirs(write(tmp_path, text))) == 2

    def test_a_missing_file_is_not_a_crash(self, tmp_path):
        assert krb5.included_dirs(str(tmp_path / "nope.conf")) == []

    def test_snippets_of_a_missing_directory_are_empty(self, tmp_path):
        assert krb5.sssd_snippets(str(tmp_path / "nope")) == []

    def test_snippets_are_listed_and_sorted(self, tmp_path):
        directory = tmp_path / "include.d"
        directory.mkdir()
        (directory / "localauth_plugin").write_text("x", encoding="utf-8")
        (directory / "domain_realm_ad").write_text("y", encoding="utf-8")
        assert krb5.sssd_snippets(str(directory)) == [
            "domain_realm_ad",
            "localauth_plugin",
        ]


class TestPkinitAnchors:
    def test_the_stock_file_has_none(self, tmp_path):
        assert krb5.pkinit_anchors_configured(write(tmp_path, STOCK)) == []

    def test_an_anchor_in_libdefaults_is_found(self, tmp_path):
        text = STOCK.replace(
            "default_realm = AD.EXAMPLE.COM",
            "default_realm = AD.EXAMPLE.COM\n"
            "pkinit_anchors = FILE:/etc/sssd/pki/sssd_auth_ca_db.pem",
        )
        assert krb5.pkinit_anchors_configured(write(tmp_path, text)) == [
            "FILE:/etc/sssd/pki/sssd_auth_ca_db.pem"
        ]

    def test_an_anchor_inside_an_included_directory_is_found(self, tmp_path):
        """The real-world case: the anchor lives in a snippet, not in krb5.conf."""
        directory = tmp_path / "include.d"
        directory.mkdir()
        (directory / "pkinit").write_text(
            "[libdefaults]\npkinit_anchors = DIR:/etc/krb5/anchors\n", encoding="utf-8"
        )
        path = write(tmp_path, f"includedir {directory}\n" + STOCK)
        assert krb5.pkinit_anchors_configured(path) == ["DIR:/etc/krb5/anchors"]

    def test_an_unreadable_included_directory_is_skipped(self, tmp_path):
        path = write(tmp_path, f"includedir {tmp_path / 'absent'}\n" + STOCK)
        assert krb5.pkinit_anchors_configured(path) == []

    def test_default_realm_still_parses_from_the_stock_file(self, tmp_path):
        assert (
            krb5.default_realm(write(tmp_path, STOCK)) == "AD.EXAMPLE.COM"
        )
