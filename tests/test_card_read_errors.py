"""Saying which link in the chain broke, instead of blaming the card.

`cert inspect --from-card` and `krb5 test --from-card` both failed with

    error: no readable certificate found on the card.

while `card detect`, run on the same host a minute later, reported
`[PASS] certificates  1 certificate(s) found`. Two commands in one tool
disagreeing about one card. The card was almost certainly held by a login or
screen-lock helper at that moment -- there were three p11_child/gdm processes
running -- but the message said *no certificate*, which sends the operator to
look at provisioning for what was contention.

The scan already knows: `CardScan.checks` carries the FAIL that explains which
step failed. The message threw it away. These tests pin the three distinct
outcomes apart, because they have three different remedies:

* the card could not be read at all -- retry, or find what is holding it
* the card was read and holds nothing -- it is not provisioned
* the card holds certificates but none is an authentication certificate --
  choose one with --cert-id
"""

from __future__ import annotations

import pytest

from sssd_smartcard import cli
from sssd_smartcard.errors import SmartCardError
from sssd_smartcard.pkcs11.detect import CardCertificate, CardScan, Reader
from sssd_smartcard.report import Printer
from sssd_smartcard.util import Check


class Args:
    """Only the attributes the loader reads."""

    def __init__(self):
        self.file = None
        self.base64 = None
        self.stdin = False
        self.from_card = True
        self.cert_id = None
        self.module = None
        self.slot = None


def load_with(monkeypatch, scan_result):
    monkeypatch.setattr(
        "sssd_smartcard.pkcs11.detect.scan", lambda **kw: scan_result
    )
    monkeypatch.setattr(
        "sssd_smartcard.pkcs11.detect.pick_authentication_certificate",
        lambda result: None,
    )
    with pytest.raises(SmartCardError) as excinfo:
        cli.resolve_certificate(Args(), Printer(colour=False))
    return str(excinfo.value)


class TestTheThreeOutcomesAreDistinguished:
    def test_unreadable_card_names_the_failing_step(self, monkeypatch):
        scan = CardScan(
            readers=[Reader(name="Reader 0", card_present=True)],
            checks=[Check("token", "FAIL", "no PKCS#11 token found")],
        )
        message = load_with(monkeypatch, scan)
        assert "could not be read" in message
        assert "no PKCS#11 token found" in message

    def test_a_card_in_the_reader_points_at_contention_not_provisioning(self, monkeypatch):
        """This is the case that actually happened."""
        scan = CardScan(
            readers=[Reader(name="Reader 0", card_present=True)],
            checks=[Check("token", "FAIL", "no PKCS#11 token found")],
        )
        message = load_with(monkeypatch, scan)
        assert "contention" in message
        assert "holding it" in message

    def test_an_empty_reader_does_not_claim_contention(self, monkeypatch):
        """Nothing is holding a card that is not there."""
        scan = CardScan(
            readers=[Reader(name="Reader 0", card_present=False)],
            checks=[Check("readers", "FAIL", "no reader detected")],
        )
        message = load_with(monkeypatch, scan)
        assert "contention" not in message
        assert "no reader detected" in message

    def test_a_read_card_with_nothing_on_it_says_so(self, monkeypatch):
        scan = CardScan(readers=[Reader(name="Reader 0", card_present=True)])
        message = load_with(monkeypatch, scan)
        assert "holds no certificate" in message
        assert "provisioned" in message

    def test_certificates_present_but_none_suitable_says_which_remedy(self, monkeypatch):
        scan = CardScan(
            readers=[Reader(name="Reader 0", card_present=True)],
            certificates=[
                CardCertificate(label="Key Management", object_id="02"),
                CardCertificate(label="Digital Signature", object_id="03"),
            ],
        )
        message = load_with(monkeypatch, scan)
        assert "2 certificate(s)" in message
        assert "--cert-id" in message

    def test_no_outcome_still_says_only_no_readable_certificate(self, monkeypatch):
        """The old wording blamed the card in every case; none should now."""
        for scan in (
            CardScan(readers=[Reader(name="R", card_present=True)],
                     checks=[Check("token", "FAIL", "x")]),
            CardScan(readers=[Reader(name="R", card_present=True)]),
            CardScan(readers=[Reader(name="R", card_present=True)],
                     certificates=[CardCertificate(label="x", object_id="02")]),
        ):
            assert "no readable certificate found" not in load_with(monkeypatch, scan)
