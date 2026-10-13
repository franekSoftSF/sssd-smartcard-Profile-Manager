"""An alternative UPN suffix is not a trusted domain.

A certificate whose UPN suffix differs from the joined domain means one of two
unrelated things, and the right configuration differs completely:

* the accounts live in a **trusted domain** — `domains=` directs the search
  there, and pinning the suffix is correct;
* Active Directory has **alternative UPN suffixes** — the same domain, with
  users logging in as `user@example.com` while the domain is `ad.example.com`.
  Here `domains=` names a domain SSSD has never heard of, so every lookup
  fails, and pinning the one suffix rejects every card issued under another.

Measured on a lab whose AD UPN is aligned with Entra ID: the card carried
`@example.com` while the host was joined to `ad.example.com`, and the generated
rule came out with `domains = example.com` — a domain `sssctl domain-list` does
not list. The question that separates the two cases is whether that suffix is a
domain SSSD actually knows, which the tool could already answer; it warned
about it and then generated the trusted-domain shape anyway.

Several suffixes are not handled by listing them: `||` in a matching rule
leaves the literal operator in the preceding component's value, which is
measured in test_matchrule_syntax. Accepting any suffix is one rule, and the
trust still rests on the pinned issuer and EKU plus the LDAP lookup.
"""

from __future__ import annotations

import pytest

from sssd_smartcard.certmap.compat import Version
from sssd_smartcard.certmap.mappings import build_rule
from sssd_smartcard.x509.recommend import build_profile, recommend

V = Version.parse("2.9.4")

JOINED = "ad.example.com"


def profile_for(cert, *, sssd_domains):
    """What the tool would generate on a host knowing *sssd_domains*."""
    return build_profile(
        recommend(cert, version=V),
        section_domain=JOINED,
        sssd_domains=sssd_domains,
    )


@pytest.fixture
def upn_cert(piv_cert, monkeypatch):
    """A certificate whose UPN suffix differs from the joined domain."""
    return piv_cert


class TestTrustedDomain:
    """The suffix IS a domain SSSD knows: direct the search there."""

    def test_domains_is_emitted(self, piv_cert):
        account = recommend(piv_cert, version=V).domain
        profile = profile_for(piv_cert, sssd_domains=[JOINED, account])
        assert profile.mapping.domains == [account]

    def test_the_suffix_is_pinned(self, piv_cert):
        account = recommend(piv_cert, version=V).domain
        profile = profile_for(piv_cert, sssd_domains=[JOINED, account])
        rule = build_rule(profile, version=V)
        rendered = rule.matchrule.render()
        assert account.replace(".", "\\.") in rendered

    def test_any_suffix_is_not_set(self, piv_cert):
        account = recommend(piv_cert, version=V).domain
        profile = profile_for(piv_cert, sssd_domains=[JOINED, account])
        assert profile.mapping.options.get("any_suffix") is not True


class TestAlternativeUpnSuffix:
    """The suffix is NOT a domain SSSD knows: it is a UPN suffix, not a domain."""

    def test_domains_is_not_emitted(self, piv_cert):
        profile = profile_for(piv_cert, sssd_domains=[JOINED])
        assert profile.mapping.domains == [], (
            "domains= would name a domain SSSD has never heard of"
        )

    def test_any_suffix_is_set_instead_of_pinning_one(self, piv_cert):
        profile = profile_for(piv_cert, sssd_domains=[JOINED])
        assert profile.mapping.options.get("any_suffix") is True
        assert "upn_suffix" not in profile.mapping.options

    def test_the_rule_accepts_any_suffix(self, piv_cert):
        """A lab can have several suffixes; one rule has to cover them all."""
        profile = profile_for(piv_cert, sssd_domains=[JOINED])
        rendered = build_rule(profile, version=V).matchrule.render()
        assert "<SAN:ntPrincipalName>.*" in rendered
        account = recommend(piv_cert, version=V).domain
        assert account.replace(".", "\\.") not in rendered

    def test_the_issuer_is_still_pinned(self, piv_cert):
        """Dropping the suffix anchor must not drop the trust anchor."""
        profile = profile_for(piv_cert, sssd_domains=[JOINED])
        rendered = build_rule(profile, version=V).matchrule.render()
        assert rendered.startswith("KRB5:<ISSUER>^")
        assert "<EKU>" in rendered

    def test_a_certificate_from_another_ca_is_still_rejected(self, piv_cert):
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        import conftest
        from sssd_smartcard.certmap.evaluator import evaluate_match

        profile = profile_for(piv_cert, sssd_domains=[JOINED])
        rule = build_rule(profile, version=V)
        original = conftest.ISSUER_DN_PARTS[:]
        try:
            conftest.ISSUER_DN_PARTS[:] = [
                x509.NameAttribute(NameOID.COMMON_NAME, "Rogue CA")
            ]
            rogue = conftest.build_cert()
        finally:
            conftest.ISSUER_DN_PARTS[:] = original
        assert not evaluate_match(rule.matchrule, rogue).matched

    def test_the_real_certificate_still_matches(self, piv_cert):
        from sssd_smartcard.certmap.evaluator import evaluate_match

        profile = profile_for(piv_cert, sssd_domains=[JOINED])
        rule = build_rule(profile, version=V)
        assert evaluate_match(rule.matchrule, piv_cert).matched


class TestWhenTheDomainsAreUnknown:
    """Offline, or no sssd.conf: do not guess the restrictive shape."""

    def test_no_domain_list_keeps_the_trusted_domain_reading(self, piv_cert):
        account = recommend(piv_cert, version=V).domain
        profile = profile_for(piv_cert, sssd_domains=None)
        assert profile.mapping.domains == [account]

    def test_an_empty_domain_list_is_treated_as_unknown(self, piv_cert):
        account = recommend(piv_cert, version=V).domain
        profile = profile_for(piv_cert, sssd_domains=[])
        assert profile.mapping.domains == [account]


class TestSameDomain:
    """No difference to resolve."""

    def test_nothing_special_happens(self, piv_cert):
        account = recommend(piv_cert, version=V).domain
        profile = build_profile(
            recommend(piv_cert, version=V),
            section_domain=account,
            sssd_domains=[account],
        )
        assert profile.mapping.domains == []
        assert profile.mapping.options.get("any_suffix") is not True
