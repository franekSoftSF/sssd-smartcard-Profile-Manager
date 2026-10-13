"""Matching-rule syntax, as libsss_certmap actually parses it.

Every expectation here was measured against SSSD 2.9.4 on a real host with a
real PIV certificate, using ``sssctl cert-eval-rule`` with positive and negative
controls. The regression these tests exist for was severe: the generated rule
used an infix ``" && "`` between components, which SSSD rejected outright
(``sss_certmap_add_rule failed ... [22][Invalid argument]``). The rule was
skipped, SSSD fell back to its default ``userCertificate;binary`` mapping, no
user was ever found, and smart card login silently fell through to the password.

Upstream's wording is the trap: ``sss-certmap(5)`` says only that pairs "can be
either joined with '&&' (and) or '||' (or)", which reads like an infix operator.
The SSSD design page disambiguates it -- rules "can be grouped together with a
prefixed && (and) or || (or) operator (&& is the default)" -- and every upstream
example simply concatenates the components.
"""

from __future__ import annotations

import pytest

from sssd_smartcard.certmap.compat import Version
from sssd_smartcard.certmap.mappings import build_rule
from sssd_smartcard.certmap.rules import MatchRule, MatchTerm, anchored
from sssd_smartcard.x509.recommend import build_profile, recommend

V = Version.parse("2.9.4")

#: The real rule from the lab host, in the form SSSD accepts.
REAL = (
    "KRB5:<ISSUER>^CN=Example Issuing CA,DC=ad,"
    "DC=example,DC=pl$<EKU>clientAuth,msScLogin"
    "<SAN:ntPrincipalName>.*@ad\\.example\\.pl$"
)


class TestRendering:
    def test_components_are_concatenated_with_no_operator(self):
        rule = MatchRule.all_of(
            MatchTerm("ISSUER", anchored("CN=CA,DC=x")),
            MatchTerm("EKU", "clientAuth"),
        )
        assert rule.render() == "KRB5:<ISSUER>^CN=CA,DC=x$<EKU>clientAuth"

    def test_no_infix_operator_is_ever_emitted(self):
        rule = MatchRule.all_of(
            MatchTerm("ISSUER", anchored("CN=CA")),
            MatchTerm("EKU", "clientAuth,msScLogin"),
            MatchTerm("SAN:ntPrincipalName", ".*@x\\.y$"),
        )
        rendered = rule.render()
        assert " && " not in rendered
        assert "&&" not in rendered
        assert " || " not in rendered

    def test_matches_upstreams_own_example_shape(self):
        """<ISSUER>...$<EKU>clientAuth<SAN:ntPrincipalName>*@AD.DOM"""
        rule = MatchRule.all_of(
            MatchTerm("ISSUER", "^CN=AD-CA,dc=ISSUER,DC=COM$"),
            MatchTerm("EKU", "clientAuth"),
            MatchTerm("SAN:ntPrincipalName", "*@AD.DOM"),
        )
        assert rule.render(include_prefix=False) == (
            "<ISSUER>^CN=AD-CA,dc=ISSUER,DC=COM$<EKU>clientAuth"
            "<SAN:ntPrincipalName>*@AD.DOM"
        )

    def test_alternative_groups_use_a_prefixed_or(self):
        rule = MatchRule(
            [
                [MatchTerm("SAN:ntPrincipalName", ".*")],
                [MatchTerm("SAN:rfc822Name", ".*")],
            ]
        )
        assert rule.render() == (
            "KRB5:<SAN:ntPrincipalName>.*||<SAN:rfc822Name>.*"
        )


class TestValidation:
    def test_an_infix_operator_is_reported(self):
        rule = MatchRule.parse(
            "KRB5:<ISSUER>^CN=CA$ && <EKU>clientAuth"
        )
        # Parsing normalises it, so build the broken form by hand.
        broken = MatchRule.all_of(
            MatchTerm("ISSUER", "^CN=CA$ && "), MatchTerm("EKU", "clientAuth")
        )
        problems = broken.validate()
        assert any("infix" in p for p in problems)
        assert rule.validate() == []

    def test_or_is_flagged_as_fragile(self):
        rule = MatchRule(
            [[MatchTerm("ISSUER", "^CN=A$")], [MatchTerm("SAN:rfc822Name", ".*")]]
        )
        assert rule.or_is_fragile
        assert any("'||'" in p for p in rule.validate())

    def test_eku_in_the_middle_is_not_flagged(self):
        """Measured as valid: the value terminates at the next '<'."""
        rule = MatchRule.all_of(
            MatchTerm("ISSUER", anchored("CN=CA")),
            MatchTerm("EKU", "clientAuth,msScLogin"),
            MatchTerm("SAN:ntPrincipalName", ".*@x\\.y$"),
        )
        assert rule.validate() == []

    def test_ku_in_the_middle_is_not_flagged(self):
        rule = MatchRule.all_of(
            MatchTerm("ISSUER", anchored("CN=CA")),
            MatchTerm("KU", "digitalSignature"),
            MatchTerm("SAN:ntPrincipalName", ".*"),
        )
        assert rule.validate() == []

    def test_a_plain_single_component_rule_is_clean(self):
        assert MatchRule.all_of(MatchTerm("EKU", "clientAuth")).validate() == []


class TestParsing:
    def test_the_real_rule_round_trips(self):
        parsed = MatchRule.parse(REAL)
        assert [t.keyword for t in parsed.terms] == [
            "ISSUER",
            "EKU",
            "SAN:ntPrincipalName",
        ]
        assert parsed.render() == REAL

    def test_values_terminate_at_the_next_component(self):
        parsed = MatchRule.parse(REAL)
        by_keyword = {t.keyword: t.value for t in parsed.terms}
        assert by_keyword["EKU"] == "clientAuth,msScLogin"
        assert by_keyword["ISSUER"].endswith("DC=pl$")
        assert by_keyword["SAN:ntPrincipalName"] == ".*@ad\\.example\\.pl$"

    def test_the_legacy_infix_form_is_read_and_normalised(self):
        """An existing broken config must be readable, then reported."""
        parsed = MatchRule.parse(
            "KRB5:<ISSUER>^CN=CA$ && <EKU>clientAuth && <SAN:ntPrincipalName>.*@x\\.y$"
        )
        assert [t.keyword for t in parsed.terms] == [
            "ISSUER",
            "EKU",
            "SAN:ntPrincipalName",
        ]
        assert parsed.terms[0].value == "^CN=CA$"
        assert parsed.terms[1].value == "clientAuth"
        assert "&&" not in parsed.render()

    def test_a_prefixed_or_starts_a_new_group(self):
        parsed = MatchRule.parse(
            "KRB5:<SAN:ntPrincipalName>.*||<SAN:rfc822Name>.*"
        )
        assert len(parsed.groups) == 2

    def test_a_rule_without_components_is_rejected(self):
        from sssd_smartcard.errors import RuleSyntaxError

        with pytest.raises(RuleSyntaxError):
            MatchRule.parse("KRB5:not-a-component")

    def test_keyword_case_is_normalised_on_parse(self):
        parsed = MatchRule.parse("krb5:<issuer>^CN=CA$<eku>clientAuth")
        assert [t.keyword for t in parsed.terms] == ["ISSUER", "EKU"]


class TestGeneratedRuleIsAccepted:
    """What the generator emits must be the form SSSD accepts."""

    def test_the_generated_rule_has_no_operator(self, piv_cert):
        rule = build_rule(build_profile(recommend(piv_cert, version=V)), version=V)
        rendered = rule.matchrule.render()
        assert "&&" not in rendered
        assert rendered.startswith("KRB5:<ISSUER>")
        assert "<EKU>clientAuth,msScLogin" in rendered
        assert "<SAN:ntPrincipalName>" in rendered

    def test_the_generated_rule_reports_no_problems(self, piv_cert):
        rule = build_rule(build_profile(recommend(piv_cert, version=V)), version=V)
        assert rule.matchrule.validate() == []
        assert not any("infix" in w for w in rule.warnings)

    def test_the_generated_rule_still_evaluates_locally(self, piv_cert):
        from sssd_smartcard.certmap.evaluator import evaluate_match, render_map

        rule = build_rule(build_profile(recommend(piv_cert, version=V)), version=V)
        assert evaluate_match(rule.matchrule, piv_cert).matched
        assert render_map(rule.maprule, piv_cert).complete

    def test_a_certificate_from_another_ca_is_still_rejected(self, piv_cert):
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        import conftest
        from sssd_smartcard.certmap.evaluator import evaluate_match

        rule = build_rule(build_profile(recommend(piv_cert, version=V)), version=V)
        original = conftest.ISSUER_DN_PARTS[:]
        try:
            conftest.ISSUER_DN_PARTS[:] = [
                x509.NameAttribute(NameOID.COMMON_NAME, "Rogue CA")
            ]
            rogue = conftest.build_cert()
        finally:
            conftest.ISSUER_DN_PARTS[:] = original
        assert not evaluate_match(rule.matchrule, rogue).matched


class TestSssctlOutputIsNotMisread:
    """A rejected rule must never be reported as a MATCH.

    The original parser tested for the substring "match", which appears inside
    the word "matching" in `Failed to add mapping and matching rules with error
    [22][Invalid argument].` -- so the tool confidently reported
    "MATCH, decided by sssctl" for a rule SSSD had refused to load.
    """

    def _run(self, monkeypatch, stdout: str, returncode: int = 0):
        from sssd_smartcard.certmap import evaluator
        from sssd_smartcard.util import CommandResult

        monkeypatch.setattr(
            evaluator,
            "run",
            lambda argv, **kw: CommandResult(list(argv), returncode, stdout, ""),
        )
        return evaluator.sssctl_eval_rule

    def test_invalid_argument_is_an_error_not_a_match(self, monkeypatch, piv_cert):
        fn = self._run(
            monkeypatch,
            "Failed to add mapping and matching rules with error "
            "[22][Invalid argument].\n",
        )
        result = fn(piv_cert, "KRB5:<EKU>clientAuth", "LDAP:(uid=x)")
        assert result.matched is None
        assert not result.available
        assert "rejected the rule" in result.error

    def test_a_nonzero_exit_is_an_error(self, monkeypatch, piv_cert):
        fn = self._run(monkeypatch, "Certificate matches rule.\n", returncode=1)
        result = fn(piv_cert, "KRB5:<EKU>clientAuth", "LDAP:(uid=x)")
        assert result.matched is None

    def test_a_real_match_is_still_recognised(self, monkeypatch, piv_cert):
        fn = self._run(
            monkeypatch,
            "Certificate matches rule.\nMapping filter:\n\n    (uid=testuser)\n",
        )
        result = fn(piv_cert, "KRB5:<EKU>clientAuth", "LDAP:(uid=x)")
        assert result.available and result.matched is True
        assert result.filter == "(uid=testuser)"

    def test_a_real_no_match_is_still_recognised(self, monkeypatch, piv_cert):
        fn = self._run(monkeypatch, "Certificate does not match rule.\n")
        result = fn(piv_cert, "KRB5:<EKU>clientAuth", "LDAP:(uid=x)")
        assert result.available and result.matched is False

    def test_empty_output_is_not_a_verdict(self, monkeypatch, piv_cert):
        fn = self._run(monkeypatch, "")
        result = fn(piv_cert, "KRB5:<EKU>clientAuth", "LDAP:(uid=x)")
        assert result.matched is None
        assert not result.available
