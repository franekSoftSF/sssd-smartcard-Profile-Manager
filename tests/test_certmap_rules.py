"""Matching and mapping rule syntax."""

from __future__ import annotations

import pytest

from sssd_smartcard.certmap.rules import (
    MapRule,
    MatchRule,
    MatchTerm,
    anchored,
    escape_regex,
    ldap_filter_escape,
)
from sssd_smartcard.errors import RuleSyntaxError


class TestEscaping:
    def test_escapes_every_documented_special_character(self):
        # sss-certmap(5) lists ^ . [ $ ( ) | * + ? { \
        assert escape_regex("a.b") == r"a\.b"
        assert escape_regex("a|b") == r"a\|b"
        assert escape_regex("a+b*c?") == r"a\+b\*c\?"
        assert escape_regex("{x}") == r"\{x}"
        assert escape_regex("a\\b") == "a\\\\b"

    def test_leaves_ordinary_dn_characters_alone(self):
        assert escape_regex("CN=Enterprise CA,DC=example") == "CN=Enterprise CA,DC=example"

    def test_anchored_pins_both_ends(self):
        assert anchored("CN=CA,DC=x") == "^CN=CA,DC=x$"

    def test_anchoring_prevents_a_prefix_match(self):
        # Without anchors, <ISSUER>CN=CA would also match CN=CA-Evil.
        rule = MatchRule.all_of(MatchTerm("ISSUER", anchored("CN=CA")))
        assert rule.render() == "KRB5:<ISSUER>^CN=CA$"

    def test_ldap_filter_escape(self):
        assert ldap_filter_escape("a*b") == r"a\2ab"
        assert ldap_filter_escape("(x)") == r"\28x\29"


class TestMatchRule:
    def test_renders_conjunction_by_concatenation(self):
        """AND is plain concatenation -- no operator. See test_matchrule_syntax.

        These two assertions originally expected an infix " && ", which SSSD
        rejects outright; the tests were encoding the bug.
        """
        rule = MatchRule.all_of(
            MatchTerm("ISSUER", "^CN=CA$"),
            MatchTerm("EKU", "clientAuth,msScLogin"),
        )
        assert rule.render() == "KRB5:<ISSUER>^CN=CA$<EKU>clientAuth,msScLogin"

    def test_renders_alternatives_with_a_prefixed_or(self):
        rule = MatchRule(
            [
                [MatchTerm("SAN:ntPrincipalName", ".*")],
                [MatchTerm("SAN:rfc822Name", ".*")],
            ]
        )
        assert rule.render() == "KRB5:<SAN:ntPrincipalName>.*||<SAN:rfc822Name>.*"

    def test_round_trips_through_parse(self):
        text = (
            "KRB5:<ISSUER>^CN=CA,DC=x$ && <EKU>clientAuth "
            "|| <SAN:rfc822Name>.*@example\\.com"
        )
        parsed = MatchRule.parse(text)
        assert len(parsed.groups) == 2
        assert parsed.groups[0][0].keyword == "ISSUER"
        assert parsed.groups[1][0].keyword == "SAN:rfc822Name"
        assert MatchRule.parse(parsed.render()).render() == parsed.render()

    def test_parse_without_prefix_defaults_to_krb5(self):
        parsed = MatchRule.parse("<EKU>clientAuth")
        assert parsed.prefix == "KRB5"
        assert parsed.render() == "KRB5:<EKU>clientAuth"

    def test_escaped_pipe_is_not_an_operator(self):
        parsed = MatchRule.parse(r"KRB5:<SUBJECT>a\|b")
        assert len(parsed.groups) == 1
        assert parsed.groups[0][0].value == r"a\|b"

    def test_keyword_case_is_normalised(self):
        assert MatchTerm("san:ntprincipalname", ".*").keyword == "SAN:ntPrincipalName"

    def test_san_with_oid_is_accepted(self):
        assert MatchTerm("SAN:1.2.3.4", "x").render() == "<SAN:1.2.3.4>x"

    def test_unknown_keyword_is_rejected_with_the_valid_list(self):
        with pytest.raises(RuleSyntaxError) as excinfo:
            MatchTerm("SAN:nonsense", "x")
        assert "SAN:ntPrincipalName" in str(excinfo.value)

    def test_empty_rule_renders_to_nothing(self):
        assert MatchRule([]).render() == ""


class TestMapRule:
    def test_default_prefix_is_ldap(self):
        assert MapRule("(uid={subject_dn})").render() == "LDAP:(uid={subject_dn})"

    def test_parse_recognises_ldapu1(self):
        parsed = MapRule.parse("LDAPU1:(objectSid={sid})")
        assert parsed.prefix == "LDAPU1"
        assert parsed.template == "(objectSid={sid})"

    def test_extended_templates_are_detected(self):
        assert MapRule("(a={sid})").requires_ldapu1
        assert MapRule("(a={serial_number!hex_ur})").requires_ldapu1
        assert not MapRule("(a={subject_nt_principal})").requires_ldapu1

    def test_validate_flags_a_missing_ldapu1_prefix(self):
        problems = MapRule("(objectSid={sid})").validate()
        assert any("LDAPU1" in p for p in problems)

    def test_validate_flags_an_unknown_template(self):
        problems = MapRule("(uid={not_a_template})").validate()
        assert any("not_a_template" in p for p in problems)

    def test_validate_flags_an_incomplete_filter(self):
        problems = MapRule("uid={subject_dn}").validate()
        assert any("complete LDAP filter" in p for p in problems)

    def test_a_correct_ldapu1_rule_has_no_problems(self):
        assert MapRule("(objectSid={sid})", prefix="LDAPU1").validate() == []

    def test_template_names_include_selectors_and_conversions(self):
        rule = MapRule("(|(a={subject_nt_principal.short_name})(b={issuer_dn!ad_x500}))")
        assert rule.template_names == ["subject_nt_principal", "issuer_dn"]
