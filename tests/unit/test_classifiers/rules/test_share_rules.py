"""Tests for share enumeration rules — ensures ENDS_WITH rules with literal $
correctly match share names like C$, ADMIN$, IPC$, PRINT$, SCCMContentLib$."""

import pytest

from snaffler.classifiers.default_rules import get_share_rules
from snaffler.classifiers.rules import (
    ClassifierRule, EnumerationScope, MatchAction,
    MatchLocation, MatchListType, Triage,
)


@pytest.fixture(scope="module")
def share_rules():
    return get_share_rules()


def _find_rule(rules, name):
    for r in rules:
        if r.rule_name == name:
            return r
    raise ValueError(f"Rule {name!r} not found")


# ---------- DiscardNonFileShares ----------

class TestDiscardNonFileShares:
    def test_matches_ipc_dollar(self, share_rules):
        rule = _find_rule(share_rules, "DiscardNonFileShares")
        assert rule.matches("IPC$") is not None

    def test_matches_print_dollar(self, share_rules):
        rule = _find_rule(share_rules, "DiscardNonFileShares")
        assert rule.matches("PRINT$") is not None

    def test_case_insensitive(self, share_rules):
        rule = _find_rule(share_rules, "DiscardNonFileShares")
        assert rule.matches("ipc$") is not None
        assert rule.matches("print$") is not None

    def test_no_match_plain_ipc(self, share_rules):
        """'IPC' without $ should NOT match."""
        rule = _find_rule(share_rules, "DiscardNonFileShares")
        assert rule.matches("IPC") is None

    def test_no_match_data_share(self, share_rules):
        rule = _find_rule(share_rules, "DiscardNonFileShares")
        assert rule.matches("DATA") is None


# ---------- KeepDollarShares ----------

class TestKeepDollarShares:
    def test_matches_c_dollar(self, share_rules):
        rule = _find_rule(share_rules, "KeepDollarShares")
        assert rule.matches("C$") is not None

    def test_matches_admin_dollar(self, share_rules):
        rule = _find_rule(share_rules, "KeepDollarShares")
        assert rule.matches("ADMIN$") is not None

    def test_case_insensitive(self, share_rules):
        rule = _find_rule(share_rules, "KeepDollarShares")
        assert rule.matches("c$") is not None
        assert rule.matches("admin$") is not None

    def test_no_match_without_dollar(self, share_rules):
        """'C' or 'ADMIN' without $ should NOT match."""
        rule = _find_rule(share_rules, "KeepDollarShares")
        assert rule.matches("C") is None
        assert rule.matches("ADMIN") is None

    def test_no_match_data_share(self, share_rules):
        rule = _find_rule(share_rules, "KeepDollarShares")
        assert rule.matches("DATA") is None

    def test_triage_is_black(self, share_rules):
        rule = _find_rule(share_rules, "KeepDollarShares")
        assert rule.triage == Triage.BLACK


# ---------- KeepSCCMShares ----------

class TestKeepSCCMShares:
    def test_matches_sccm_dollar(self, share_rules):
        rule = _find_rule(share_rules, "KeepSCCMShares")
        assert rule.matches("SCCMContentLib$") is not None

    def test_case_insensitive(self, share_rules):
        rule = _find_rule(share_rules, "KeepSCCMShares")
        assert rule.matches("sccmcontentlib$") is not None

    def test_no_match_without_dollar(self, share_rules):
        rule = _find_rule(share_rules, "KeepSCCMShares")
        assert rule.matches("SCCMContentLib") is None


# ---------- ENDS_WITH regex escaping ----------

class TestEndsWithDollarEscaping:
    """Verify that ENDS_WITH with literal $ doesn't treat $ as regex anchor."""

    def test_ends_with_dollar_escaping(self):
        """The $ in the wordlist must be escaped so it matches literal $ in text."""
        rule = ClassifierRule(
            rule_name="TestEndsWith",
            enumeration_scope=EnumerationScope.SHARE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.SHARE_NAME,
            wordlist_type=MatchListType.ENDS_WITH,
            wordlist=["C$"],
            triage=Triage.BLACK,
        )
        # Must match "C$" (literal dollar at end)
        assert rule.matches("C$") is not None
        # Must NOT match "C" (no dollar sign)
        assert rule.matches("C") is None

    def test_ends_with_no_false_anchor(self):
        """Without proper escaping, 'C$' would compile to regex 'C$$'
        where the first $ is literal and the second is anchor — still works.
        But 'C' alone matching 'C$' (anchor treating $ as end-of-string) is the bug."""
        rule = ClassifierRule(
            rule_name="TestAnchor",
            enumeration_scope=EnumerationScope.SHARE_ENUMERATION,
            match_action=MatchAction.SNAFFLE,
            match_location=MatchLocation.SHARE_NAME,
            wordlist_type=MatchListType.ENDS_WITH,
            wordlist=["ADMIN$"],
            triage=Triage.BLACK,
        )
        # "ADMIN" without $ must NOT match
        assert rule.matches("ADMIN") is None
        # "ADMIN$" must match
        assert rule.matches("ADMIN$") is not None
