"""Tests for dynamic domain user content rules."""

import re

import pytest

from snaffler.classifiers.loader import build_domain_user_rule
from snaffler.classifiers.rules import (
    EnumerationScope, MatchAction, MatchListType, Triage,
)


class TestBuildDomainUserRule:
    """Unit tests for build_domain_user_rule()."""

    def test_basic_rule_properties(self):
        rule = build_domain_user_rule(["svc_sql", "admin_backup"])
        assert rule.rule_name == "DynamicDomainUsers"
        assert rule.enumeration_scope == EnumerationScope.CONTENTS_ENUMERATION
        assert rule.match_action == MatchAction.SNAFFLE
        assert rule.wordlist_type == MatchListType.REGEX
        assert rule.triage == Triage.RED

    def test_empty_list_raises(self):
        with pytest.raises(ValueError, match="empty"):
            build_domain_user_rule([])

    def test_single_user_matches_equals(self):
        rule = build_domain_user_rule(["svc_backup"])
        assert rule.matches("RunAs=svc_backup") is not None

    def test_single_user_matches_colon(self):
        rule = build_domain_user_rule(["svc_backup"])
        assert rule.matches("user: svc_backup") is not None

    def test_single_user_matches_quoted(self):
        rule = build_domain_user_rule(["svc_backup"])
        assert rule.matches('"svc_backup"') is not None

    def test_single_user_matches_backslash_domain(self):
        rule = build_domain_user_rule(["svc_backup"])
        assert rule.matches("DOMAIN\\svc_backup") is not None

    def test_single_user_matches_start_of_line(self):
        rule = build_domain_user_rule(["svc_backup"])
        assert rule.matches("svc_backup=secret") is not None

    def test_multiple_users_match_first(self):
        rule = build_domain_user_rule(["svc_sql", "admin_ops"])
        assert rule.matches("user=svc_sql") is not None

    def test_multiple_users_match_second(self):
        rule = build_domain_user_rule(["svc_sql", "admin_ops"])
        assert rule.matches("account: admin_ops") is not None

    def test_no_match_unrelated(self):
        rule = build_domain_user_rule(["svc_sql"])
        assert rule.matches("hostname=server01") is None

    def test_username_with_special_chars_escaped(self):
        """Usernames with regex metacharacters are escaped safely."""
        rule = build_domain_user_rule(["svc.backup+test"])
        assert rule.matches("user=svc.backup+test") is not None
        # Literal dot should not match arbitrary char
        assert rule.matches("user=svcXbackup+test") is None

    def test_case_insensitive(self):
        rule = build_domain_user_rule(["SVC_SQL"])
        assert rule.matches("user=svc_sql") is not None
        assert rule.matches("USER=SVC_SQL") is not None

    def test_large_user_list_compiles(self):
        """Verify regex compiles and works with 1500 users."""
        users = [f"svc_user_{i:04d}" for i in range(1500)]
        rule = build_domain_user_rule(users)
        assert rule.matches("account=svc_user_0000") is not None
        assert rule.matches("account=svc_user_1499") is not None
        assert rule.matches("account=nonexistent_user") is None

    def test_regex_compiles_to_pattern(self):
        """Rule's __post_init__ compiles the regex."""
        rule = build_domain_user_rule(["svc_test"])
        assert len(rule.regexes) == 1
        assert isinstance(rule.regexes[0], re.Pattern)

    def test_comma_delimiter(self):
        rule = build_domain_user_rule(["svc_sql"])
        assert rule.matches("users=admin,svc_sql,guest") is not None

    def test_whitespace_delimiter(self):
        rule = build_domain_user_rule(["svc_sql"])
        assert rule.matches("run as svc_sql please") is not None

    def test_single_quote_delimiter(self):
        rule = build_domain_user_rule(["svc_sql"])
        assert rule.matches("user='svc_sql'") is not None
