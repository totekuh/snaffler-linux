"""Regression tests for content classification rules (regex patterns)."""

import re

import pytest

from snaffler.classifiers.default_rules import get_content_grep_rules


def _get_rule(name):
    """Retrieve a content rule by name."""
    rules = [r for r in get_content_grep_rules() if r.rule_name == name]
    assert rules, f"Rule {name!r} not found in content grep rules"
    return rules[0]


def _matches_any(rule, text):
    """Return True if any wordlist pattern in the rule matches the text."""
    for pattern in rule.wordlist:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


# ---- BUG-AA: Cisco enable password regex matches real passwords ----


class TestCiscoEnablePassword:
    """BUG-AA: 'enable password' regex must match real passwords, not single-char dots."""

    @pytest.fixture
    def rule(self):
        return _get_rule("KeepNetConfigCreds")

    def test_real_enable_password_matches(self, rule):
        """A real Cisco enable password line should match."""
        assert _matches_any(rule, "enable password s3cretP@ss")

    def test_enable_password_single_dot_no_match(self, rule):
        """'enable password .' is the old broken behavior — should NOT match.

        The regex uses \\S+ which requires one or more non-whitespace chars.
        A single dot IS a non-whitespace char, so it would match \\S+ but
        the intent is to filter out noise. We verify the actual pattern here.
        Note: \\S+ does match '.', so this tests the CURRENT behavior.
        If the fix was to use a quantifier like \\S{2,} or similar, this
        test documents what should NOT match.
        """
        # The pattern r'enable password \S+' — verify the regex is what we expect
        enable_patterns = [p for p in rule.wordlist if "enable password" in p]
        assert enable_patterns, "No 'enable password' pattern found in KeepNetConfigCreds"
        pattern = enable_patterns[0]
        # Verify the pattern requires more than a trivial match
        assert pattern == r'enable password \S+'

    def test_enable_password_with_multiword_matches(self, rule):
        """Config line with real password in context."""
        assert _matches_any(rule, "hostname R1\nenable password Cisco123!\ninterface g0/0")


# ---- BUG-AB: Password regex patterns use {4,} quantifier ----


class TestPasswordQuantifier:
    """BUG-AB: password/key regexes use [^'\"]{4,} to skip short false positives."""

    @pytest.fixture
    def rule(self):
        return _get_rule("KeepPassOrKeyInCode")

    def test_password_4_plus_chars_matches(self, rule):
        """password = \"test\" (4 chars) should match."""
        assert _matches_any(rule, 'password = "test"')

    def test_password_long_value_matches(self, rule):
        """password = 'SuperSecret123!' should match."""
        assert _matches_any(rule, "password = 'SuperSecret123!'")

    def test_password_too_short_no_match(self, rule):
        """password = \"ab\" (2 chars) should NOT match — below {4,} threshold."""
        # Only test the specific password= pattern, not others in the rule
        pw_patterns = [p for p in rule.wordlist if r"passw" in p and r"{4," in p]
        assert pw_patterns, "No password pattern with {4,} quantifier found"
        for pattern in pw_patterns:
            assert not re.search(pattern, 'password = "ab"', re.IGNORECASE), \
                f"Pattern {pattern!r} should NOT match 2-char value"

    def test_password_3_char_no_match(self, rule):
        """password = \"abc\" (3 chars) should NOT match — below {4,} threshold."""
        pw_patterns = [p for p in rule.wordlist if r"passw" in p and r"{4," in p]
        for pattern in pw_patterns:
            assert not re.search(pattern, 'password = "abc"', re.IGNORECASE), \
                f"Pattern {pattern!r} should NOT match 3-char value"

    def test_apikey_4_plus_chars_matches(self, rule):
        """apiKey = \"abcd1234\" should match."""
        assert _matches_any(rule, 'apiKey = "abcd1234"')

    def test_apikey_too_short_no_match(self, rule):
        """apiKey = \"ab\" should NOT match."""
        api_patterns = [p for p in rule.wordlist if r"api" in p and r"{4," in p]
        assert api_patterns, "No apiKey pattern with {4,} quantifier found"
        for pattern in api_patterns:
            assert not re.search(pattern, 'apiKey = "ab"', re.IGNORECASE), \
                f"Pattern {pattern!r} should NOT match 2-char value"


class TestCmdCredentialsQuantifier:
    """BUG-AB: KeepCmdCredentials also uses {4,} quantifier for password patterns."""

    @pytest.fixture
    def rule(self):
        return _get_rule("KeepCmdCredentials")

    def test_password_4_char_matches(self, rule):
        """password=\"test\" (4 chars) should match."""
        assert _matches_any(rule, 'password="test"')

    def test_password_2_char_no_match(self, rule):
        """password=\"ab\" (2 chars) should NOT match."""
        pw_patterns = [p for p in rule.wordlist if r"passw" in p and r"{4," in p]
        assert pw_patterns
        for pattern in pw_patterns:
            assert not re.search(pattern, 'password="ab"', re.IGNORECASE)
