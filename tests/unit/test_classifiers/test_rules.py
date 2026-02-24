import textwrap
import pytest

from snaffler.classifiers.rules import (
    EnumerationScope,
    MatchLocation,
    MatchListType,
    MatchAction,
    Triage,
    ClassifierRule,
    load_rules_from_toml,
    load_rules_from_directory,
)

# ---------------------------------------------------------------------------
# ENUMS + TRIAGE
# ---------------------------------------------------------------------------

def test_enums_basic():
    assert EnumerationScope.FILE_ENUMERATION.value == "FileEnumeration"
    assert MatchAction.DISCARD.value == "Discard"


def test_triage_logic():
    assert Triage.GREEN.below(1)
    assert not Triage.RED.below(1)
    assert Triage.BLACK.more_severe_than(Triage.YELLOW)


# ---------------------------------------------------------------------------
# MATCHING
# ---------------------------------------------------------------------------

def test_rule_exact_match():
    rule = ClassifierRule(
        rule_name="exact",
        enumeration_scope=EnumerationScope.FILE_ENUMERATION,
        match_action=MatchAction.SNAFFLE,
        match_location=MatchLocation.FILE_NAME,
        wordlist_type=MatchListType.EXACT,
        wordlist=["secret.txt"],
    )

    assert rule.matches("secret.txt")
    assert rule.matches("SECRET.TXT")
    assert rule.matches("other.txt") is None


def test_exact_returns_matched_text():
    """EXACT matches return the input text as a string, not re.Match."""
    rule = ClassifierRule(
        rule_name="exact",
        enumeration_scope=EnumerationScope.FILE_ENUMERATION,
        match_action=MatchAction.SNAFFLE,
        match_location=MatchLocation.FILE_NAME,
        wordlist_type=MatchListType.EXACT,
        wordlist=["secret.txt"],
    )
    result = rule.matches("Secret.TXT")
    assert result == "Secret.TXT"
    assert isinstance(result, str)


def test_exact_no_substring_match():
    """EXACT must not match substrings — only full value."""
    rule = ClassifierRule(
        rule_name="exact",
        enumeration_scope=EnumerationScope.FILE_ENUMERATION,
        match_action=MatchAction.SNAFFLE,
        match_location=MatchLocation.FILE_NAME,
        wordlist_type=MatchListType.EXACT,
        wordlist=["web.config"],
    )
    assert rule.matches("web.config") is not None
    assert rule.matches("old_web.config") is None
    assert rule.matches("web.config.bak") is None


def test_exact_multiple_wordlist():
    """EXACT with multiple words matches any of them."""
    rule = ClassifierRule(
        rule_name="exact_multi",
        enumeration_scope=EnumerationScope.FILE_ENUMERATION,
        match_action=MatchAction.SNAFFLE,
        match_location=MatchLocation.FILE_NAME,
        wordlist_type=MatchListType.EXACT,
        wordlist=["id_rsa", "id_dsa"],
    )
    assert rule.matches("id_rsa") is not None
    assert rule.matches("ID_RSA") is not None
    assert rule.matches("id_dsa") is not None
    assert rule.matches("id_ecdsa") is None


def test_rule_contains_match():
    rule = ClassifierRule(
        rule_name="contains",
        enumeration_scope=EnumerationScope.FILE_ENUMERATION,
        match_action=MatchAction.SNAFFLE,
        match_location=MatchLocation.FILE_NAME,
        wordlist_type=MatchListType.CONTAINS,
        wordlist=["secret"],
    )

    assert rule.matches("my_secret_file.txt")
    assert rule.matches("nosecret")  # ← contains is substring


def test_rule_regex():
    rule = ClassifierRule(
        rule_name="regex",
        enumeration_scope=EnumerationScope.FILE_ENUMERATION,
        match_action=MatchAction.SNAFFLE,
        match_location=MatchLocation.FILE_NAME,
        wordlist_type=MatchListType.REGEX,
        wordlist=[r"pass(word)?"],
    )

    assert rule.matches("passwords.txt")
    assert rule.matches("pass.txt")
    assert rule.matches("secret.txt") is None


def test_matches_empty():
    rule = ClassifierRule(
        rule_name="empty",
        enumeration_scope=EnumerationScope.FILE_ENUMERATION,
        match_action=MatchAction.SNAFFLE,
        match_location=MatchLocation.FILE_NAME,
        wordlist_type=MatchListType.CONTAINS,
        wordlist=["x"],
    )

    assert rule.matches("") is None
    assert rule.matches(None) is None


# ---------------------------------------------------------------------------
# TOML LOADING (EXPECTED FAILURES)
# ---------------------------------------------------------------------------

def test_rule_from_toml_valid_triage():
    for label in ("Green", "Yellow", "Red", "Black"):
        data = {
            "RuleName": "GoodRule",
            "EnumerationScope": "FileEnumeration",
            "MatchAction": "Snaffle",
            "MatchLocation": "FileName",
            "WordListType": "Contains",
            "WordList": ["secret"],
            "Triage": label,
        }
        rule = ClassifierRule.from_toml(data)
        assert rule.triage.label == label


def test_rule_from_toml_invalid_triage():
    data = {
        "RuleName": "BadRule",
        "EnumerationScope": "FileEnumeration",
        "MatchAction": "Snaffle",
        "MatchLocation": "FileName",
        "WordListType": "Contains",
        "WordList": ["secret"],
        "Triage": "InvalidSeverity",
    }

    with pytest.raises(ValueError):
        ClassifierRule.from_toml(data)


def test_load_rules_from_toml_invalid_rules_are_skipped(tmp_path):
    toml_file = tmp_path / "rules.toml"
    toml_file.write_text("""
        [[ClassifierRules]]
        RuleName = "Broken"
        EnumerationScope = "FileEnumeration"
        MatchAction = "Snaffle"
        MatchLocation = "FileName"
        WordListType = "Contains"
        WordList = ["secret"]
        Triage = "InvalidSeverity"
    """)

    rules = load_rules_from_toml(str(toml_file))
    assert rules == []


def test_load_rules_from_toml_valid_rules_are_loaded(tmp_path):
    toml_file = tmp_path / "rules.toml"
    toml_file.write_text("""
        [[ClassifierRules]]
        RuleName = "GoodRule"
        EnumerationScope = "FileEnumeration"
        MatchAction = "Snaffle"
        MatchLocation = "FileName"
        WordListType = "Contains"
        WordList = ["secret"]
        Triage = "Red"
    """)

    rules = load_rules_from_toml(str(toml_file))
    assert len(rules) == 1
    assert rules[0].rule_name == "GoodRule"
    assert rules[0].triage == Triage.RED


def test_load_rules_from_directory_all_invalid(tmp_path):
    f = tmp_path / "a.toml"
    f.write_text("""
        [[ClassifierRules]]
        RuleName = "Broken"
        EnumerationScope = "FileEnumeration"
        MatchAction = "Snaffle"
        MatchLocation = "FileName"
        WordListType = "Contains"
        WordList = ["x"]
        Triage = "InvalidSeverity"
    """)

    rules = load_rules_from_directory(str(tmp_path))
    assert rules == []

