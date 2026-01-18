from pathlib import Path
from datetime import datetime

import pytest

from snaffler.classifiers.default_rules import get_content_grep_rules
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.analysis.model.file_context import FileContext
from snaffler.classifiers.rules import (
    EnumerationScope,
    MatchAction,
)

# ----------------------------------------------------------------------
# test data
# ----------------------------------------------------------------------

DATA_ROOT = Path(__file__).parents[3] / "data" / "content_grep"

# Mapping of test files to expected matching rules
TEST_CASES = [
    ("db_connection.cs", "KeepCSharpDbConnStringsRed"),
    ("aws_keys.py", "KeepAwsKeysInCode"),
    ("private_key.pem", "KeepInlinePrivateKey"),
    ("slack_webhook.js", "KeepSlackTokensInCode"),
    ("powershell_creds.ps1", "KeepPsCredentials"),
]


@pytest.fixture(scope="session")
def content_rules():
    return get_content_grep_rules()


def make_ctx(path: Path) -> FileContext:
    return FileContext(
        unc_path=str(path),
        smb_path=str(path),
        name=path.name,
        ext=path.suffix.lower(),
        size=path.stat().st_size,
        modified=datetime.fromtimestamp(0),
    )


@pytest.mark.parametrize("filename,expected_rule", TEST_CASES)
def test_content_grep_rules_match_file_contents(filename, expected_rule, content_rules):
    """
    Content grep rules MUST match patterns in file contents
    and result in SNAFFLE with appropriate triage level.
    """
    path = DATA_ROOT / filename
    assert path.exists(), f"Missing test file: {path}"

    # Read file content
    content = path.read_text()

    # Find the expected rule
    matching_rules = [r for r in content_rules if r.rule_name == expected_rule]
    assert len(matching_rules) > 0, f"Rule {expected_rule} not found in content rules"

    rule = matching_rules[0]

    # Test that the rule matches the content
    assert rule.enumeration_scope == EnumerationScope.CONTENTS_ENUMERATION
    assert rule.match_action == MatchAction.SNAFFLE

    # Test the rule's matches method
    match = rule.matches(content)
    assert match is not None, f"Rule {expected_rule} did not match content in {filename}"
