from pathlib import Path
from datetime import datetime

import pytest

from snaffler.classifiers.default_rules import get_default_rules
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.analysis.model.file_context import FileContext
from snaffler.classifiers.rules import (
    EnumerationScope,
    MatchAction,
)

# ----------------------------------------------------------------------
# test data
# ----------------------------------------------------------------------

DATA_ROOT = Path(__file__).parents[3] / "data" / "relay_rules"

# Mapping of test files to expected relay rules
RELAY_TEST_CASES = [
    ("webapp.cs", "RelayCSharpByExtension"),
    ("deploy.ps1", "RelayPsByExtension"),
    ("app.py", "RelayPythonByExtension"),
    ("config.php", "RelayPhpByExtension"),
    ("connection.rdp", "RelayRdpByExtension"),
]


@pytest.fixture(scope="session")
def evaluator():
    return RuleEvaluator(
        file_rules=get_default_rules(),
        content_rules=[],
        postmatch_rules=[],
    )


def make_ctx(path: Path) -> FileContext:
    return FileContext(
        unc_path=str(path),
        smb_path=str(path),
        name=path.name,
        ext=path.suffix.lower(),
        size=path.stat().st_size,
        modified=datetime.fromtimestamp(0),
    )


@pytest.mark.parametrize("filename,expected_relay_rule", RELAY_TEST_CASES)
def test_relay_rules_trigger_for_file_types(filename, expected_relay_rule, evaluator):
    """
    Relay rules MUST trigger based on file extension and result in RELAY action
    which would then trigger content scanning with specific content rules.
    """
    path = DATA_ROOT / filename
    assert path.exists(), f"Missing test file: {path}"

    ctx = make_ctx(path)

    hits = []

    for rule in evaluator.file_rules:
        if rule.enumeration_scope != EnumerationScope.FILE_ENUMERATION:
            continue

        decision = evaluator.evaluate_file_rule(rule, ctx)
        if decision:
            hits.append((rule.rule_name, decision.action))

    # something matched
    assert hits, f"No rules matched {filename}"

    # correct relay rule fired
    assert any(
        h[0] == expected_relay_rule and
        h[1] == MatchAction.RELAY
        for h in hits
    ), f"{expected_relay_rule} with RELAY action not triggered. Got: {hits}"

    # verify that the relay rule has content_rule_names configured
    matching_rules = [r for r in evaluator.file_rules if r.rule_name == expected_relay_rule]
    assert len(matching_rules) > 0, f"Relay rule {expected_relay_rule} not found"
    relay_rule = matching_rules[0]
    assert relay_rule.content_rule_names, f"Relay rule {expected_relay_rule} has no content_rule_names configured"
    assert len(relay_rule.content_rule_names) > 0, f"Relay rule {expected_relay_rule} has empty content_rule_names"
