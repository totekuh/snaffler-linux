from pathlib import Path
from datetime import datetime, timezone

import pytest

from snaffler.classifiers.default_rules import get_default_rules
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.analysis.model.file_context import FileContext
from snaffler.classifiers.rules import (
    EnumerationScope,
    MatchAction,
)

# test data root
DATA_ROOT = Path(__file__).parents[3] / "data"

SSH_KEY_PATH = DATA_ROOT / "relay_ssh_key" / "id_rsa"


@pytest.fixture(scope="session")
def evaluator():
    rules = get_default_rules()
    return RuleEvaluator(
        file_rules=rules,
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
        modified=datetime.fromtimestamp(0, timezone.utc),
    )


def test_id_rsa_triggers_ssh_key_rule(evaluator):
    """
    relay_ssh_key/id_rsa MUST be detected as an SSH private key
    via KeepSSHKeysByFileName and result in SNAFFLE.
    """
    assert SSH_KEY_PATH.exists(), "Test SSH key file is missing"

    ctx = make_ctx(SSH_KEY_PATH)

    decisions = []

    for rule in evaluator.file_rules:
        if rule.enumeration_scope != EnumerationScope.FILE_ENUMERATION:
            continue

        decision = evaluator.evaluate_file_rule(rule, ctx)
        if decision:
            decisions.append((rule.rule_name, decision.action))

    # ---- assertions ----

    # 1. Something matched
    assert decisions, "No rules matched id_rsa - SSH detection is broken"

    # 2. Correct rule fired
    assert (
               "KeepSSHKeysByFileName",
               MatchAction.SNAFFLE,
           ) in decisions, f"Expected SSH key rule not triggered. Got: {decisions}"
