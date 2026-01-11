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

DATA_ROOT = Path(__file__).parents[3] / "data"
SSH_PATH_FILE = DATA_ROOT / "home" / "user" / ".ssh" / "custom_key"


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


def test_ssh_path_triggers_snaffle(evaluator):
    """
    Any file under /.ssh/ MUST be snaffled via KeepSSHFilesByPath
    regardless of filename.
    """
    assert SSH_PATH_FILE.exists(), "SSH test file missing"

    ctx = make_ctx(SSH_PATH_FILE)

    decisions = []

    for rule in evaluator.file_rules:
        if rule.enumeration_scope != EnumerationScope.FILE_ENUMERATION:
            continue

        decision = evaluator.evaluate_file_rule(rule, ctx)
        if decision:
            decisions.append((rule.rule_name, decision.action))

    # ---- assertions ----

    # Path-based SSH rule MUST fire
    assert (
               "KeepSSHFilesByPath",
               MatchAction.SNAFFLE,
           ) in decisions, f"SSH path rule did not fire. Got: {decisions}"

    # Filename-based SSH rule MUST NOT fire
    assert not any(
        rule == "KeepSSHKeysByFileName"
        for rule, _ in decisions
    ), f"Filename-based SSH rule should not fire. Got: {decisions}"
