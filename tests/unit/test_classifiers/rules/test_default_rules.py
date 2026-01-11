from pathlib import Path
from datetime import datetime

import pytest

from snaffler.classifiers.default_rules import get_default_rules
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.analysis.model.file_context import FileContext
from snaffler.classifiers.rules import EnumerationScope, MatchAction

DATA_ROOT = Path(__file__).parents[3] / "data"
PPK_PATH = DATA_ROOT / "relay_ssh_key" / "test_key.ppk"


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


def test_ppk_triggers_ssh_extension_rule(evaluator):
    """
    .ppk files MUST be detected as SSH keys via KeepSSHKeysByFileExtension
    and result in SNAFFLE.
    """
    assert PPK_PATH.exists(), "Test .ppk file is missing"

    ctx = make_ctx(PPK_PATH)

    decisions = []

    for rule in evaluator.file_rules:
        if rule.enumeration_scope != EnumerationScope.FILE_ENUMERATION:
            continue

        decision = evaluator.evaluate_file_rule(rule, ctx)
        if decision:
            decisions.append((rule.rule_name, decision.action))

    # sanity
    assert decisions, "No rules matched .ppk file — SSH extension detection is broken"

    # exact rule check
    assert (
               "KeepSSHKeysByFileExtension",
               MatchAction.SNAFFLE,
           ) in decisions, f"Expected SSH .ppk rule not triggered. Got: {decisions}"
