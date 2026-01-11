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
IMAGE_PATH = DATA_ROOT / "images" / "logo.png"


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


def test_png_is_discarded(evaluator):
    """
    PNG images must be discarded and never snaffled or relayed.
    """
    assert IMAGE_PATH.exists(), "Test image file is missing"

    ctx = make_ctx(IMAGE_PATH)

    decisions = []

    for rule in evaluator.file_rules:
        if rule.enumeration_scope != EnumerationScope.FILE_ENUMERATION:
            continue

        decision = evaluator.evaluate_file_rule(rule, ctx)
        if decision:
            decisions.append((rule.rule_name, decision.action))

    # Must discard
    assert any(
        action == MatchAction.DISCARD for _, action in decisions
    ), f"Expected DISCARD for PNG. Got: {decisions}"

    # Must NOT snaffle or relay
    assert not any(
        action in (MatchAction.SNAFFLE, MatchAction.RELAY)
        for _, action in decisions
    ), f"PNG should not be snaffled or relayed. Got: {decisions}"
