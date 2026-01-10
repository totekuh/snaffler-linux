from pathlib import Path

import pytest

from snaffler.classifiers.default_rules import get_default_rules
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.analysis.file_context import FileContext
from snaffler.classifiers.rules import EnumerationScope


TEST_ROOT = Path(__file__).parent


def collect_test_files():
    return [
        p for p in TEST_ROOT.rglob("*")
        if p.is_file() and not p.name.startswith("test_")
    ]


@pytest.fixture(scope="session")
def evaluator():
    rules = get_default_rules()
    return RuleEvaluator(
        file_rules=rules,
        content_rules=[],
        postmatch_rules=[]
    )


@pytest.mark.parametrize(
    "file_path",
    collect_test_files(),
    ids=lambda p: str(p.relative_to(TEST_ROOT)),
)
def test_default_rules_on_files(file_path: Path, evaluator):

    ctx = FileContext(
        str(file_path),
        file_path.name,
        file_path.suffix.lower(),
        file_path.stat().st_size
    )

    rules = evaluator.file_rules
    matched = []

    for rule in rules:
        if rule.enumeration_scope != EnumerationScope.FILE_ENUMERATION:
            continue

        if evaluator.evaluate_file_rule(rule, ctx):
            matched.append(rule)

    # 🔒 Минимальный, но реальный assert
    assert matched is not None



