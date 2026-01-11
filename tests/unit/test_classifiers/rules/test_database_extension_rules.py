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

DATA_ROOT = Path(__file__).parents[3] / "data" / "database"

EXTENSIONS = [
    ".mdf",
    ".sdf",
    ".sqldump",
    ".bak",
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


@pytest.mark.parametrize("ext", EXTENSIONS)
def test_database_extensions_trigger_keep_database_rule(ext, evaluator):
    """
    Database files by extension MUST trigger KeepDatabaseByExtension
    and result in SNAFFLE.
    """
    path = DATA_ROOT / f"test{ext}"
    assert path.exists(), f"Missing test file: {path}"

    ctx = make_ctx(path)

    hits = []

    for rule in evaluator.file_rules:
        if rule.enumeration_scope != EnumerationScope.FILE_ENUMERATION:
            continue

        decision = evaluator.evaluate_file_rule(rule, ctx)
        if decision:
            hits.append((rule.rule_name, decision.action))

    assert hits, f"No rules matched {path.name}"

    assert (
               "KeepDatabaseByExtension",
               MatchAction.SNAFFLE,
           ) in hits, f"KeepDatabaseByExtension not triggered. Got: {hits}"
