from pathlib import Path
from datetime import datetime

import pytest

from snaffler.classifiers.default_rules import get_default_rules, get_postmatch_rules
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.analysis.model.file_context import FileContext
from snaffler.classifiers.rules import (
    EnumerationScope,
    MatchAction,
)

# ----------------------------------------------------------------------
# test data
# ----------------------------------------------------------------------

DATA_ROOT = Path(__file__).parents[3] / "data" / "postmatch_name"

FILENAMES = [
    "credentialprovider.idl",
    "pspasswd64.exe",
    "psexec.exe",
]


@pytest.fixture(scope="session")
def evaluator():
    return RuleEvaluator(
        file_rules=[],
        content_rules=[],
        postmatch_rules=get_postmatch_rules(),
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


@pytest.mark.parametrize("filename", FILENAMES)
def test_postmatch_discard_by_name_filters_false_positives(filename, evaluator):
    """
    Post-match discard rules MUST filter out false positive files by exact name
    and result in DISCARD action to prevent them from being flagged.
    """
    path = DATA_ROOT / filename
    assert path.exists(), f"Missing test file: {path}"

    ctx = make_ctx(path)

    hits = []

    for rule in evaluator.postmatch_rules:
        if rule.enumeration_scope != EnumerationScope.POST_MATCH:
            continue

        decision = evaluator.evaluate_file_rule(rule, ctx)
        if decision:
            hits.append((rule.rule_name, decision.action))

    # something matched
    assert hits, f"No postmatch rules matched {filename}"

    # correct discard rule fired
    assert (
        "DiscardPostMatchByName",
        MatchAction.DISCARD,
    ) in hits, f"DiscardPostMatchByName not triggered. Got: {hits}"
