from pathlib import Path
from datetime import datetime

import pytest

from snaffler.classifiers.default_rules import get_default_rules
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.analysis.model.file_context import FileContext
from snaffler.classifiers.rules import (
    EnumerationScope,
    MatchAction,
    Triage,
)

# ----------------------------------------------------------------------
# test data
# ----------------------------------------------------------------------

DATA_ROOT = Path(__file__).parents[3] / "data" / "sccm_path"

PATHS = [
    "control/customsettings.ini",
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


@pytest.mark.parametrize("rel_path", PATHS)
def test_sccm_domain_join_files_by_path_trigger_keep_rule(rel_path, evaluator):
    """
    SCCM/Domain Join config files matched by path pattern (control/customsettings.ini)
    MUST trigger KeepDomainJoinCredsByPath and result in SNAFFLE with RED triage.
    """
    path = DATA_ROOT / rel_path
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
    assert hits, f"No rules matched {rel_path}"

    # correct rule fired
    assert (
        "KeepDomainJoinCredsByPath",
        MatchAction.SNAFFLE,
    ) in hits, f"KeepDomainJoinCredsByPath not triggered. Got: {hits}"
