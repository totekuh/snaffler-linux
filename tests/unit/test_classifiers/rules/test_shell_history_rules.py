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

DATA_ROOT = Path(__file__).parents[3] / "data" / "shell_history"

FILENAMES = [
    ".bash_history",
    ".zsh_history",
    ".sh_history",
    "zhistory",
    ".irb_history",
    "ConsoleHost_History.txt",
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


@pytest.mark.parametrize("filename", FILENAMES)
def test_shell_history_files_by_name_trigger_keep_shell_history_rule(filename, evaluator):
    """
    Shell history files matched by name MUST trigger KeepShellHistoryByName
    and result in SNAFFLE.
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

    # correct rule fired
    assert (
               "KeepShellHistoryByName",
               MatchAction.SNAFFLE,
           ) in hits, f"KeepShellHistoryByName not triggered. Got: {hits}"
