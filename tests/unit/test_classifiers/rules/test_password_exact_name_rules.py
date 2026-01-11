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

# -----------------------------
# paths
# -----------------------------

DATA_ROOT = Path(__file__).parents[3] / "data" / "password_exact"

FILENAMES = [
    "passwords.txt", "pass.txt", "accounts.txt",
    "passwords.doc", "pass.doc", "accounts.doc",
    "passwords.xls", "pass.xls", "accounts.xls",
    "passwords.docx", "pass.docx", "accounts.docx",
    "passwords.xlsx", "pass.xlsx", "accounts.xlsx",
    "secrets.txt", "secrets.doc", "secrets.xls",
    "secrets.docx", "secrets.xlsx",
    "BitlockerLAPSPasswords.csv",
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
def test_exact_password_filename_triggers_red_rule(filename, evaluator):
    """
    Files with EXACT sensitive names MUST trigger
    KeepPasswordFilesByName and result in SNAFFLE.
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

    # 1. Something matched
    assert hits, f"No rules matched {filename}"

    # 2. Correct rule matched with correct action
    assert (
               "KeepPasswordFilesByName",
               MatchAction.SNAFFLE,
           ) in hits, f"Expected KeepPasswordFilesByName not triggered. Got: {hits}"
