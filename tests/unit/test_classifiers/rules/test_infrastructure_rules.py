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

DATA_ROOT = Path(__file__).parents[3] / "data" / "infrastructure"

EXTENSION_FILENAMES = [
    ("ServiceConfiguration.cscfg", ".cscfg"),
    ("config.ucs", ".ucs"),
    ("terraform.tfvars", ".tfvars"),
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


@pytest.mark.parametrize("filename,extension", EXTENSION_FILENAMES)
def test_infrastructure_files_by_extension_trigger_keep_rule(filename, extension, evaluator):
    """
    Infrastructure as Code files matched by extension (.cscfg, .ucs, .tfvars)
    MUST trigger KeepInfraAsCodeByExtension and result in SNAFFLE with RED triage.
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
        "KeepInfraAsCodeByExtension",
        MatchAction.SNAFFLE,
    ) in hits, f"KeepInfraAsCodeByExtension not triggered. Got: {hits}"
