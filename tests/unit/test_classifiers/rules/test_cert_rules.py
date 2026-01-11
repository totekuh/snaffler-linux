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
# existing PEM test files
# -----------------------------

DATA_ROOT = Path(__file__).parents[3] / "data"

PEM_FILES = [
    DATA_ROOT / "test_cert.pem",
    DATA_ROOT / "test_key.pem",
    DATA_ROOT / "test_combined.pem",
    DATA_ROOT / "pem_pass_key.pem",
    DATA_ROOT / "private_key" / "generic_key.pem",
    DATA_ROOT / "private_key" / "rsa_key.pem",
    DATA_ROOT / "relay_ssh_key" / "privatekey.pem",
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


@pytest.mark.parametrize("path", PEM_FILES, ids=lambda p: str(p.relative_to(DATA_ROOT)))
def test_pem_files_trigger_cert_check_for_keys(path, evaluator):
    """
    .pem files MUST trigger RelayCertByExtension
    and return CHECK_FOR_KEYS.
    """
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
    assert hits, f"No rules matched {path.name}"

    # 2. Cert rule fired with correct action
    assert (
               "RelayCertByExtension",
               MatchAction.CHECK_FOR_KEYS,
           ) in hits, f"RelayCertByExtension not triggered correctly. Got: {hits}"
