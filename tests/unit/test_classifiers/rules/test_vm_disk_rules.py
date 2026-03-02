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

DATA_ROOT = Path(__file__).parents[3] / "data" / "vm_disks"

VM_DISK_EXTENSIONS = [
    ".vmdk", ".vdi", ".vhd", ".vhdx",
    ".qcow2", ".qcow",
    ".avhd", ".avhdx",
    ".vma", ".vmx",
    ".img", ".e01", ".dd",
]

BACKUP_IMAGE_EXTENSIONS = [
    ".tib", ".v2i", ".mrimg", ".bkf", ".iso",
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
        name=path.name,
        ext=path.suffix.lower(),
        size=path.stat().st_size,
        modified=datetime.fromtimestamp(0),
    )


@pytest.mark.parametrize("ext", VM_DISK_EXTENSIONS)
def test_vm_disk_extensions_trigger_rule(ext, evaluator):
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
        "KeepVMDisksByExtension",
        MatchAction.SNAFFLE,
    ) in hits, f"KeepVMDisksByExtension not triggered. Got: {hits}"


@pytest.mark.parametrize("ext", BACKUP_IMAGE_EXTENSIONS)
def test_backup_image_extensions_trigger_rule(ext, evaluator):
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
        "KeepBackupImagesByExtension",
        MatchAction.SNAFFLE,
    ) in hits, f"KeepBackupImagesByExtension not triggered. Got: {hits}"


def test_non_vm_disk_not_matched(evaluator):
    """A regular file shouldn't trigger the VM disk rule."""
    path = DATA_ROOT / "test.vmdk"
    ctx = FileContext(
        unc_path="//server/share/notes.txt",
        name="notes.txt",
        ext=".txt",
        size=path.stat().st_size,
        modified=datetime.fromtimestamp(0),
    )

    for rule in evaluator.file_rules:
        if rule.rule_name not in ("KeepVMDisksByExtension", "KeepBackupImagesByExtension"):
            continue
        decision = evaluator.evaluate_file_rule(rule, ctx)
        assert decision is None, f".txt should not match {rule.rule_name}"
