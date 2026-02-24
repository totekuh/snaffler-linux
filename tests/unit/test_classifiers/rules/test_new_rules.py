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


def _match(evaluator, ctx):
    hits = []
    for rule in evaluator.file_rules:
        if rule.enumeration_scope != EnumerationScope.FILE_ENUMERATION:
            continue
        decision = evaluator.evaluate_file_rule(rule, ctx)
        if decision:
            hits.append((rule.rule_name, decision.action, rule.triage))
    return hits


DATA = Path(__file__).parents[3] / "data"


# ---------- Terraform state ----------

class TestTerraformState:
    def test_tfstate_extension(self, evaluator):
        ctx = make_ctx(DATA / "terraform_state" / "prod.tfstate")
        hits = _match(evaluator, ctx)
        names = [h[0] for h in hits]
        assert "KeepTerraformStateByExtension" in names
        match = next(h for h in hits if h[0] == "KeepTerraformStateByExtension")
        assert match[1] == MatchAction.SNAFFLE
        assert match[2] == Triage.RED

    def test_tfstate_backup(self, evaluator):
        ctx = make_ctx(DATA / "terraform_state" / "prod.tfstate.backup")
        hits = _match(evaluator, ctx)
        names = [h[0] for h in hits]
        assert "KeepTerraformStateBackupByName" in names
        match = next(h for h in hits if h[0] == "KeepTerraformStateBackupByName")
        assert match[1] == MatchAction.SNAFFLE
        assert match[2] == Triage.RED


# ---------- WinSCP ----------

class TestWinScp:
    def test_winscp_ini(self, evaluator):
        ctx = make_ctx(DATA / "winscp" / "winscp.ini")
        hits = _match(evaluator, ctx)
        names = [h[0] for h in hits]
        assert "KeepWinScpByName" in names
        match = next(h for h in hits if h[0] == "KeepWinScpByName")
        assert match[1] == MatchAction.SNAFFLE
        assert match[2] == Triage.RED


# ---------- .env variants ----------

class TestEnvVariants:
    @pytest.mark.parametrize("filename", [".env.local", ".env.production", ".env.backup"])
    def test_env_variant_triggers(self, filename, evaluator):
        ctx = make_ctx(DATA / "env_variants" / filename)
        hits = _match(evaluator, ctx)
        names = [h[0] for h in hits]
        assert "KeepEnvVariantsByName" in names
        match = next(h for h in hits if h[0] == "KeepEnvVariantsByName")
        assert match[1] == MatchAction.SNAFFLE
        assert match[2] == Triage.RED

    def test_plain_env_not_matched_by_variants_rule(self, evaluator):
        """The base .env file should NOT trigger KeepEnvVariantsByName."""
        path = DATA / "env_variants" / ".env.local"
        ctx = FileContext(
            unc_path="//HOST/share/.env",
            smb_path="\\share\\.env",
            name=".env",
            ext="",
            size=path.stat().st_size,
            modified=datetime.fromtimestamp(0),
        )
        hits = _match(evaluator, ctx)
        names = [h[0] for h in hits]
        assert "KeepEnvVariantsByName" not in names
