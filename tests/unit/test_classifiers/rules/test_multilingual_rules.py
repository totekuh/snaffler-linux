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

DATA_ROOT = Path(__file__).parents[3] / "data" / "multilingual"

# (filename, expected_rule_name)
POSITIVE_CASES = [
    # German
    ("Passwörter_Server.csv", "KeepGermanPasswordFilenames"),
    ("Kennwort_Liste.txt", "KeepGermanPasswordFilenames"),
    ("Zugangsdaten_VPN.txt", "KeepGermanPasswordFilenames"),
    ("Schlüssel_backup.txt", "KeepGermanPasswordFilenames"),
    # French
    ("mot_de_passe_wifi.txt", "KeepFrenchPasswordFilenames"),
    ("identifiants_reseau.txt", "KeepFrenchPasswordFilenames"),
    # Spanish
    ("contraseñas_servidor.txt", "KeepSpanishPasswordFilenames"),
    ("credenciales_vpn.txt", "KeepSpanishPasswordFilenames"),
    # German — extra keywords from C# Snaffler comparison
    ("Kontodaten_Server.txt", "KeepGermanPasswordFilenames"),
    ("Konten_Übersicht.txt", "KeepGermanPasswordFilenames"),
    ("Türcode_Büro.txt", "KeepGermanPasswordFilenames"),
    ("Torcode_Parkplatz.txt", "KeepGermanPasswordFilenames"),
    ("Anmeldung_VPN.txt", "KeepGermanPasswordFilenames"),
    ("Logindaten_Intranet.txt", "KeepGermanPasswordFilenames"),
    # Dutch
    ("wachtwoorden_backup.txt", "KeepDutchPasswordFilenames"),
    # Italian
    ("credenziali_accesso.txt", "KeepItalianPasswordFilenames"),
]

NEGATIVE_CASES = [
    "readme.txt",
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


@pytest.mark.parametrize("filename,expected_rule", POSITIVE_CASES)
def test_multilingual_filename_triggers_rule(filename, expected_rule, evaluator):
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

    assert hits, f"No rules matched {filename}"
    assert (
        expected_rule,
        MatchAction.SNAFFLE,
    ) in hits, f"Expected {expected_rule} not triggered for {filename}. Got: {hits}"


@pytest.mark.parametrize("filename", NEGATIVE_CASES)
def test_multilingual_no_false_positive(filename, evaluator):
    path = DATA_ROOT / filename
    assert path.exists(), f"Missing test file: {path}"

    ctx = make_ctx(path)
    hits = []

    for rule in evaluator.file_rules:
        if rule.enumeration_scope != EnumerationScope.FILE_ENUMERATION:
            continue
        # Only check the multilingual rules
        if not rule.rule_name.startswith("Keep") or "Filenames" not in rule.rule_name:
            continue
        decision = evaluator.evaluate_file_rule(rule, ctx)
        if decision:
            hits.append(rule.rule_name)

    assert not hits, f"False positive on {filename}: {hits}"
