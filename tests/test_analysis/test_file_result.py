from datetime import datetime

from snaffler.analysis.file_result import FileResult
from snaffler.classifiers.rules import Triage


def make_result(triage: Triage) -> FileResult:
    return FileResult(
        file_path="//HOST/SHARE/file.txt",
        size=123,
        modified=datetime(2024, 1, 1),
        triage=triage,
        rule_name="TestRule",
        match="secret",
        context="context",
    )


# ---------- constructor ----------

def test_file_result_init():
    r = make_result(Triage.RED)

    assert r.file_path == "//HOST/SHARE/file.txt"
    assert r.size == 123
    assert r.modified.year == 2024
    assert r.triage == Triage.RED
    assert r.rule_name == "TestRule"
    assert r.match == "secret"
    assert r.context == "context"


# ---------- pick_best ----------

def test_pick_best_current_none():
    candidate = make_result(Triage.YELLOW)

    result = FileResult.pick_best(None, candidate)

    assert result is candidate


def test_pick_best_candidate_none():
    current = make_result(Triage.YELLOW)

    result = FileResult.pick_best(current, None)

    assert result is current


def test_pick_best_candidate_more_severe():
    current = make_result(Triage.YELLOW)
    candidate = make_result(Triage.RED)

    result = FileResult.pick_best(current, candidate)

    assert result is candidate


def test_pick_best_candidate_less_severe():
    current = make_result(Triage.RED)
    candidate = make_result(Triage.GREEN)

    result = FileResult.pick_best(current, candidate)

    assert result is current


def test_pick_best_same_severity_keeps_current():
    current = make_result(Triage.RED)
    candidate = make_result(Triage.RED)

    result = FileResult.pick_best(current, candidate)

    assert result is current
