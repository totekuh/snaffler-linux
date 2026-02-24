from datetime import datetime
from unittest.mock import MagicMock, patch

from snaffler.analysis.file_scanner import FileScanner
from snaffler.analysis.model.file_result import FileResult
from snaffler.classifiers.evaluator import RuleEvaluator, RuleDecision
from snaffler.classifiers.rules import (
    MatchAction,
    MatchLocation,
    Triage,
)


# ---------------- helpers ----------------

def make_cfg():
    cfg = MagicMock()
    cfg.scanning.min_interest = 0
    cfg.scanning.max_read_bytes = 1024 * 1024
    cfg.scanning.max_file_bytes = 1024 * 1024
    cfg.scanning.match_context_bytes = 20
    cfg.scanning.snaffle = False
    cfg.scanning.snaffle_path = None
    cfg.scanning.cert_passwords = []
    return cfg


def make_rule(
    action,
    location=MatchLocation.FILE_NAME,
    triage=Triage.GREEN,
    name="TestRule",
):
    rule = MagicMock()
    rule.match_action = action
    rule.match_location = location
    rule.triage = triage
    rule.rule_name = name
    return rule


# ---------------- tests ----------------

def test_scan_file_unreadable_content():
    """When read() returns None (access denied), content scan is skipped gracefully."""
    accessor = MagicMock()
    accessor.read.return_value = None

    rule = make_rule(
        action=MatchAction.SNAFFLE,
        location=MatchLocation.FILE_CONTENT_AS_STRING,
        triage=Triage.YELLOW,
        name="ContentRule",
    )

    evaluator = RuleEvaluator(
        file_rules=[],
        content_rules=[rule],
        postmatch_rules=[],
    )

    scanner = FileScanner(make_cfg(), accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/f.txt", "f.txt", ".txt"),
    ):
        result = scanner.scan_file("//srv/share/f.txt", 100, 1700000000.0)

    assert result is None
    accessor.read.assert_called_once()


def test_scan_file_discard_rule():
    accessor = MagicMock()


    rule = make_rule(action=MatchAction.DISCARD)

    evaluator = MagicMock()
    evaluator.file_rules = [rule]
    evaluator.evaluate_file_rule.return_value = RuleDecision(
        action=MatchAction.DISCARD
    )

    scanner = FileScanner(make_cfg(), accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/f.txt", "f.txt", ".txt"),
    ):
        result = scanner.scan_file("//srv/share/f.txt", 100, 1700000000.0)

    assert result is None


def test_scan_file_snaffle_rule():
    accessor = MagicMock()


    rule = make_rule(
        action=MatchAction.SNAFFLE,
        triage=Triage.RED,
        name="SecretRule",
    )

    evaluator = MagicMock()
    evaluator.file_rules = [rule]
    evaluator.should_discard_postmatch.return_value = False
    evaluator.evaluate_file_rule.return_value = RuleDecision(
        action=MatchAction.SNAFFLE,
        match="secret",
    )

    scanner = FileScanner(make_cfg(), accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/f.txt", "f.txt", ".txt"),
    ), patch(
        "snaffler.analysis.file_scanner.log_file_result"
    ):
        result = scanner.scan_file("//srv/share/f.txt", 100, 1700000000.0)

    assert isinstance(result, FileResult)
    assert result.rule_name == "SecretRule"
    assert result.triage == Triage.RED


def test_scan_file_check_for_keys():
    accessor = MagicMock()

    accessor.read.return_value = b"CERTDATA"

    rule = make_rule(action=MatchAction.CHECK_FOR_KEYS)

    evaluator = MagicMock()
    evaluator.file_rules = [rule]
    evaluator.evaluate_file_rule.return_value = RuleDecision(
        action=MatchAction.CHECK_FOR_KEYS
    )

    scanner = FileScanner(make_cfg(), accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/cert.pfx", "cert.pfx", ".pfx"),
    ), patch.object(
        scanner.cert_checker,
        "check_certificate",
        return_value=["HasPrivateKey"],
    ), patch(
        "snaffler.analysis.file_scanner.log_file_result"
    ):
        result = scanner.scan_file("//srv/share/cert.pfx", 100, 1700000000.0)

    assert isinstance(result, FileResult)
    assert result.triage == Triage.RED
    assert "HasPrivateKey" in result.context


def test_scan_file_content_rule():
    accessor = MagicMock()

    accessor.read.return_value = b"this contains password=123"

    rule = make_rule(
        action=MatchAction.SNAFFLE,
        location=MatchLocation.FILE_CONTENT_AS_STRING,
        triage=Triage.YELLOW,
        name="ContentRule",
    )

    rule.matches.return_value = MagicMock(
        start=lambda: 14,
        end=lambda: 22,
        group=lambda _: "password",
    )

    evaluator = RuleEvaluator(
        file_rules=[],
        content_rules=[rule],
        postmatch_rules=[],
    )

    scanner = FileScanner(make_cfg(), accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/f.txt", "f.txt", ".txt"),
    ), patch(
        "snaffler.analysis.file_scanner.log_file_result"
    ):
        result = scanner.scan_file("//srv/share/f.txt", 100, 1700000000.0)

    assert isinstance(result, FileResult)
    assert result.rule_name == "ContentRule"
    assert result.triage == Triage.YELLOW


def test_scan_file_zero_mtime():
    """mtime_epoch=0 should result in modified=None."""
    accessor = MagicMock()


    evaluator = MagicMock()
    evaluator.file_rules = []
    evaluator.content_rules = []

    scanner = FileScanner(make_cfg(), accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/f.txt", "f.txt", ".txt"),
    ):
        result = scanner.scan_file("//srv/share/f.txt", 100, 0.0)

    # No rules match → None result, but we just verify it doesn't crash
    assert result is None


def test_scan_file_black_triage_skips_content_scan():
    """Black-triage file match should skip content scanning entirely (no read() call)."""
    accessor = MagicMock()

    file_rule = make_rule(
        action=MatchAction.SNAFFLE,
        triage=Triage.BLACK,
        name="KeepNtdsBlack",
    )

    content_rule = make_rule(
        action=MatchAction.SNAFFLE,
        location=MatchLocation.FILE_CONTENT_AS_STRING,
        triage=Triage.YELLOW,
        name="ContentRule",
    )

    evaluator = MagicMock()
    evaluator.file_rules = [file_rule]
    evaluator.content_rules = [content_rule]
    evaluator.should_discard_postmatch.return_value = False
    evaluator.evaluate_file_rule.return_value = RuleDecision(
        action=MatchAction.SNAFFLE,
        match="ntds.dit",
    )

    scanner = FileScanner(make_cfg(), accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/ntds.dit", "ntds.dit", ".dit"),
    ), patch(
        "snaffler.analysis.file_scanner.log_file_result"
    ):
        result = scanner.scan_file("//srv/share/ntds.dit", 100, 1700000000.0)

    assert isinstance(result, FileResult)
    assert result.triage == Triage.BLACK
    assert result.rule_name == "KeepNtdsBlack"
    # read() should NOT have been called — content scan was skipped
    accessor.read.assert_not_called()
