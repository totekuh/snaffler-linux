from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from snaffler.analysis.file_scanner import FileScanner
from snaffler.analysis.file_result import FileResult
from snaffler.classifiers.evaluator import RuleEvaluator, RuleDecision
from snaffler.classifiers.rules import (
    MatchAction,
    MatchLocation,
    Triage,
)
from snaffler.analysis.file_context import FileContext


# ---------------- helpers ----------------

def make_cfg():
    cfg = MagicMock()
    cfg.scanning.min_interest = 0
    cfg.scanning.max_size_to_grep = 1024 * 1024
    cfg.scanning.max_size_to_snaffle = 1024 * 1024
    cfg.scanning.match_context_bytes = 20
    cfg.scanning.snaffle = False
    cfg.scanning.snaffle_path = None
    cfg.scanning.cert_passwords = []
    return cfg


def make_file_info(size=100):
    fi = MagicMock()
    fi.get_filesize.return_value = size
    return fi


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

def test_scan_file_not_readable():
    accessor = MagicMock()
    accessor.can_read.return_value = False

    evaluator = MagicMock()
    evaluator.file_rules = []

    scanner = FileScanner(make_cfg(), accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/f.txt", "f.txt", ".txt"),
    ):
        result = scanner.scan_file("//srv/share/f.txt", make_file_info())

    assert result is None


def test_scan_file_discard_rule():
    accessor = MagicMock()
    accessor.can_read.return_value = True

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
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ):
        result = scanner.scan_file("//srv/share/f.txt", make_file_info())

    assert result is None


def test_scan_file_snaffle_rule():
    accessor = MagicMock()
    accessor.can_read.return_value = True

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
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ), patch(
        "snaffler.analysis.file_scanner.log_file_result"
    ):
        result = scanner.scan_file("//srv/share/f.txt", make_file_info())

    assert isinstance(result, FileResult)
    assert result.rule_name == "SecretRule"
    assert result.triage == Triage.RED


def test_scan_file_check_for_keys():
    accessor = MagicMock()
    accessor.can_read.return_value = True
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
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ), patch.object(
        scanner.cert_checker,
        "check_certificate",
        return_value=["HasPrivateKey"],
    ), patch(
        "snaffler.analysis.file_scanner.log_file_result"
    ):
        result = scanner.scan_file("//srv/share/cert.pfx", make_file_info())

    assert isinstance(result, FileResult)
    assert result.triage == Triage.RED
    assert "HasPrivateKey" in result.context


def test_scan_file_content_rule():
    accessor = MagicMock()
    accessor.can_read.return_value = True
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
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ), patch(
        "snaffler.analysis.file_scanner.log_file_result"
    ):
        result = scanner.scan_file("//srv/share/f.txt", make_file_info())

    assert isinstance(result, FileResult)
    assert result.rule_name == "ContentRule"
    assert result.triage == Triage.YELLOW

