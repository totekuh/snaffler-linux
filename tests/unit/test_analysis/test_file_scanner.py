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


# ---------------- Large file memory safety tests ----------------

def test_scan_file_at_max_read_bytes_limit():
    """File exactly at max_read_bytes should still be scanned"""
    cfg = make_cfg()
    cfg.scanning.max_read_bytes = 2 * 1024 * 1024  # 2 MB

    accessor = MagicMock()
    accessor.can_read.return_value = True
    accessor.read.return_value = b"password=secret123"

    rule = make_rule(
        action=MatchAction.SNAFFLE,
        location=MatchLocation.FILE_CONTENT_AS_STRING,
        triage=Triage.RED,
        name="ContentRule",
    )

    rule.matches.return_value = MagicMock(
        start=lambda: 0,
        end=lambda: 8,
        group=lambda _: "password",
    )

    evaluator = RuleEvaluator(
        file_rules=[],
        content_rules=[rule],
        postmatch_rules=[],
    )

    scanner = FileScanner(cfg, accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/f.txt", "f.txt", ".txt"),
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ), patch(
        "snaffler.analysis.file_scanner.log_file_result"
    ):
        result = scanner.scan_file(
            "//srv/share/f.txt",
            make_file_info(size=2 * 1024 * 1024)  # Exactly 2 MB
        )

    # Should scan content and call read()
    accessor.read.assert_called_once()
    assert isinstance(result, FileResult)
    assert result.rule_name == "ContentRule"


def test_scan_file_over_max_read_bytes_skips_content_scan():
    """File over max_read_bytes should skip content scanning to prevent memory explosion"""
    cfg = make_cfg()
    cfg.scanning.max_read_bytes = 2 * 1024 * 1024  # 2 MB

    accessor = MagicMock()
    accessor.can_read.return_value = True
    accessor.read.return_value = b"password=secret123"

    content_rule = make_rule(
        action=MatchAction.SNAFFLE,
        location=MatchLocation.FILE_CONTENT_AS_STRING,
        triage=Triage.RED,
        name="ContentRule",
    )

    content_rule.matches.return_value = MagicMock(
        start=lambda: 0,
        end=lambda: 8,
        group=lambda _: "password",
    )

    evaluator = RuleEvaluator(
        file_rules=[],
        content_rules=[content_rule],
        postmatch_rules=[],
    )

    scanner = FileScanner(cfg, accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/huge.txt", "huge.txt", ".txt"),
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ):
        result = scanner.scan_file(
            "//srv/share/huge.txt",
            make_file_info(size=(2 * 1024 * 1024) + 1)  # 2 MB + 1 byte
        )

    # CRITICAL: read() should NOT be called to prevent memory issues
    accessor.read.assert_not_called()
    assert result is None


def test_scan_huge_file_10gb_no_memory_explosion():
    """10 GB file should not trigger content read - critical memory safety test"""
    cfg = make_cfg()
    cfg.scanning.max_read_bytes = 2 * 1024 * 1024  # 2 MB

    accessor = MagicMock()
    accessor.can_read.return_value = True

    content_rule = make_rule(
        action=MatchAction.SNAFFLE,
        location=MatchLocation.FILE_CONTENT_AS_STRING,
        triage=Triage.RED,
        name="ContentRule",
    )

    evaluator = RuleEvaluator(
        file_rules=[],
        content_rules=[content_rule],
        postmatch_rules=[],
    )

    scanner = FileScanner(cfg, accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/massive.sql", "massive.sql", ".sql"),
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ):
        result = scanner.scan_file(
            "//srv/share/massive.sql",
            make_file_info(size=10 * 1024 * 1024 * 1024)  # 10 GB
        )

    # CRITICAL: Must never call read() for huge files
    accessor.read.assert_not_called()
    assert result is None


def test_scan_huge_file_with_file_rule_still_works():
    """Large files should still match file-based rules (name/ext) without reading content"""
    cfg = make_cfg()
    cfg.scanning.max_read_bytes = 2 * 1024 * 1024  # 2 MB

    accessor = MagicMock()
    accessor.can_read.return_value = True

    # File-based rule that matches on filename
    file_rule = make_rule(
        action=MatchAction.SNAFFLE,
        location=MatchLocation.FILE_NAME,
        triage=Triage.YELLOW,
        name="SecretFileRule",
    )

    evaluator = MagicMock()
    evaluator.file_rules = [file_rule]
    evaluator.content_rules = []
    evaluator.should_discard_postmatch.return_value = False
    evaluator.evaluate_file_rule.return_value = RuleDecision(
        action=MatchAction.SNAFFLE,
        match="password",
    )

    scanner = FileScanner(cfg, accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/password.txt", "password.txt", ".txt"),
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ), patch(
        "snaffler.analysis.file_scanner.log_file_result"
    ):
        result = scanner.scan_file(
            "//srv/share/password.txt",
            make_file_info(size=10 * 1024 * 1024 * 1024)  # 10 GB
        )

    # Should match via file rule WITHOUT reading content
    accessor.read.assert_not_called()
    assert isinstance(result, FileResult)
    assert result.rule_name == "SecretFileRule"
    assert result.triage == Triage.YELLOW


def test_scan_oversized_file_with_content_rule_returns_none():
    """Oversized file with ONLY content rules should return None (not crash)"""
    cfg = make_cfg()
    cfg.scanning.max_read_bytes = 1 * 1024 * 1024  # 1 MB

    accessor = MagicMock()
    accessor.can_read.return_value = True

    content_rule = make_rule(
        action=MatchAction.SNAFFLE,
        location=MatchLocation.FILE_CONTENT_AS_STRING,
        triage=Triage.RED,
        name="PasswordInContent",
    )

    evaluator = RuleEvaluator(
        file_rules=[],
        content_rules=[content_rule],
        postmatch_rules=[],
    )

    scanner = FileScanner(cfg, accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/large.log", "large.log", ".log"),
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ):
        result = scanner.scan_file(
            "//srv/share/large.log",
            make_file_info(size=100 * 1024 * 1024)  # 100 MB
        )

    # No file rules matched, content scan skipped due to size -> returns None
    accessor.read.assert_not_called()
    assert result is None
