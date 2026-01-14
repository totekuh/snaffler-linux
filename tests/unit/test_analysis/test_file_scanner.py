from datetime import datetime
from unittest.mock import MagicMock, patch

from snaffler.analysis.file_scanner import FileScanner
from snaffler.analysis.model.file_result import FileResult
from snaffler.classifiers.evaluator import RuleEvaluator, RuleDecision
from snaffler.classifiers.rules import (
    ClassifierRule,
    EnumerationScope,
    MatchAction,
    MatchListType,
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


# ---------------- Snaffle/Copy memory safety tests ----------------

def test_snaffle_copies_file_within_size_limit():
    """When snaffle=True and file <= max_file_bytes, should copy to local"""
    cfg = make_cfg()
    cfg.scanning.snaffle = True
    cfg.scanning.snaffle_path = "/tmp/snaffle"
    cfg.scanning.max_file_bytes = 10 * 1024 * 1024  # 10 MB
    cfg.scanning.min_interest = 0

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
            make_file_info(size=5 * 1024 * 1024)  # 5 MB, under limit
        )

    # Should copy file since it's under max_file_bytes
    accessor.copy_to_local.assert_called_once_with(
        "srv", "share", "/password.txt", "/tmp/snaffle"
    )
    assert result is not None


def test_snaffle_skips_file_over_size_limit():
    """When snaffle=True but file > max_file_bytes, should NOT copy (memory safety)"""
    cfg = make_cfg()
    cfg.scanning.snaffle = True
    cfg.scanning.snaffle_path = "/tmp/snaffle"
    cfg.scanning.max_file_bytes = 10 * 1024 * 1024  # 10 MB
    cfg.scanning.min_interest = 0

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
        match="database",
    )

    scanner = FileScanner(cfg, accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/huge.sql", "huge.sql", ".sql"),
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ), patch(
        "snaffler.analysis.file_scanner.log_file_result"
    ):
        result = scanner.scan_file(
            "//srv/share/huge.sql",
            make_file_info(size=50 * 1024 * 1024)  # 50 MB, over limit
        )

    # CRITICAL: Should NOT copy file since it exceeds max_file_bytes
    accessor.copy_to_local.assert_not_called()
    # But should still return result (file matched)
    assert result is not None


# ---------------- RELAY action tests ----------------

def test_relay_action_with_content_rule_names():
    """RELAY action should collect content_rule_names for targeted content scanning"""
    cfg = make_cfg()
    cfg.scanning.max_read_bytes = 10 * 1024 * 1024

    accessor = MagicMock()
    accessor.can_read.return_value = True
    accessor.read.return_value = b"password=secret123"

    relay_rule = make_rule(action=MatchAction.RELAY)

    content_rule = make_rule(
        action=MatchAction.SNAFFLE,
        location=MatchLocation.FILE_CONTENT_AS_STRING,
        triage=Triage.YELLOW,
        name="PasswordRule",
    )
    content_rule.matches.return_value = MagicMock(
        start=lambda: 0,
        end=lambda: 8,
        group=lambda _: "password",
    )

    evaluator = RuleEvaluator(
        file_rules=[relay_rule],
        content_rules=[content_rule],
        postmatch_rules=[],
    )
    # Mock the file rule evaluation to return RELAY with specific content rules
    evaluator.evaluate_file_rule = MagicMock(
        return_value=RuleDecision(
            action=MatchAction.RELAY,
            content_rule_names=["PasswordRule"],
        )
    )

    scanner = FileScanner(cfg, accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/config.py", "config.py", ".py"),
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ), patch(
        "snaffler.analysis.file_scanner.log_file_result"
    ):
        result = scanner.scan_file(
            "//srv/share/config.py",
            make_file_info(size=100)
        )

    # Should scan content and match
    accessor.read.assert_called_once()
    assert result is not None
    assert result.rule_name == "PasswordRule"


def test_relay_action_without_content_rule_names():
    """RELAY without content_rule_names should use default content rules"""
    cfg = make_cfg()
    cfg.scanning.max_read_bytes = 10 * 1024 * 1024

    accessor = MagicMock()
    accessor.can_read.return_value = True
    accessor.read.return_value = b"api_key=abc123"

    relay_rule = make_rule(action=MatchAction.RELAY)

    content_rule = make_rule(
        action=MatchAction.SNAFFLE,
        location=MatchLocation.FILE_CONTENT_AS_STRING,
        triage=Triage.YELLOW,
        name="ApiKeyRule",
    )
    content_rule.matches.return_value = MagicMock(
        start=lambda: 0,
        end=lambda: 7,
        group=lambda _: "api_key",
    )

    evaluator = RuleEvaluator(
        file_rules=[relay_rule],
        content_rules=[content_rule],
        postmatch_rules=[],
    )
    evaluator.evaluate_file_rule = MagicMock(
        return_value=RuleDecision(
            action=MatchAction.RELAY,
            content_rule_names=None,  # No specific rules
        )
    )

    scanner = FileScanner(cfg, accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/app.py", "app.py", ".py"),
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ), patch(
        "snaffler.analysis.file_scanner.log_file_result"
    ):
        result = scanner.scan_file("//srv/share/app.py", make_file_info(size=50))

    # Should scan with all content rules
    accessor.read.assert_called_once()
    assert result is not None


# ---------------- Post-match discard tests ----------------

def test_postmatch_discard_after_file_rule_match():
    """File matching SNAFFLE rule should be discarded if postmatch rule triggers"""
    cfg = make_cfg()

    accessor = MagicMock()
    accessor.can_read.return_value = True

    rule = make_rule(
        action=MatchAction.SNAFFLE,
        triage=Triage.RED,
        name="PasswordRule",
    )

    evaluator = MagicMock()
    evaluator.file_rules = [rule]
    evaluator.should_discard_postmatch.return_value = True  # Discard it
    evaluator.evaluate_file_rule.return_value = RuleDecision(
        action=MatchAction.SNAFFLE,
        match="password",
    )

    scanner = FileScanner(cfg, accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/password.old", "password.old", ".old"),
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ):
        result = scanner.scan_file(
            "//srv/share/password.old",
            make_file_info(size=100)
        )

    # Should be discarded by postmatch rule
    assert result is None


def test_postmatch_discard_after_content_rule_match():
    """Content matching rule should be discarded if postmatch rule triggers"""
    cfg = make_cfg()
    cfg.scanning.max_read_bytes = 10 * 1024 * 1024

    accessor = MagicMock()
    accessor.can_read.return_value = True
    accessor.read.return_value = b"password=fake123"

    content_rule = make_rule(
        action=MatchAction.SNAFFLE,
        location=MatchLocation.FILE_CONTENT_AS_STRING,
        triage=Triage.YELLOW,
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
    # Mock postmatch to discard
    evaluator.should_discard_postmatch = MagicMock(return_value=True)

    scanner = FileScanner(cfg, accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/test.js", "test.js", ".js"),
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ):
        result = scanner.scan_file("//srv/share/test.js", make_file_info(size=50))

    # Content was read but result discarded
    accessor.read.assert_called_once()
    assert result is None


# ---------------- Error handling tests ----------------

def test_read_returns_none_in_content_scan():
    """When read() returns None during content scan, should handle gracefully"""
    cfg = make_cfg()
    cfg.scanning.max_read_bytes = 10 * 1024 * 1024

    accessor = MagicMock()
    accessor.can_read.return_value = True
    accessor.read.return_value = None  # Read failed

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
        return_value=("srv", "share", "/broken.txt", "broken.txt", ".txt"),
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ):
        result = scanner.scan_file(
            "//srv/share/broken.txt",
            make_file_info(size=100)
        )

    # Should return None without crashing
    assert result is None


def test_read_returns_none_in_cert_check():
    """When read() returns None during cert check, should handle gracefully"""
    cfg = make_cfg()

    accessor = MagicMock()
    accessor.can_read.return_value = True
    accessor.read.return_value = None  # Read failed

    rule = make_rule(action=MatchAction.CHECK_FOR_KEYS)

    evaluator = MagicMock()
    evaluator.file_rules = [rule]
    evaluator.evaluate_file_rule.return_value = RuleDecision(
        action=MatchAction.CHECK_FOR_KEYS
    )

    scanner = FileScanner(cfg, accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/cert.pfx", "cert.pfx", ".pfx"),
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ):
        result = scanner.scan_file(
            "//srv/share/cert.pfx",
            make_file_info(size=100)
        )

    # Should return None without crashing
    assert result is None


def test_exception_during_scan_returns_none():
    """Unhandled exception during scan should be caught and return None"""
    cfg = make_cfg()

    accessor = MagicMock()
    accessor.can_read.side_effect = Exception("Network error")

    evaluator = MagicMock()
    evaluator.file_rules = []

    scanner = FileScanner(cfg, accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/file.txt", "file.txt", ".txt"),
    ):
        result = scanner.scan_file(
            "//srv/share/file.txt",
            make_file_info(size=100)
        )

    # Should catch exception and return None
    assert result is None


# ---------------- Unicode handling tests ----------------

def test_unicode_decode_fallback_to_latin1():
    """Non-UTF8 files should fallback to latin-1 decoding"""
    cfg = make_cfg()
    cfg.scanning.max_read_bytes = 10 * 1024 * 1024

    accessor = MagicMock()
    accessor.can_read.return_value = True
    # Binary data that's not valid UTF-8
    accessor.read.return_value = b"\xff\xfe\x70\x61\x73\x73\x77\x6f\x72\x64"

    content_rule = make_rule(
        action=MatchAction.SNAFFLE,
        location=MatchLocation.FILE_CONTENT_AS_STRING,
        triage=Triage.YELLOW,
        name="BinaryRule",
    )
    # The pattern will still try to match the latin-1 decoded string
    content_rule.matches.return_value = None  # Doesn't match, but that's OK

    evaluator = RuleEvaluator(
        file_rules=[],
        content_rules=[content_rule],
        postmatch_rules=[],
    )

    scanner = FileScanner(cfg, accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/binary.dat", "binary.dat", ".dat"),
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ):
        result = scanner.scan_file(
            "//srv/share/binary.dat",
            make_file_info(size=100)
        )

    # Should not crash, just return None (no match)
    assert result is None


# ---------------- Min interest filtering tests ----------------

def test_min_interest_filters_low_priority_results():
    """Results below min_interest threshold should be filtered out"""
    cfg = make_cfg()
    cfg.scanning.min_interest = 2  # Only RED (2) and BLACK (3)

    accessor = MagicMock()
    accessor.can_read.return_value = True

    rule = make_rule(
        action=MatchAction.SNAFFLE,
        triage=Triage.YELLOW,  # YELLOW is 1, below threshold of 2
        name="LowPriorityRule",
    )

    evaluator = MagicMock()
    evaluator.file_rules = [rule]
    evaluator.should_discard_postmatch.return_value = False
    evaluator.evaluate_file_rule.return_value = RuleDecision(
        action=MatchAction.SNAFFLE,
        match="debug",
    )

    scanner = FileScanner(cfg, accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/debug.log", "debug.log", ".log"),
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ):
        result = scanner.scan_file(
            "//srv/share/debug.log",
            make_file_info(size=100)
        )

    # Should be filtered out due to low triage level
    assert result is None


def test_min_interest_allows_high_priority_results():
    """Results at or above min_interest should pass through"""
    cfg = make_cfg()
    cfg.scanning.min_interest = 2  # Only RED (2) and BLACK (3)

    accessor = MagicMock()
    accessor.can_read.return_value = True

    rule = make_rule(
        action=MatchAction.SNAFFLE,
        triage=Triage.RED,  # RED is 2, at threshold
        name="HighPriorityRule",
    )

    evaluator = MagicMock()
    evaluator.file_rules = [rule]
    evaluator.should_discard_postmatch.return_value = False
    evaluator.evaluate_file_rule.return_value = RuleDecision(
        action=MatchAction.SNAFFLE,
        match="password",
    )

    scanner = FileScanner(cfg, accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/secret.txt", "secret.txt", ".txt"),
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ), patch(
        "snaffler.analysis.file_scanner.log_file_result"
    ):
        result = scanner.scan_file(
            "//srv/share/secret.txt",
            make_file_info(size=100)
        )

    # Should pass through
    assert result is not None
    assert result.triage == Triage.RED


# ---------------- Edge case tests ----------------

def test_parse_unc_path_returns_none():
    """Invalid UNC path should return None gracefully"""
    cfg = make_cfg()
    accessor = MagicMock()
    evaluator = MagicMock()
    evaluator.file_rules = []

    scanner = FileScanner(cfg, accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=None,  # Invalid path
    ):
        result = scanner.scan_file("invalid_path", make_file_info())

    assert result is None


def test_cert_check_no_private_key():
    """Certificate without private key should return None"""
    cfg = make_cfg()

    accessor = MagicMock()
    accessor.can_read.return_value = True
    accessor.read.return_value = b"CERT_DATA"

    rule = make_rule(action=MatchAction.CHECK_FOR_KEYS)

    evaluator = MagicMock()
    evaluator.file_rules = [rule]
    evaluator.evaluate_file_rule.return_value = RuleDecision(
        action=MatchAction.CHECK_FOR_KEYS
    )

    scanner = FileScanner(cfg, accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/cert.pem", "cert.pem", ".pem"),
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ), patch.object(
        scanner.cert_checker,
        "check_certificate",
        return_value=[],  # No reasons, or no HasPrivateKey
    ):
        result = scanner.scan_file(
            "//srv/share/cert.pem",
            make_file_info(size=100)
        )

    # Should return None if no private key
    assert result is None


def test_content_rule_no_match():
    """Content rule that doesn't match should return None"""
    cfg = make_cfg()
    cfg.scanning.max_read_bytes = 10 * 1024 * 1024

    accessor = MagicMock()
    accessor.can_read.return_value = True
    accessor.read.return_value = b"no secrets here"

    content_rule = make_rule(
        action=MatchAction.SNAFFLE,
        location=MatchLocation.FILE_CONTENT_AS_STRING,
        triage=Triage.RED,
        name="PasswordRule",
    )
    content_rule.matches.return_value = None  # No match

    evaluator = RuleEvaluator(
        file_rules=[],
        content_rules=[content_rule],
        postmatch_rules=[],
    )

    scanner = FileScanner(cfg, accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/clean.txt", "clean.txt", ".txt"),
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ):
        result = scanner.scan_file(
            "//srv/share/clean.txt",
            make_file_info(size=100)
        )

    # No match -> None
    assert result is None


def test_multiple_file_rules_pick_best():
    """When multiple file rules match, should pick highest severity"""
    cfg = make_cfg()

    accessor = MagicMock()
    accessor.can_read.return_value = True

    low_rule = make_rule(
        action=MatchAction.SNAFFLE,
        triage=Triage.GREEN,
        name="LowRule",
    )
    high_rule = make_rule(
        action=MatchAction.SNAFFLE,
        triage=Triage.RED,
        name="HighRule",
    )

    evaluator = MagicMock()
    evaluator.file_rules = [low_rule, high_rule]
    evaluator.should_discard_postmatch.return_value = False

    # Both rules match
    evaluator.evaluate_file_rule.side_effect = [
        RuleDecision(action=MatchAction.SNAFFLE, match="low"),
        RuleDecision(action=MatchAction.SNAFFLE, match="high"),
    ]

    scanner = FileScanner(cfg, accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/multi.txt", "multi.txt", ".txt"),
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ), patch(
        "snaffler.analysis.file_scanner.log_file_result"
    ):
        result = scanner.scan_file(
            "//srv/share/multi.txt",
            make_file_info(size=100)
        )

    # Should pick RED over GREEN
    assert result is not None
    assert result.triage == Triage.RED
    assert result.rule_name == "HighRule"


def test_file_and_content_rules_pick_best():
    """When both file and content rules match, should pick highest severity"""
    cfg = make_cfg()
    cfg.scanning.max_read_bytes = 10 * 1024 * 1024

    accessor = MagicMock()
    accessor.can_read.return_value = True
    accessor.read.return_value = b"password=secret"

    file_rule = make_rule(
        action=MatchAction.SNAFFLE,
        triage=Triage.GREEN,
        name="FileRule",
    )

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
        file_rules=[file_rule],
        content_rules=[content_rule],
        postmatch_rules=[],
    )
    evaluator.evaluate_file_rule = MagicMock(
        return_value=RuleDecision(action=MatchAction.SNAFFLE, match="file")
    )
    evaluator.should_discard_postmatch = MagicMock(return_value=False)

    scanner = FileScanner(cfg, accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/both.txt", "both.txt", ".txt"),
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ), patch(
        "snaffler.analysis.file_scanner.log_file_result"
    ):
        result = scanner.scan_file(
            "//srv/share/both.txt",
            make_file_info(size=100)
        )

    # Should pick content rule (RED) over file rule (GREEN)
    assert result is not None
    assert result.triage == Triage.RED
    assert result.rule_name == "ContentRule"


def test_file_rule_no_match_falls_through_to_content_scan():
    """CRITICAL: File rule doesn't match (returns None), should still scan content

    This tests line 107-108: if not decision: continue
    Common scenario: File "data.txt" doesn't match file rule "password*.txt"
    but content contains "password=secret" and should be found.
    """
    cfg = make_cfg()
    cfg.scanning.max_read_bytes = 10 * 1024 * 1024

    accessor = MagicMock()
    accessor.can_read.return_value = True
    accessor.read.return_value = b"some data with password=secret123 inside"

    # File rule that WON'T match "data.txt" (looks for password*.txt)
    file_rule = ClassifierRule(
        rule_name="PasswordFileNameRule",
        enumeration_scope=EnumerationScope.FILE_ENUMERATION,
        match_action=MatchAction.SNAFFLE,
        match_location=MatchLocation.FILE_NAME,
        wordlist_type=MatchListType.REGEX,
        wordlist=[r"^password.*\.txt$"],
        triage=Triage.YELLOW,
    )

    # Content rule that WILL match "password=" in content
    content_rule = ClassifierRule(
        rule_name="PasswordInContentRule",
        enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
        match_action=MatchAction.SNAFFLE,
        match_location=MatchLocation.FILE_CONTENT_AS_STRING,
        wordlist_type=MatchListType.CONTAINS,
        wordlist=["password="],
        triage=Triage.RED,
    )

    # Use REAL RuleEvaluator (not mocked) to test actual evaluation flow
    evaluator = RuleEvaluator(
        file_rules=[file_rule],
        content_rules=[content_rule],
        postmatch_rules=[],
    )

    scanner = FileScanner(cfg, accessor, evaluator)

    with patch(
        "snaffler.analysis.file_scanner.parse_unc_path",
        return_value=("srv", "share", "/data.txt", "data.txt", ".txt"),
    ), patch(
        "snaffler.analysis.file_scanner.get_modified_time",
        return_value=datetime.now(),
    ), patch(
        "snaffler.analysis.file_scanner.log_file_result"
    ):
        result = scanner.scan_file(
            "//srv/share/data.txt",
            make_file_info(size=100)
        )

    # CRITICAL: File rule didn't match, but content scan should still happen
    # Lines 107-108 executed: if not decision: continue
    # Then falls through to content scan at line 163
    accessor.read.assert_called_once()
    assert result is not None
    assert result.rule_name == "PasswordInContentRule"
    assert result.triage == Triage.RED
    assert "password=" in result.match
