import io
import os
import zipfile
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from snaffler.analysis.file_scanner import FileScanner
from snaffler.analysis.model.file_context import FileContext
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

TEST_ARCHIVE = os.path.join(
    os.path.dirname(__file__), os.pardir, os.pardir, "data", "test_archive.zip"
)
TEST_RAR_SENSITIVE = os.path.join(
    os.path.dirname(__file__), os.pardir, os.pardir, "data", "archives", "sensitive_archive.rar"
)
TEST_RAR_BORING = os.path.join(
    os.path.dirname(__file__), os.pardir, os.pardir, "data", "archives", "boring_archive.rar"
)


# ---------------- helpers ----------------

def make_cfg(max_read=2 * 1024 * 1024, match_filter=None):
    cfg = MagicMock()
    cfg.scanning.min_interest = 0
    cfg.scanning.max_read_bytes = max_read
    cfg.scanning.max_file_bytes = max_read
    cfg.scanning.match_context_bytes = 20
    cfg.scanning.snaffle = False
    cfg.scanning.snaffle_path = None
    cfg.scanning.cert_passwords = []
    cfg.scanning.match_filter = match_filter
    return cfg


def _zip_bytes(*members):
    """Build an in-memory ZIP.  members = [(name, content_bytes), ...]"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def _password_rule():
    """File rule that SNAFFLEs files named 'passwords.txt'."""
    return ClassifierRule(
        rule_name="KeepPasswordFileBlack",
        enumeration_scope=EnumerationScope.FILE_ENUMERATION,
        match_action=MatchAction.SNAFFLE,
        match_location=MatchLocation.FILE_NAME,
        wordlist_type=MatchListType.EXACT,
        wordlist=["passwords.txt"],
        triage=Triage.BLACK,
    )


def _ssh_key_rule():
    """File rule that SNAFFLEs files named 'id_rsa'."""
    return ClassifierRule(
        rule_name="KeepIdRsaBlack",
        enumeration_scope=EnumerationScope.FILE_ENUMERATION,
        match_action=MatchAction.SNAFFLE,
        match_location=MatchLocation.FILE_NAME,
        wordlist_type=MatchListType.EXACT,
        wordlist=["id_rsa"],
        triage=Triage.BLACK,
    )


def _archive_rule(ext=".zip"):
    """File rule that triggers ENTER_ARCHIVE for the given extension."""
    return ClassifierRule(
        rule_name="EnterZipByExtension",
        enumeration_scope=EnumerationScope.FILE_ENUMERATION,
        match_action=MatchAction.ENTER_ARCHIVE,
        match_location=MatchLocation.FILE_EXTENSION,
        wordlist_type=MatchListType.EXACT,
        wordlist=[ext],
        triage=Triage.GREEN,
    )


def _discard_rule(name):
    """Postmatch rule that DISCARDs files with the given name."""
    return ClassifierRule(
        rule_name="DiscardBoring",
        enumeration_scope=EnumerationScope.POST_MATCH,
        match_action=MatchAction.DISCARD,
        match_location=MatchLocation.FILE_NAME,
        wordlist_type=MatchListType.EXACT,
        wordlist=[name],
        triage=Triage.GREEN,
    )


# ---------------- tests ----------------

class TestArchivePeek:

    def test_zip_with_sensitive_file(self):
        """ZIP containing passwords.txt → Black finding."""
        zip_data = _zip_bytes(
            ("passwords.txt", b"admin:hunter2"),
            ("readme.txt", b"nothing here"),
        )
        accessor = MagicMock()
        accessor.read.return_value = zip_data

        evaluator = RuleEvaluator(
            file_rules=[_archive_rule(), _password_rule()],
            content_rules=[],
            postmatch_rules=[],
        )

        scanner = FileScanner(make_cfg(), accessor, evaluator)

        with patch("snaffler.analysis.file_scanner.log_file_result"):
            result = scanner.scan_file("//srv/share/backups/stuff.zip", 500, 1700000000.0)

        assert isinstance(result, FileResult)
        assert result.triage == Triage.BLACK
        assert result.rule_name == "KeepPasswordFileBlack"
        assert "\u2192passwords.txt" in result.file_path

    def test_zip_nothing_interesting(self):
        """ZIP with only boring files → no finding."""
        zip_data = _zip_bytes(
            ("readme.txt", b"nothing"),
            ("data.csv", b"1,2,3"),
        )
        accessor = MagicMock()
        accessor.read.return_value = zip_data

        evaluator = RuleEvaluator(
            file_rules=[_archive_rule(), _password_rule()],
            content_rules=[],
            postmatch_rules=[],
        )

        scanner = FileScanner(make_cfg(), accessor, evaluator)

        with patch("snaffler.analysis.file_scanner.log_file_result"):
            result = scanner.scan_file("//srv/share/stuff.zip", 500, 1700000000.0)

        assert result is None

    def test_corrupt_archive_returns_none(self):
        """Corrupt ZIP data → no crash, returns None."""
        accessor = MagicMock()
        accessor.read.return_value = b"this is not a zip file at all"

        evaluator = RuleEvaluator(
            file_rules=[_archive_rule(), _password_rule()],
            content_rules=[],
            postmatch_rules=[],
        )

        scanner = FileScanner(make_cfg(), accessor, evaluator)

        with patch("snaffler.analysis.file_scanner.log_file_result"):
            result = scanner.scan_file("//srv/share/bad.zip", 100, 1700000000.0)

        assert result is None

    def test_archive_over_max_read_bytes_skipped(self):
        """Archive larger than max_read_bytes → no peeking, no read() call."""
        accessor = MagicMock()

        evaluator = RuleEvaluator(
            file_rules=[_archive_rule(), _password_rule()],
            content_rules=[],
            postmatch_rules=[],
        )

        scanner = FileScanner(make_cfg(max_read=100), accessor, evaluator)

        with patch("snaffler.analysis.file_scanner.log_file_result"):
            result = scanner.scan_file("//srv/share/big.zip", 999999, 1700000000.0)

        # No read because size > max_read_bytes
        accessor.read.assert_not_called()
        assert result is None

    def test_nested_archive_not_recursed(self):
        """ZIP inside ZIP → inner ZIP is not recursed into."""
        inner_zip = _zip_bytes(("passwords.txt", b"secret"))
        outer_zip = _zip_bytes(("inner.zip", inner_zip))

        accessor = MagicMock()
        accessor.read.return_value = outer_zip

        evaluator = RuleEvaluator(
            file_rules=[_archive_rule(), _password_rule()],
            content_rules=[],
            postmatch_rules=[],
        )

        scanner = FileScanner(make_cfg(), accessor, evaluator)

        with patch("snaffler.analysis.file_scanner.log_file_result"):
            result = scanner.scan_file("//srv/share/nested.zip", 500, 1700000000.0)

        # inner.zip triggers ENTER_ARCHIVE but _peek_archive skips recursive
        # ENTER_ARCHIVE actions — only SNAFFLE is handled for members.
        # passwords.txt is NOT found because it's inside inner.zip.
        assert result is None

    def test_postmatch_discard_on_member(self):
        """Postmatch discard rule filters out a member finding."""
        zip_data = _zip_bytes(("passwords.txt", b"secret"))

        accessor = MagicMock()
        accessor.read.return_value = zip_data

        evaluator = RuleEvaluator(
            file_rules=[_archive_rule(), _password_rule()],
            content_rules=[],
            postmatch_rules=[_discard_rule("passwords.txt")],
        )

        scanner = FileScanner(make_cfg(), accessor, evaluator)

        with patch("snaffler.analysis.file_scanner.log_file_result"):
            result = scanner.scan_file("//srv/share/stuff.zip", 500, 1700000000.0)

        assert result is None

    def test_member_unc_path_format(self):
        """Member UNC path uses → separator."""
        zip_data = _zip_bytes(("passwords.txt", b"secret"))

        accessor = MagicMock()
        accessor.read.return_value = zip_data

        evaluator = RuleEvaluator(
            file_rules=[_archive_rule(), _password_rule()],
            content_rules=[],
            postmatch_rules=[],
        )

        scanner = FileScanner(make_cfg(), accessor, evaluator)

        with patch("snaffler.analysis.file_scanner.log_file_result"):
            result = scanner.scan_file("//srv/share/archive.zip", 500, 1700000000.0)

        assert result is not None
        assert result.file_path == "//srv/share/archive.zip\u2192passwords.txt"

    def test_7z_missing_py7zr_skips(self):
        """When py7zr is not installed, 7z peeking is skipped gracefully."""
        accessor = MagicMock()
        accessor.read.return_value = b"fake7zdata"

        evaluator = RuleEvaluator(
            file_rules=[_archive_rule(".7z"), _password_rule()],
            content_rules=[],
            postmatch_rules=[],
        )

        scanner = FileScanner(make_cfg(), accessor, evaluator)

        with patch("snaffler.analysis.file_scanner.log_file_result"), \
             patch.dict("sys.modules", {"py7zr": None}):
            result = scanner.scan_file("//srv/share/stuff.7z", 500, 1700000000.0)

        assert result is None

    def test_read_returns_none_skips(self):
        """When read() returns None (access denied), archive peek is skipped."""
        accessor = MagicMock()
        accessor.read.return_value = None

        evaluator = RuleEvaluator(
            file_rules=[_archive_rule(), _password_rule()],
            content_rules=[],
            postmatch_rules=[],
        )

        scanner = FileScanner(make_cfg(), accessor, evaluator)

        with patch("snaffler.analysis.file_scanner.log_file_result"):
            result = scanner.scan_file("//srv/share/stuff.zip", 500, 1700000000.0)

        assert result is None

    def test_real_test_archive(self):
        """Integration-style test using tests/data/test_archive.zip."""
        with open(TEST_ARCHIVE, "rb") as f:
            zip_data = f.read()

        accessor = MagicMock()
        accessor.read.return_value = zip_data

        evaluator = RuleEvaluator(
            file_rules=[_archive_rule(), _password_rule(), _ssh_key_rule()],
            content_rules=[],
            postmatch_rules=[],
        )

        scanner = FileScanner(make_cfg(), accessor, evaluator)

        with patch("snaffler.analysis.file_scanner.log_file_result"):
            result = scanner.scan_file(
                "//srv/share/test_archive.zip", len(zip_data), 1700000000.0
            )

        assert isinstance(result, FileResult)
        assert result.triage == Triage.BLACK

    def test_match_filter_applies_to_archive_members(self):
        """--match filter applies to archive member findings."""
        zip_data = _zip_bytes(("passwords.txt", b"secret"))

        accessor = MagicMock()
        accessor.read.return_value = zip_data

        evaluator = RuleEvaluator(
            file_rules=[_archive_rule(), _password_rule()],
            content_rules=[],
            postmatch_rules=[],
        )

        scanner = FileScanner(
            make_cfg(match_filter="nomatch_pattern"), accessor, evaluator
        )

        with patch("snaffler.analysis.file_scanner.log_file_result"):
            result = scanner.scan_file("//srv/share/stuff.zip", 500, 1700000000.0)

        # --match filter suppresses the output
        assert result is None

    def test_subdirectory_member_uses_filename_only(self):
        """Members in subdirs: name is the filename part, not the full path."""
        zip_data = _zip_bytes(("subdir/passwords.txt", b"secret"))

        accessor = MagicMock()
        accessor.read.return_value = zip_data

        evaluator = RuleEvaluator(
            file_rules=[_archive_rule(), _password_rule()],
            content_rules=[],
            postmatch_rules=[],
        )

        scanner = FileScanner(make_cfg(), accessor, evaluator)

        with patch("snaffler.analysis.file_scanner.log_file_result"):
            result = scanner.scan_file("//srv/share/stuff.zip", 500, 1700000000.0)

        assert isinstance(result, FileResult)
        assert result.triage == Triage.BLACK
        assert "\u2192subdir/passwords.txt" in result.file_path


class TestRarArchivePeek:

    def test_rar_with_sensitive_file(self):
        """RAR containing id_rsa → Black finding."""
        with open(TEST_RAR_SENSITIVE, "rb") as f:
            rar_data = f.read()

        accessor = MagicMock()
        accessor.read.return_value = rar_data

        evaluator = RuleEvaluator(
            file_rules=[_archive_rule(".rar"), _password_rule(), _ssh_key_rule()],
            content_rules=[],
            postmatch_rules=[],
        )

        scanner = FileScanner(make_cfg(), accessor, evaluator)

        with patch("snaffler.analysis.file_scanner.log_file_result"):
            result = scanner.scan_file("//srv/share/backup.rar", len(rar_data), 1700000000.0)

        assert isinstance(result, FileResult)
        assert result.triage == Triage.BLACK
        assert "\u2192" in result.file_path

    def test_rar_nothing_interesting(self):
        """RAR with only boring files → no finding."""
        with open(TEST_RAR_BORING, "rb") as f:
            rar_data = f.read()

        accessor = MagicMock()
        accessor.read.return_value = rar_data

        evaluator = RuleEvaluator(
            file_rules=[_archive_rule(".rar"), _password_rule()],
            content_rules=[],
            postmatch_rules=[],
        )

        scanner = FileScanner(make_cfg(), accessor, evaluator)

        with patch("snaffler.analysis.file_scanner.log_file_result"):
            result = scanner.scan_file("//srv/share/stuff.rar", len(rar_data), 1700000000.0)

        assert result is None

    def test_rar_corrupt_returns_none(self):
        """Corrupt RAR data → no crash, returns None."""
        accessor = MagicMock()
        accessor.read.return_value = b"this is not a rar file"

        evaluator = RuleEvaluator(
            file_rules=[_archive_rule(".rar"), _password_rule()],
            content_rules=[],
            postmatch_rules=[],
        )

        scanner = FileScanner(make_cfg(), accessor, evaluator)

        with patch("snaffler.analysis.file_scanner.log_file_result"):
            result = scanner.scan_file("//srv/share/bad.rar", 100, 1700000000.0)

        assert result is None

    def test_rar_missing_rarfile_skips(self):
        """When rarfile is not installed, RAR peeking is skipped gracefully."""
        accessor = MagicMock()
        accessor.read.return_value = b"fakerardata"

        evaluator = RuleEvaluator(
            file_rules=[_archive_rule(".rar"), _password_rule()],
            content_rules=[],
            postmatch_rules=[],
        )

        scanner = FileScanner(make_cfg(), accessor, evaluator)

        with patch("snaffler.analysis.file_scanner.log_file_result"), \
             patch.dict("sys.modules", {"rarfile": None}):
            result = scanner.scan_file("//srv/share/stuff.rar", 500, 1700000000.0)

        assert result is None

    def test_rar_over_max_read_bytes_skipped(self):
        """RAR larger than max_read_bytes → no peeking, no read() call."""
        accessor = MagicMock()

        evaluator = RuleEvaluator(
            file_rules=[_archive_rule(".rar"), _password_rule()],
            content_rules=[],
            postmatch_rules=[],
        )

        scanner = FileScanner(make_cfg(max_read=100), accessor, evaluator)

        with patch("snaffler.analysis.file_scanner.log_file_result"):
            result = scanner.scan_file("//srv/share/big.rar", 999999, 1700000000.0)

        accessor.read.assert_not_called()
        assert result is None

    def test_rar_member_unc_path_format(self):
        """RAR member UNC path uses → separator."""
        with open(TEST_RAR_SENSITIVE, "rb") as f:
            rar_data = f.read()

        accessor = MagicMock()
        accessor.read.return_value = rar_data

        evaluator = RuleEvaluator(
            file_rules=[_archive_rule(".rar"), _ssh_key_rule()],
            content_rules=[],
            postmatch_rules=[],
        )

        scanner = FileScanner(make_cfg(), accessor, evaluator)

        with patch("snaffler.analysis.file_scanner.log_file_result"):
            result = scanner.scan_file("//srv/share/archive.rar", len(rar_data), 1700000000.0)

        assert result is not None
        assert result.file_path == "//srv/share/archive.rar\u2192id_rsa"
