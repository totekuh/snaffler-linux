"""Regression tests for snaffler.utils.logger."""

import logging
from unittest.mock import MagicMock, patch

from snaffler.utils import logger as logger_mod
from snaffler.utils.logger import log_file_result


# ---- BUG-NEW-1: _finding_store only called when suppress_log=False ----


class TestFindingStoreSuppressLog:
    """BUG-NEW-1: _finding_store must NOT be invoked when suppress_log=True."""

    def _make_logger(self):
        lg = logging.getLogger("snaffler.test.finding_store")
        lg.handlers.clear()
        lg.setLevel(logging.DEBUG)
        lg.addHandler(logging.NullHandler())
        return lg

    def test_finding_store_not_called_when_suppress_log_true(self):
        store = MagicMock()
        old = logger_mod._finding_store
        try:
            logger_mod._finding_store = store
            log_file_result(
                logger=self._make_logger(),
                file_path="//srv/share/secret.txt",
                triage="Red",
                rule_name="TestRule",
                match="password",
                context="password=hunter2",
                suppress_log=True,
            )
            store.assert_not_called()
        finally:
            logger_mod._finding_store = old

    def test_finding_store_called_when_suppress_log_false(self):
        store = MagicMock()
        old = logger_mod._finding_store
        try:
            logger_mod._finding_store = store
            log_file_result(
                logger=self._make_logger(),
                file_path="//srv/share/secret.txt",
                triage="Red",
                rule_name="TestRule",
                match="password",
                context="password=hunter2",
                suppress_log=False,
            )
            store.assert_called_once()
            kwargs = store.call_args[1]
            assert kwargs["file_path"] == "//srv/share/secret.txt"
            assert kwargs["triage"] == "Red"
            assert kwargs["rule_name"] == "TestRule"
        finally:
            logger_mod._finding_store = old


# ---- BUG-NEW-3: Ellipsis only appended when context > 200 chars ----


class TestContextEllipsis:
    """BUG-NEW-3: '...' must only appear when context exceeds 200 characters."""

    def _make_logger(self):
        lg = logging.getLogger("snaffler.test.ellipsis")
        lg.handlers.clear()
        lg.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)
        lg.addHandler(handler)
        return lg

    def test_no_ellipsis_for_exactly_200_chars(self, capsys):
        context_200 = "A" * 200
        lg = self._make_logger()

        with patch.object(logger_mod, "NO_COLOR", True):
            log_file_result(
                logger=lg,
                file_path="//srv/share/f.txt",
                triage="Green",
                rule_name="Rule",
                context=context_200,
            )

        captured = capsys.readouterr()
        # Context exactly 200 chars: no ellipsis
        assert "..." not in captured.err and "..." not in captured.out
        # But the full context IS present
        assert context_200 in (captured.out + captured.err)

    def test_ellipsis_for_201_chars(self, capsys):
        context_201 = "B" * 201
        lg = self._make_logger()

        with patch.object(logger_mod, "NO_COLOR", True):
            log_file_result(
                logger=lg,
                file_path="//srv/share/f.txt",
                triage="Green",
                rule_name="Rule",
                context=context_201,
            )

        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert "..." in output
        # Truncated to 200 chars + "..."
        assert "B" * 200 + "..." in output


# ---- BUG-F2: TSV file handler leak ----


class TestTSVFileHandlerLeak:
    """BUG-F2: setup_logging with log_type='tsv' must create exactly one FileHandler."""

    def test_tsv_creates_exactly_one_file_handler(self, tmp_path):
        from snaffler.utils.logger import setup_logging

        tsv_file = str(tmp_path / "test.tsv")
        lg = setup_logging(
            log_to_file=True,
            log_file_path=tsv_file,
            log_type="tsv",
            log_to_console=False,
        )
        try:
            file_handlers = [
                h for h in lg.handlers if isinstance(h, logging.FileHandler)
            ]
            assert len(file_handlers) == 1, (
                f"Expected exactly 1 FileHandler, got {len(file_handlers)}"
            )
        finally:
            for h in lg.handlers[:]:
                h.close()
            lg.handlers.clear()
