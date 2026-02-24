"""Tests for snaffler.utils.hotkeys — runtime log level switching."""
import logging
from unittest.mock import patch

import pytest

from snaffler.utils.hotkeys import (
    _change_log_level,
    _get_console_handler,
    start_hotkey_listener,
    stop_hotkey_listener,
)


@pytest.fixture()
def snaffler_logger():
    """Set up a snaffler logger with a console StreamHandler at INFO."""
    logger = logging.getLogger("snaffler")
    logger.setLevel(logging.DEBUG)
    old_handlers = list(logger.handlers)
    logger.handlers.clear()

    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    logger.addHandler(handler)

    yield logger

    logger.handlers.clear()
    for h in old_handlers:
        logger.addHandler(h)


class TestGetConsoleHandler:
    def test_finds_stream_handler(self, snaffler_logger):
        h = _get_console_handler()
        assert h is not None
        assert isinstance(h, logging.StreamHandler)

    def test_ignores_file_handler(self, snaffler_logger):
        snaffler_logger.handlers.clear()
        fh = logging.FileHandler("/dev/null")
        snaffler_logger.addHandler(fh)
        assert _get_console_handler() is None
        fh.close()

    def test_returns_none_when_no_handlers(self, snaffler_logger):
        snaffler_logger.handlers.clear()
        assert _get_console_handler() is None


class TestChangeLogLevel:
    def test_switch_to_debug(self, snaffler_logger):
        handler = _get_console_handler()
        assert handler.level == logging.INFO
        _change_log_level("d")
        assert handler.level == logging.DEBUG

    def test_switch_to_info(self, snaffler_logger):
        handler = _get_console_handler()
        handler.setLevel(logging.DEBUG)
        _change_log_level("i")
        assert handler.level == logging.INFO

    def test_unrecognized_key_ignored(self, snaffler_logger):
        handler = _get_console_handler()
        handler.setLevel(logging.INFO)
        _change_log_level("x")
        assert handler.level == logging.INFO

    def test_no_handler_no_crash(self, snaffler_logger):
        snaffler_logger.handlers.clear()
        _change_log_level("d")  # should not raise


class TestStartStop:
    def test_nontty_is_noop(self, snaffler_logger):
        """start/stop with non-TTY stdin must not crash."""
        import threading

        stop = threading.Event()
        with patch("sys.stdin") as mock_stdin:
            mock_stdin.isatty.return_value = False
            start_hotkey_listener(stop)
        stop_hotkey_listener()

    def test_stop_without_start(self):
        """stop_hotkey_listener is safe to call even if start was never called."""
        stop_hotkey_listener()  # should not raise
