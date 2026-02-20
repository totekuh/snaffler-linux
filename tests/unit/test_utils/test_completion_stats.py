"""Test that completion summary includes progress counters."""
import logging
from datetime import datetime, timedelta

from snaffler.utils.logger import print_completion_stats
from snaffler.utils.progress import ProgressState


def test_completion_stats_with_progress(caplog):
    start = datetime.now() - timedelta(minutes=2, seconds=30)
    progress = ProgressState()
    progress.computers_total = 42
    progress.computers_done = 42
    progress.shares_found = 87
    progress.files_total = 1203
    progress.files_scanned = 1203
    progress.files_matched = 15
    progress.severity_black = 2
    progress.severity_red = 5
    progress.severity_yellow = 6
    progress.severity_green = 2

    with caplog.at_level(logging.INFO, logger="snaffler"):
        print_completion_stats(start, progress=progress)

    output = caplog.text
    assert "Computers: 42/42" in output
    assert "Shares: 87" in output
    assert "Files scanned: 1203/1203" in output
    assert "Matched: 15" in output
    assert "Duration:" in output
    assert "Findings: Black=2 Red=5 Yellow=6 Green=2" in output


def test_completion_stats_no_progress(caplog):
    start = datetime.now() - timedelta(seconds=5)

    with caplog.at_level(logging.INFO, logger="snaffler"):
        print_completion_stats(start, progress=None)

    output = caplog.text
    assert "Duration:" in output
    assert "Computers:" not in output
    assert "Shares:" not in output


def test_completion_stats_partial_counters(caplog):
    """UNC-only scan: no computers, only file counters."""
    start = datetime.now() - timedelta(seconds=10)
    progress = ProgressState()
    progress.files_total = 50
    progress.files_scanned = 50
    progress.files_matched = 3

    with caplog.at_level(logging.INFO, logger="snaffler"):
        print_completion_stats(start, progress=progress)

    output = caplog.text
    assert "Computers:" not in output
    assert "Shares:" not in output
    assert "Files scanned: 50/50" in output
    assert "Matched: 3" in output


def test_completion_stats_zero_matches(caplog):
    """All files scanned but nothing matched — no Matched or Findings line."""
    start = datetime.now() - timedelta(seconds=10)
    progress = ProgressState()
    progress.computers_total = 5
    progress.computers_done = 5
    progress.shares_found = 10
    progress.files_total = 200
    progress.files_scanned = 200

    with caplog.at_level(logging.INFO, logger="snaffler"):
        print_completion_stats(start, progress=progress)

    output = caplog.text
    assert "Computers: 5/5" in output
    assert "Shares: 10" in output
    assert "Files scanned: 200/200" in output
    assert "Matched:" not in output
    assert "Findings:" not in output


def test_completion_stats_partial_severity(caplog):
    """Only some severity levels have findings — zeroes are omitted."""
    start = datetime.now() - timedelta(seconds=10)
    progress = ProgressState()
    progress.files_total = 100
    progress.files_scanned = 100
    progress.files_matched = 7
    progress.severity_red = 3
    progress.severity_yellow = 4

    with caplog.at_level(logging.INFO, logger="snaffler"):
        print_completion_stats(start, progress=progress)

    output = caplog.text
    assert "Findings: Red=3 Yellow=4" in output
    assert "Black" not in output
    assert "Green" not in output
