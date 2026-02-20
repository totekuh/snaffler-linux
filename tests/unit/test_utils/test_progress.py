import threading
from datetime import datetime, timedelta
from unittest.mock import patch

from snaffler.utils.progress import ProgressState


def test_format_status_defaults():
    ps = ProgressState()
    status = ps.format_status()
    assert "elapsed=" in status
    assert "mem=" in status
    # No counters set — should not show computers/shares/files/matched/severity
    assert "computers=" not in status
    assert "shares=" not in status
    assert "files=" not in status
    assert "matched=" not in status
    assert "Black=" not in status
    assert "Red=" not in status


def test_format_status_with_counters():
    ps = ProgressState()
    ps.computers_total = 10
    ps.computers_done = 3
    ps.shares_found = 7
    ps.files_total = 100
    ps.files_scanned = 42
    ps.files_matched = 5

    status = ps.format_status()
    assert "computers=3/10" in status
    assert "shares=7" in status
    assert "files=42/100" in status
    assert "matched=5" in status


def test_format_status_severity_counts():
    ps = ProgressState()
    ps.files_total = 100
    ps.files_scanned = 100
    ps.files_matched = 10
    ps.severity_black = 1
    ps.severity_red = 3
    ps.severity_yellow = 4
    ps.severity_green = 2

    status = ps.format_status()
    assert "Black=1 Red=3 Yellow=4 Green=2" in status


def test_format_status_severity_omits_zeroes():
    ps = ProgressState()
    ps.files_total = 50
    ps.files_scanned = 50
    ps.files_matched = 3
    ps.severity_red = 2
    ps.severity_green = 1

    status = ps.format_status()
    assert "Red=2 Green=1" in status
    assert "Black" not in status
    assert "Yellow" not in status


def test_format_status_elapsed_format():
    ps = ProgressState()
    ps.start_time = datetime.now() - timedelta(hours=1, minutes=23, seconds=45)

    status = ps.format_status()
    assert "elapsed=1h23m45s" in status


def test_format_status_elapsed_no_hours():
    ps = ProgressState()
    ps.start_time = datetime.now() - timedelta(minutes=5, seconds=12)

    status = ps.format_status()
    assert "elapsed=5m12s" in status


def test_format_status_memory():
    ps = ProgressState()
    status = ps.format_status()
    # Should contain mem=<number>MB
    assert "mem=" in status
    assert "MB" in status


def test_concurrent_increments():
    """Concurrent increments should not crash."""
    ps = ProgressState()
    ps.computers_total = 100
    ps.files_total = 1000

    errors = []

    def increment_counters():
        try:
            for _ in range(100):
                ps.computers_done += 1
                ps.shares_found += 1
                ps.files_scanned += 1
                ps.files_matched += 1
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=increment_counters) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    # GIL makes single-attr increments atomic in CPython
    assert ps.computers_done == 1000
    assert ps.shares_found == 1000
    assert ps.files_scanned == 1000
    assert ps.files_matched == 1000


def test_format_status_during_increments():
    """format_status() should not crash while counters are being modified."""
    ps = ProgressState()
    ps.computers_total = 50
    ps.files_total = 500

    errors = []
    stop = threading.Event()

    def increment_loop():
        while not stop.is_set():
            ps.computers_done += 1
            ps.files_scanned += 1

    def format_loop():
        try:
            for _ in range(50):
                ps.format_status()
        except Exception as e:
            errors.append(e)

    t1 = threading.Thread(target=increment_loop)
    t2 = threading.Thread(target=format_loop)
    t1.start()
    t2.start()
    t2.join()
    stop.set()
    t1.join()

    assert not errors
