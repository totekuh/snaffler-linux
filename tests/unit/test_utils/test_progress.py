import threading
import time
from datetime import datetime, timedelta
from unittest.mock import patch

from snaffler.utils.progress import ProgressState


def test_format_status_defaults():
    ps = ProgressState()
    status = ps.format_status()
    assert "Elapsed: " in status
    assert "Mem: " in status
    # No counters set — should not show computers/shares/files/matched/severity
    assert "Computers:" not in status
    assert "Shares:" not in status
    assert "Files:" not in status
    assert "Matched:" not in status
    assert "Black:" not in status
    assert "Red:" not in status


def test_format_status_dns_counters():
    ps = ProgressState()
    ps.dns_total = 100
    ps.dns_resolved = 80
    ps.dns_filtered = 20

    status = ps.format_status()
    assert "DNS: 80 up, 20 filtered, 0 to go" in status


def test_format_status_dns_eta():
    """ETA shown when enough samples and remaining > 0."""
    ps = ProgressState()
    ps.dns_total = 1000
    ps.dns_resolved = 400
    ps.dns_filtered = 100
    # Simulate 50s elapsed — 500 done in 50s = 10/s, 500 remaining = ~50s
    ps.dns_start = time.monotonic() - 50

    status = ps.format_status()
    assert "500 to go" in status
    assert "(~" in status  # ETA present


def test_format_status_dns_eta_too_early():
    """No ETA when fewer than 10 hosts checked."""
    ps = ProgressState()
    ps.dns_total = 1000
    ps.dns_resolved = 5
    ps.dns_filtered = 2
    ps.dns_start = time.monotonic() - 1

    status = ps.format_status()
    assert "993 to go" in status
    assert "~" not in status  # no ETA yet


def test_format_status_dns_eta_done():
    """No ETA when remaining is 0."""
    ps = ProgressState()
    ps.dns_total = 100
    ps.dns_resolved = 80
    ps.dns_filtered = 20
    ps.dns_start = time.monotonic() - 30

    status = ps.format_status()
    assert "0 to go" in status
    assert "~" not in status


def test_format_status_no_dns_when_zero():
    ps = ProgressState()
    status = ps.format_status()
    assert "DNS:" not in status


def test_format_status_with_counters():
    ps = ProgressState()
    ps.computers_total = 10
    ps.computers_done = 3
    ps.shares_found = 7
    ps.files_total = 100
    ps.files_scanned = 42
    ps.files_matched = 5

    status = ps.format_status()
    assert "Computers: 3/10" in status
    assert "Shares: 7" in status
    assert "Files: 42/100" in status
    assert "Matched: 5" in status


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
    assert "Black: 1 | Red: 3 | Yellow: 4 | Green: 2" in status


def test_format_status_severity_omits_zeroes():
    ps = ProgressState()
    ps.files_total = 50
    ps.files_scanned = 50
    ps.files_matched = 3
    ps.severity_red = 2
    ps.severity_green = 1

    status = ps.format_status()
    assert "Red: 2 | Green: 1" in status
    assert "Black" not in status
    assert "Yellow" not in status


def test_format_status_shares_walked():
    """When shares_total is set, show walked/total instead of just found count."""
    ps = ProgressState()
    ps.shares_total = 200
    ps.shares_walked = 50
    ps.shares_found = 200

    status = ps.format_status()
    assert "Shares: 50/200" in status


def test_format_status_shares_discovery_phase():
    """During share discovery (no shares_total), show just the found count."""
    ps = ProgressState()
    ps.shares_found = 42

    status = ps.format_status()
    assert "Shares: 42" in status
    assert "/" not in status.split("Shares: 42")[1].split("|")[0]


def test_format_status_elapsed_format():
    ps = ProgressState()
    ps.start_time = datetime.now() - timedelta(hours=1, minutes=23, seconds=45)

    status = ps.format_status()
    assert "Elapsed: 1h23m45s" in status


def test_format_status_elapsed_no_hours():
    ps = ProgressState()
    ps.start_time = datetime.now() - timedelta(minutes=5, seconds=12)

    status = ps.format_status()
    assert "Elapsed: 5m12s" in status


def test_format_status_memory():
    ps = ProgressState()
    status = ps.format_status()
    assert "Mem: " in status
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
