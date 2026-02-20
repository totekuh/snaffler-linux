"""
Thread-safe progress counters for periodic status reporting.
"""
import resource
import threading
from datetime import datetime


class ProgressState:
    """Thread-safe progress counters for periodic status reporting."""

    def __init__(self):
        self._lock = threading.Lock()
        self.start_time = datetime.now()

        # Share discovery stage
        self.computers_total = 0
        self.computers_done = 0
        self.shares_found = 0

        # File scanning stage
        self.files_total = 0
        self.files_scanned = 0
        self.files_matched = 0

    def format_status(self) -> str:
        with self._lock:
            elapsed = datetime.now() - self.start_time
            secs = int(elapsed.total_seconds())
            h, r = divmod(secs, 3600)
            m, s = divmod(r, 60)
            elapsed_str = f"{h}h{m:02d}m{s:02d}s" if h else f"{m}m{s:02d}s"

            rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024

            parts = [f"elapsed={elapsed_str}"]

            if self.computers_total:
                parts.append(f"computers={self.computers_done}/{self.computers_total}")
            if self.shares_found:
                parts.append(f"shares={self.shares_found}")
            if self.files_total:
                parts.append(f"files={self.files_scanned}/{self.files_total}")
            if self.files_matched:
                parts.append(f"matched={self.files_matched}")

            parts.append(f"mem={rss_mb}MB")

            return " | ".join(parts)
