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

        # Per-severity finding counts
        self.severity_black = 0
        self.severity_red = 0
        self.severity_yellow = 0
        self.severity_green = 0

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
            sev = self._format_severity()
            if sev:
                parts.append(sev)

            parts.append(f"mem={rss_mb}MB")

            return " | ".join(parts)

    def _format_severity(self) -> str:
        """Format per-severity counts, omitting zeroes."""
        counts = []
        if self.severity_black:
            counts.append(f"Black={self.severity_black}")
        if self.severity_red:
            counts.append(f"Red={self.severity_red}")
        if self.severity_yellow:
            counts.append(f"Yellow={self.severity_yellow}")
        if self.severity_green:
            counts.append(f"Green={self.severity_green}")
        return " ".join(counts)
