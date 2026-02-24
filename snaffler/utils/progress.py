"""
Thread-safe progress counters for periodic status reporting.
"""
import ctypes
import os
import threading
import time
from datetime import datetime


def _get_rss_mb() -> int:
    """Return current RSS in MB, cross-platform."""
    if os.name == "nt":
        # Windows: kernel32 GetProcessMemoryInfo via ctypes (no extra deps)
        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        pmc = PROCESS_MEMORY_COUNTERS()
        pmc.cb = ctypes.sizeof(pmc)
        handle = ctypes.windll.kernel32.GetCurrentProcess()
        if ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb):
            return pmc.WorkingSetSize // (1024 * 1024)
        return 0
    else:
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024


class ProgressState:
    """Thread-safe progress counters for periodic status reporting."""

    def __init__(self):
        self._lock = threading.Lock()
        self.start_time = datetime.now()

        # DNS pre-resolution stage
        self.dns_total = 0
        self.dns_resolved = 0
        self.dns_filtered = 0
        self.dns_start = None  # set when DNS phase begins

        # Share discovery stage
        self.computers_total = 0
        self.computers_done = 0
        self.shares_found = 0

        # Tree walking / file scanning stage
        self.shares_total = 0
        self.shares_walked = 0
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

            rss_mb = _get_rss_mb()

            parts = [f"Elapsed: {elapsed_str}"]

            if self.dns_total:
                remaining = self.dns_total - self.dns_resolved - self.dns_filtered
                dns_str = (
                    f"DNS: {self.dns_resolved} up, "
                    f"{self.dns_filtered} filtered, "
                    f"{remaining} to go"
                )
                eta = self._dns_eta(remaining)
                if eta:
                    dns_str += f" (~{eta})"
                parts.append(dns_str)
            if self.computers_total:
                parts.append(f"Computers: {self.computers_done}/{self.computers_total}")
            if self.shares_total:
                parts.append(f"Shares: {self.shares_walked}/{self.shares_total}")
            elif self.shares_found:
                parts.append(f"Shares: {self.shares_found}")
            if self.files_total:
                parts.append(f"Files: {self.files_scanned}/{self.files_total}")
            if self.files_matched:
                parts.append(f"Matched: {self.files_matched}")
            sev = self._format_severity()
            if sev:
                parts.append(sev)

            parts.append(f"Mem: {rss_mb}MB")

            return " | ".join(parts)

    def _dns_eta(self, remaining: int) -> str:
        """Estimate time remaining for DNS phase, or empty string if too early."""
        if not self.dns_start or remaining <= 0:
            return ""
        done = self.dns_resolved + self.dns_filtered
        if done < 10:
            return ""  # too early for a meaningful estimate
        elapsed = time.monotonic() - self.dns_start
        if elapsed < 1:
            return ""
        rate = done / elapsed
        eta_secs = int(remaining / rate)
        if eta_secs < 60:
            return f"{eta_secs}s"
        m, s = divmod(eta_secs, 60)
        if m < 60:
            return f"{m}m{s:02d}s"
        h, m = divmod(m, 60)
        return f"{h}h{m:02d}m"

    def _format_severity(self) -> str:
        """Format per-severity counts, omitting zeroes."""
        counts = []
        if self.severity_black:
            counts.append(f"Black: {self.severity_black}")
        if self.severity_red:
            counts.append(f"Red: {self.severity_red}")
        if self.severity_yellow:
            counts.append(f"Yellow: {self.severity_yellow}")
        if self.severity_green:
            counts.append(f"Green: {self.severity_green}")
        return " | ".join(counts)
