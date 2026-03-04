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
        self.shares_start = None  # set when share discovery begins
        self._shares_done_baseline: int = 0  # computers_done at start of resumed share discovery

        # Tree walking / file scanning stage
        self.shares_total = 0
        self.shares_walked = 0
        self.files_total = 0
        self.files_scanned = 0
        self.files_in_progress = 0
        self.files_matched = 0

        # Per-severity finding counts
        self.severity_black = 0
        self.severity_red = 0
        self.severity_yellow = 0
        self.severity_green = 0

        # Set by runner after file_pipeline.run() returns — authoritative
        # "scan finished" signal.  Prevents _detect_phase() from falsely
        # reporting "complete" when the scanner temporarily catches up to
        # files_total while the tree walker is still discovering files.
        self.scan_complete = False

    def snapshot(self) -> dict:
        """Return a point-in-time copy of all counters.

        Used by the web dashboard API to read a consistent set of values
        instead of individual attribute reads spread across serialization.
        """
        with self._lock:
            return {
                "dns_total": self.dns_total,
                "dns_resolved": self.dns_resolved,
                "dns_filtered": self.dns_filtered,
                "computers_total": self.computers_total,
                "computers_done": self.computers_done,
                "shares_found": self.shares_found,
                "shares_total": self.shares_total,
                "shares_walked": self.shares_walked,
                "files_total": self.files_total,
                "files_scanned": self.files_scanned,
                "files_in_progress": self.files_in_progress,
                "files_matched": self.files_matched,
                "severity_black": self.severity_black,
                "severity_red": self.severity_red,
                "severity_yellow": self.severity_yellow,
                "severity_green": self.severity_green,
                "scan_complete": self.scan_complete,
            }

    def format_status(self) -> str:
        with self._lock:
            elapsed = datetime.now() - self.start_time
            secs = int(elapsed.total_seconds())
            h, r = divmod(secs, 3600)
            m, s = divmod(r, 60)
            elapsed_str = f"{h}h{m:02d}m{s:02d}s" if h else f"{m}m{s:02d}s"

            rss_mb = _get_rss_mb()

            parts = [f"Elapsed: {elapsed_str}"]

            # Determine active phases (walk + scan can run concurrently)
            walking_active = self.shares_total > 0 and self.shares_walked < self.shares_total
            scanning_active = self.files_total > 0
            scan_phase = scanning_active and not walking_active
            walk_phase = walking_active
            share_phase = self.computers_total > 0 and not walk_phase and not scan_phase
            dns_phase = self.dns_total > 0 and not share_phase and not walk_phase and not scan_phase

            # --- DNS ---
            if dns_phase:
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
            elif self.dns_total and not walk_phase and not scan_phase:
                parts.append(f"DNS: {self.dns_resolved} hosts")

            # --- Shares ---
            if share_phase:
                remaining = self.computers_total - self.computers_done
                shares_str = (
                    f"Shares: {self.shares_found} found on "
                    f"{self.computers_done}/{self.computers_total} hosts"
                )
                if remaining > 0:
                    shares_str += f", {remaining} to go"
                    eta = self._shares_eta(remaining)
                    if eta:
                        shares_str += f" (~{eta})"
                parts.append(shares_str)
            elif self.shares_found:
                parts.append(f"Shares: {self.shares_found}")

            # --- Tree walking ---
            if walk_phase:
                remaining = self.shares_total - self.shares_walked
                walk_str = f"Walking: {self.shares_walked}/{self.shares_total}"
                if remaining > 0:
                    walk_str += f", {remaining} to go"
                parts.append(walk_str)

                # Concurrent scanning progress while walking
                if scanning_active:
                    fstr = f"Files: {self.files_scanned} scanned"
                    if self.files_in_progress:
                        fstr += f", {self.files_in_progress} scanning"
                    parts.append(fstr)

            # --- File scanning (walk complete) ---
            if scan_phase:
                remaining = self.files_total - self.files_scanned
                files_str = f"Files: {self.files_scanned}/{self.files_total}"
                if self.files_in_progress:
                    files_str += f", {self.files_in_progress} scanning"
                if remaining > 0:
                    files_str += f", {remaining} to go"
                parts.append(files_str)

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

    def _shares_eta(self, remaining: int) -> str:
        """Estimate time remaining for share discovery, or empty string if too early."""
        if not self.shares_start or remaining <= 0:
            return ""
        done = self.computers_done - self._shares_done_baseline
        if done < 5:
            return ""  # too early for a meaningful estimate
        elapsed = time.monotonic() - self.shares_start
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
