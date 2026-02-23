"""
Main Snaffler controller - orchestrates all components
"""
import logging
import signal
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List

from snaffler.config.configuration import SnafflerConfiguration
from snaffler.engine.domain_pipeline import DomainPipeline
from snaffler.engine.file_pipeline import FilePipeline
from snaffler.engine.share_pipeline import SharePipeline
from snaffler.resume.scan_state import SQLiteStateStore, ScanState
from snaffler.utils.logger import print_completion_stats
from snaffler.utils.progress import ProgressState

logger = logging.getLogger('snaffler')


def _deduplicate_paths(share_paths: List[str], dfs_paths: List[str]) -> List[str]:
    """Merge share and DFS paths, deduplicating case-insensitively."""
    seen = {p.lower() for p in share_paths}
    merged = list(share_paths)
    for p in dfs_paths:
        if p.lower() not in seen:
            seen.add(p.lower())
            merged.append(p)
    return merged


_STATUS_INTERVAL = 30  # seconds
_PORT_CHECK_TIMEOUT = 3  # seconds — TCP probe during DNS pre-resolution
_DNS_THREADS = 100  # DNS+port probes are lightweight — no need to throttle

_PHASE_COMPUTERS = "computer_discovery_done"
_PHASE_DNS = "dns_resolution_done"
_PHASE_SHARES = "share_discovery_done"


class SnafflerRunner:
    def __init__(self, cfg: SnafflerConfiguration):
        self.cfg = cfg
        self.start_time = None

        # ---------- progress ----------
        self.progress = ProgressState()
        self._stop_event = threading.Event()
        self._status_thread = None

        # ---------- resume state ----------
        self.state = None
        if cfg.resume.enabled and cfg.resume.state_db:
            self.state = ScanState(store=SQLiteStateStore(cfg.resume.state_db))
            logger.info(f"Resume enabled (state={cfg.resume.state_db})")

        self.share_pipeline = SharePipeline(
            cfg=cfg, state=self.state, progress=self.progress,
        )
        self.file_pipeline = FilePipeline(cfg=cfg, state=self.state, progress=self.progress)

    def _start_status_thread(self):
        self._stop_event.clear()
        self._status_thread = threading.Thread(
            target=self._status_loop, daemon=True
        )
        self._status_thread.start()

    def _stop_status_thread(self):
        self._stop_event.set()
        if self._status_thread is not None:
            self._status_thread.join(timeout=2)

    def _status_loop(self):
        while not self._stop_event.wait(timeout=_STATUS_INTERVAL):
            self._sync_progress_from_state()
            logger.info(f"Progress: {self.progress.format_status()}")

    def _sync_progress_from_state(self):
        """Refresh progress counters from resume database."""
        if not self.state:
            return
        try:
            p = self.progress
            p.computers_done = max(
                p.computers_done, self.state.count_checked_computers()
            )
            p.shares_walked = max(
                p.shares_walked, self.state.count_checked_shares()
            )
            p.files_scanned = max(
                p.files_scanned, self.state.count_checked_files()
            )
            # Ensure totals are never less than done counts
            if p.files_scanned > p.files_total and p.files_total > 0:
                p.files_total = p.files_scanned
            if p.shares_walked > p.shares_total and p.shares_total > 0:
                p.shares_total = p.shares_walked
        except Exception:
            pass

    # ---------- resume helpers ----------

    def _resume_computer_discovery(self, domain_pipeline) -> List[str]:
        """Discover or load computers, persisting to state on first run."""
        if self.state and self.state.is_phase_done(_PHASE_COMPUTERS):
            computers = self.state.load_computers()
            logger.info(f"Resume: loaded {len(computers)} computers from state")
            return computers

        computers = domain_pipeline.run()

        if self.state:
            if computers:
                self.state.store_computers(computers)
            self.state.mark_phase_done(_PHASE_COMPUTERS)
            logger.info(f"Stored {len(computers)} computers in resume state")

        return computers

    def _resolve_computers(self, computers: List[str]) -> List[str]:
        """DNS pre-resolution: filter out hosts with no A record."""
        if not computers:
            return []

        # Resume: DNS phase already complete → load from state
        if self.state and self.state.is_phase_done(_PHASE_DNS):
            resolved = self.state.load_resolved_computers()
            logger.info(
                f"Resume: loaded {len(resolved)} DNS-resolved computers from state"
            )
            return resolved

        # Ensure computers are in state DB (needed for --computer mode
        # where _resume_computer_discovery is not called)
        if self.state:
            self.state.store_computers(computers)
            to_resolve = self.state.load_unresolved_computers()
            already_resolved = self.state.load_resolved_computers()
        else:
            to_resolve = list(computers)
            already_resolved = []

        self.progress.dns_total = len(computers)
        self.progress.dns_resolved = len(already_resolved)

        def resolve_one(hostname: str):
            try:
                result = socket.getaddrinfo(
                    hostname, 445, socket.AF_INET, socket.SOCK_STREAM,
                )
                ip = result[0][4][0]
            except (socket.gaierror, socket.herror, socket.timeout, OSError):
                logger.debug(f"DNS: no record for {hostname}, skipping")
                return None

            # Quick TCP probe — verify port 445 is actually reachable
            try:
                with socket.create_connection(
                    (ip, 445), timeout=_PORT_CHECK_TIMEOUT,
                ):
                    pass
            except (OSError, socket.timeout):
                logger.debug(
                    f"DNS: {hostname} ({ip}) port 445 unreachable, skipping"
                )
                return None

            return ip

        resolved = list(already_resolved)
        interrupted = False
        t0 = time.monotonic()

        prev_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.cfg.auth.smb_timeout)
        try:
            with ThreadPoolExecutor(max_workers=_DNS_THREADS) as pool:
                futures = {
                    pool.submit(resolve_one, h): h for h in to_resolve
                }
                try:
                    for future in as_completed(futures):
                        hostname = futures[future]
                        ip = future.result()
                        if ip is not None:
                            resolved.append(hostname)
                            self.progress.dns_resolved += 1
                            if self.state:
                                self.state.set_computer_ip(hostname, ip)
                        else:
                            self.progress.dns_filtered += 1
                except KeyboardInterrupt:
                    pool.shutdown(wait=False, cancel_futures=True)
                    interrupted = True
        finally:
            socket.setdefaulttimeout(prev_timeout)

        elapsed = time.monotonic() - t0
        filtered = len(computers) - len(resolved)
        logger.info(
            f"DNS pre-resolution: {len(resolved)}/{len(computers)} hosts resolved, "
            f"{filtered} filtered ({elapsed:.1f}s)"
        )

        # Only mark phase complete if all hosts were processed.
        # On interrupt, leave it unset so unresolved hosts get retried on resume.
        if self.state and not interrupted:
            self.state.mark_phase_done(_PHASE_DNS)

        if not resolved:
            logger.warning("DNS pre-resolution: no hosts resolved, share discovery will be skipped")

        if interrupted:
            raise KeyboardInterrupt

        return resolved

    def _resume_share_discovery(self, computers: List[str]) -> List[str]:
        """Discover or load shares, skipping already-checked computers."""
        if self.progress:
            self.progress.computers_total = len(computers)

        if self.state and self.state.is_phase_done(_PHASE_SHARES):
            shares = self.state.load_shares()
            if self.progress:
                self.progress.computers_done = len(computers)
                self.progress.shares_found = len(shares)
            logger.info(f"Resume: loaded {len(shares)} shares from state")
            if self.cfg.targets.shares_only:
                return []
            return shares

        # Filter out computers already enumerated in a previous run
        if self.state:
            remaining = [
                c for c in computers
                if not self.state.should_skip_computer(c)
            ]
            skipped = len(computers) - len(remaining)
            if skipped:
                logger.info(
                    f"Resume: skipped {skipped} already-enumerated computers"
                )
                if self.progress:
                    self.progress.computers_done = skipped
        else:
            remaining = computers

        new_shares = self.share_pipeline.run(remaining) if remaining else []

        if self.state:
            # Computers + shares already marked incrementally by SharePipeline.
            # Set phase flag and load ALL shares (old + new).
            self.state.mark_phase_done(_PHASE_SHARES)
            shares = self.state.load_shares()
            logger.info(
                f"Share discovery complete: {len(shares)} total shares in state"
            )
            if self.cfg.targets.shares_only:
                return []
            return shares

        return new_shares

    def execute(self):
        self.start_time = datetime.now()
        logger.info(f"Starting Snaffler at {self.start_time:%Y-%m-%d %H:%M:%S}")

        self._start_status_thread()
        interrupted = False
        try:
            # ---------- Direct UNC paths ----------
            if self.cfg.targets.unc_targets:
                paths = self.cfg.targets.unc_targets
                # Seed progress counters from UNC paths so summary stats
                # include computer/share counts even without SharePipeline.
                hosts = {p.split("/")[2] for p in paths if p.startswith("//")}
                self.progress.computers_total = len(hosts)
                self.progress.computers_done = len(hosts)
                self.progress.shares_found = len(paths)
                self.file_pipeline.run(paths)

            # ---------- Explicit computer list ----------
            elif self.cfg.targets.computer_targets:
                resolved = self._resolve_computers(
                    self.cfg.targets.computer_targets
                )
                share_paths = self._resume_share_discovery(resolved) if resolved else []
                if share_paths:
                    self.file_pipeline.run(share_paths)

            # ---------- Domain discovery ----------
            elif self.cfg.auth.domain:
                logger.info("Starting full domain discovery")
                domain_pipeline = DomainPipeline(self.cfg)
                computers = self._resume_computer_discovery(domain_pipeline)
                resolved = self._resolve_computers(computers) if computers else []
                share_paths = self._resume_share_discovery(resolved) if resolved else []

                # DFS discovery via LDAP (always re-runs — fast, deduplicated)
                dfs_paths = domain_pipeline.get_dfs_shares()
                if dfs_paths:
                    logger.info(f"Discovered {len(dfs_paths)} DFS target paths via LDAP")

                # Merge + dedup
                all_paths = _deduplicate_paths(share_paths, dfs_paths)
                dfs_only = len(all_paths) - len(share_paths)
                if dfs_only > 0:
                    logger.info(f"Added {dfs_only} new paths from DFS discovery")

                if all_paths and not self.cfg.targets.shares_only:
                    self.file_pipeline.run(all_paths)

            else:
                logger.error("No targets specified")
                return

        except KeyboardInterrupt:
            interrupted = True
            logger.warning("Interrupted by user — shutting down")
        finally:
            # Mask SIGINT during cleanup so mashing Ctrl+C can't skip DB close
            prev_handler = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                self._stop_status_thread()
                self._sync_progress_from_state()
                try:
                    print_completion_stats(start_time=self.start_time, progress=self.progress)
                except Exception:
                    pass
                if self.state:
                    try:
                        self.state.close()
                        logger.info("Resume state saved")
                    except Exception:
                        pass
            finally:
                signal.signal(signal.SIGINT, prev_handler)
            if interrupted:
                raise KeyboardInterrupt
