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
from snaffler.discovery.shares import share_matches_filter
from snaffler.engine.domain_pipeline import DomainPipeline
from snaffler.engine.file_pipeline import FilePipeline
from snaffler.engine.share_pipeline import SharePipeline
from snaffler.resume.scan_state import SQLiteStateStore, ScanState
from snaffler.utils.hotkeys import start_hotkey_listener, stop_hotkey_listener
from snaffler.utils.logger import print_completion_stats, set_finding_store
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

        # ---------- state ----------
        self.state = ScanState(store=SQLiteStateStore(cfg.state.state_db))
        set_finding_store(self.state.store_finding)
        logger.info(f"State DB: {cfg.state.state_db}")

        self.share_pipeline = SharePipeline(
            cfg=cfg, state=self.state, progress=self.progress,
        )

        # Inject FTP transport when --ftp is used
        if cfg.targets.ftp_targets:
            from snaffler.accessors.ftp_file_accessor import FTPFileAccessor
            from snaffler.discovery.ftp_tree_walker import FTPTreeWalker

            tree_walker = FTPTreeWalker(cfg)
            file_accessor = FTPFileAccessor(cfg)
            self.file_pipeline = FilePipeline(
                cfg=cfg, state=self.state, progress=self.progress,
                tree_walker=tree_walker, file_accessor=file_accessor,
            )
        # Inject local transport when --local-fs is used
        elif cfg.targets.local_targets:
            from snaffler.accessors.local_file_accessor import LocalFileAccessor
            from snaffler.discovery.local_tree_walker import LocalTreeWalker

            tree_walker = LocalTreeWalker(
                dir_rules=cfg.rules.directory,
                exclude_unc=cfg.targets.exclude_unc,
            )
            file_accessor = LocalFileAccessor()
            self.file_pipeline = FilePipeline(
                cfg=cfg, state=self.state, progress=self.progress,
                tree_walker=tree_walker, file_accessor=file_accessor,
            )
        else:
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
            try:
                self._sync_progress_from_state()
                logger.info(f"Progress: {self.progress.format_status()}")
            except Exception:
                pass

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
            # shares_found is set by _resume_share_discovery (filtered);
            # don't overwrite with unfiltered DB count.
            # Ensure totals are never less than done counts
            p.files_total = max(p.files_total, p.files_scanned)
            p.shares_total = max(p.shares_total, p.shares_walked)

            # Restore finding counts from DB (critical for resume)
            by_triage = self.state.count_findings_by_triage()
            total = 0
            for label, count in by_triage.items():
                total += count
                low = label.lower()
                if low == "black":
                    p.severity_black = max(p.severity_black, count)
                elif low == "red":
                    p.severity_red = max(p.severity_red, count)
                elif low == "yellow":
                    p.severity_yellow = max(p.severity_yellow, count)
                elif low == "green":
                    p.severity_green = max(p.severity_green, count)
            p.files_matched = max(p.files_matched, total)
        except Exception as e:
            logger.debug(f"Failed to sync progress from state DB: {e}")

    # ---------- thread rebalancing ----------

    def _rebalance_file_threads(self):
        """Give the share thread budget to file scanning (shares are done)."""
        bonus = self.cfg.advanced.share_threads
        half = bonus // 2
        self.file_pipeline.tree_threads += half
        self.file_pipeline.file_threads += bonus - half
        logger.info(
            f"Thread rebalance: +{bonus} share threads → "
            f"tree={self.file_pipeline.tree_threads}, "
            f"file={self.file_pipeline.file_threads}"
        )

    # ---------- share filtering ----------

    def _filter_paths_by_share(self, paths: List[str]) -> List[str]:
        """Apply --share / --exclude-share filters to a list of UNC paths.

        Extracts the share name (second component of //server/share/...)
        and passes it through the same filter used by ShareFinder.
        """
        include = self.cfg.targets.share_filter
        exclude = self.cfg.targets.exclude_share
        if not include and not exclude:
            return paths

        filtered = []
        for p in paths:
            parts = p.strip("/").split("/")
            if len(parts) < 2:
                filtered.append(p)
                continue
            share_name = parts[1]
            if share_matches_filter(share_name, include, exclude):
                filtered.append(p)
            else:
                logger.debug(f"Skipping UNC path {p} (excluded by share filter)")
        return filtered

    # ---------- exclusion helpers ----------

    def _apply_exclusions(self, computers: List[str]) -> List[str]:
        """Remove computers matching the --exclusions list."""
        exclusions = self.cfg.targets.exclusions
        if not exclusions:
            return computers
        exc_set = {e.upper() for e in exclusions}
        before = len(computers)
        filtered = [c for c in computers if c.upper() not in exc_set]
        diff = before - len(filtered)
        if diff:
            logger.info(f"Excluded {diff} computer(s) via --exclusions")
        return filtered

    def _filter_paths_by_exclusions(self, paths: List[str]) -> List[str]:
        """Remove UNC paths whose hostname matches the --exclusions list."""
        exclusions = self.cfg.targets.exclusions
        if not exclusions:
            return paths
        exc_set = {e.upper() for e in exclusions}
        filtered = []
        for p in paths:
            parts = p.strip("/").split("/")
            if len(parts) < 2:
                filtered.append(p)
                continue
            if parts[0].upper() not in exc_set:
                filtered.append(p)
        diff = len(paths) - len(filtered)
        if diff:
            logger.info(f"Excluded {diff} UNC path(s) via --exclusions")
        return filtered

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
            # Only mark phase complete if LDAP finished without error.
            # On partial failure, leave unset so resume re-queries.
            if domain_pipeline.ad.discovery_complete:
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
            self.progress.dns_total = len(computers)
            self.progress.dns_resolved = len(resolved)
            self.progress.dns_filtered = len(computers) - len(resolved)
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
        self.progress.dns_start = time.monotonic()

        dns_timeout = self.cfg.auth.smb_timeout

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

        with ThreadPoolExecutor(
            max_workers=self.cfg.advanced.dns_threads,
        ) as pool:
            futures = {
                pool.submit(resolve_one, h): h for h in to_resolve
            }
            try:
                for future in as_completed(futures):
                    hostname = futures[future]
                    try:
                        ip = future.result()
                    except Exception:
                        ip = None
                        logger.debug(f"DNS: probe failed for {hostname}")
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
            shares = self._filter_paths_by_share(shares)
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

        # Pre-seed shares_found from state so the display is correct during
        # the entire resumed share phase (not just after run() completes).
        if self.state:
            existing_shares = self.state.load_shares()
            self.progress.shares_found = len(existing_shares)

        # Snapshot how many computers were already done before this run's
        # share discovery starts, so _shares_eta() only measures the current
        # session's throughput (avoids inflated ETA on resume).
        self.progress._shares_done_baseline = self.progress.computers_done

        new_shares = self.share_pipeline.run(remaining) if remaining else []

        if self.state:
            # Ensure pipeline return is persisted (idempotent — SharePipeline
            # stores incrementally, this catches any that slipped through).
            if new_shares:
                self.state.store_shares(new_shares)
            # Set phase flag and load ALL shares (old + new).
            self.state.mark_phase_done(_PHASE_SHARES)
            shares = self.state.load_shares()
            shares = self._filter_paths_by_share(shares)
            if self.progress:
                self.progress.shares_found = len(shares)
            logger.info(
                f"Share discovery complete: {len(shares)} total shares in state"
            )
            if self.cfg.targets.shares_only:
                return []
            return shares

        return self._filter_paths_by_share(new_shares)

    def execute(self):
        self.start_time = datetime.now()
        logger.info(f"Starting Snaffler at {self.start_time:%Y-%m-%d %H:%M:%S}")

        self._start_status_thread()
        start_hotkey_listener(self._stop_event)
        interrupted = False
        try:
            if self.cfg.web.enabled:
                try:
                    from snaffler.web.server import start_web_server
                    start_web_server(self.progress, self.cfg.state.state_db, self.start_time, self.cfg.web.port)
                except ImportError as exc:
                    logger.warning(f"Web dashboard unavailable: {exc}")

            # ---------- FTP targets ----------
            if self.cfg.targets.ftp_targets:
                if self.cfg.targets.shares_only:
                    logger.warning("--shares-only has no effect in --ftp mode")
                if self.cfg.targets.exclusions:
                    logger.warning("--exclusions has no effect in --ftp mode")
                paths = self.cfg.targets.ftp_targets
                self.progress.shares_found = len(paths)
                self._rebalance_file_threads()
                self.file_pipeline.run(paths)

            # ---------- Local filesystem paths ----------
            elif self.cfg.targets.local_targets:
                if self.cfg.targets.shares_only:
                    logger.warning("--shares-only has no effect in --local-fs mode")
                if self.cfg.targets.exclusions:
                    logger.warning("--exclusions has no effect in --local-fs mode")
                paths = self.cfg.targets.local_targets
                self.progress.shares_found = len(paths)
                self._rebalance_file_threads()
                self.file_pipeline.run(paths)

            # ---------- Direct UNC paths ----------
            elif self.cfg.targets.unc_targets:
                paths = self._filter_paths_by_share(self.cfg.targets.unc_targets)
                paths = self._filter_paths_by_exclusions(paths)
                # Seed progress counters from UNC paths so summary stats
                # include computer/share counts even without SharePipeline.
                hosts = {
                    p.strip("/").split("/")[0]
                    for p in paths
                    if p.startswith("//")
                }
                self.progress.computers_total = len(hosts)
                self.progress.computers_done = len(hosts)
                self.progress.shares_found = len(paths)
                if paths:
                    self._rebalance_file_threads()
                    self.file_pipeline.run(paths)

            # ---------- Explicit computer list ----------
            elif self.cfg.targets.computer_targets:
                computers = self._apply_exclusions(
                    self.cfg.targets.computer_targets
                )
                resolved = self._resolve_computers(computers) if computers else []
                share_paths = self._resume_share_discovery(resolved) if resolved else []
                if share_paths:
                    self._rebalance_file_threads()
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
                    dfs_paths = self._filter_paths_by_share(dfs_paths)

                # Merge + dedup
                all_paths = _deduplicate_paths(share_paths, dfs_paths)
                dfs_only = len(all_paths) - len(share_paths)
                if dfs_only > 0:
                    logger.info(f"Added {dfs_only} new paths from DFS discovery")

                # Reflect DFS-merged total in the status display
                self.progress.shares_found = len(all_paths)

                if all_paths and not self.cfg.targets.shares_only:
                    self._rebalance_file_threads()
                    self.file_pipeline.run(all_paths)

            else:
                logger.error("No targets specified")
                return

            self.progress.scan_complete = True

        except KeyboardInterrupt:
            interrupted = True
            logger.warning("Interrupted by user — shutting down")
        finally:
            # Mask SIGINT during cleanup so mashing Ctrl+C can't skip DB close.
            # signal.signal() raises ValueError from non-main threads.
            is_main = threading.current_thread() is threading.main_thread()
            prev_handler = None
            if is_main:
                prev_handler = signal.getsignal(signal.SIGINT)
                signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                if self.cfg.web.enabled:
                    try:
                        from snaffler.web.server import stop_web_server
                        stop_web_server()
                    except Exception:
                        pass
                stop_hotkey_listener()
                self._stop_status_thread()
                self._sync_progress_from_state()
                try:
                    print_completion_stats(start_time=self.start_time, progress=self.progress)
                except Exception:
                    pass
                if self.state:
                    try:
                        set_finding_store(None)
                        self.state.close()
                        logger.info("State saved")
                    except Exception:
                        pass
            finally:
                if is_main and prev_handler is not None:
                    signal.signal(signal.SIGINT, prev_handler)
            if interrupted:
                raise KeyboardInterrupt
