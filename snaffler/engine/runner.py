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
from snaffler.utils.fatal import check_fatal_os_error
from snaffler.utils.path_utils import extract_unc_host, extract_unc_share_name
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
_SYNC_SCAN_MODE = "scan_mode"


class SnafflerRunner:
    def __init__(self, cfg: SnafflerConfiguration):
        self.cfg = cfg
        self.start_time = None

        # ---------- pre-computed exclusion set ----------
        self._exclusion_set = frozenset(e.upper() for e in (cfg.targets.exclusions or []))

        # ---------- progress ----------
        self.progress = ProgressState()
        self._stop_event = threading.Event()
        self._status_thread = None

        # ---------- state ----------
        self.state = ScanState(store=SQLiteStateStore(cfg.state.state_db))
        set_finding_store(self.state.store_finding)
        logger.info(f"State DB: {cfg.state.state_db}")

        # SharePipeline is only needed for SMB-based modes
        if not cfg.targets.ftp_targets and not cfg.targets.local_targets:
            self.share_pipeline = SharePipeline(
                cfg=cfg, state=self.state, progress=self.progress,
            )
        else:
            self.share_pipeline = None

        # Inject FTP transport when --ftp is used
        if cfg.targets.ftp_targets:
            from snaffler.accessors.ftp_file_accessor import FTPFileAccessor
            from snaffler.discovery.ftp_tree_walker import FTPTreeWalker

            # Cap FTP threads to avoid overwhelming servers with connections.
            # Each tree + file thread opens its own FTP connection (thread-local
            # caching), so 20+20 = 40 connections can easily exceed server limits
            # (vsftpd: 50, proftpd: 30, IIS FTP: 25).  Cap at 4+4 unless the
            # user explicitly set --max-threads above the default.
            _FTP_MAX_PER_BUCKET = 4
            if cfg.advanced.tree_threads > _FTP_MAX_PER_BUCKET:
                cfg.advanced.share_threads = 0
                cfg.advanced.tree_threads = _FTP_MAX_PER_BUCKET
                cfg.advanced.file_threads = _FTP_MAX_PER_BUCKET
                logger.info(
                    f"FTP mode: capped threads to {_FTP_MAX_PER_BUCKET} tree + "
                    f"{_FTP_MAX_PER_BUCKET} file to avoid connection floods"
                )

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

    def _run_file_pipeline(self, paths: list):
        """Rebalance threads and run the file scanning pipeline."""
        if paths:
            self._rebalance_file_threads()
            self.file_pipeline.run(paths)

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
            share_name = extract_unc_share_name(p)
            if share_name is None:
                filtered.append(p)
                continue
            if share_matches_filter(share_name, include, exclude):
                filtered.append(p)
            else:
                logger.debug(f"Skipping UNC path {p} (excluded by share filter)")
        return filtered

    # ---------- --max-hosts cap ----------

    def _cap_hosts(self, computers: List[str]) -> List[str]:
        """Limit computer list to --max-hosts if set."""
        limit = self.cfg.targets.max_hosts
        if isinstance(limit, int) and len(computers) > limit:
            logger.info(f"--max-hosts {limit}: capped from {len(computers)} to {limit} hosts")
            return computers[:limit]
        return computers

    # ---------- exclusion helpers ----------

    def _apply_exclusions(self, computers: List[str]) -> List[str]:
        """Remove computers matching the --exclusions list."""
        if not self._exclusion_set:
            return computers
        before = len(computers)
        filtered = [c for c in computers if c.upper() not in self._exclusion_set]
        diff = before - len(filtered)
        if diff:
            logger.info(f"Excluded {diff} computer(s) via --exclusions")
        return filtered

    def _filter_paths_by_exclusions(self, paths: List[str]) -> List[str]:
        """Remove UNC paths whose hostname matches the --exclusions list."""
        if not self._exclusion_set:
            return paths
        filtered = []
        for p in paths:
            host = extract_unc_host(p)
            if host is None:
                filtered.append(p)
                continue
            if host.upper() not in self._exclusion_set:
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
                    except Exception as e:
                        check_fatal_os_error(e)
                        ip = None
                        logger.info(f"DNS: probe failed for {hostname}")
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

    # ---------- rescan unreadable ----------

    def _rescan_unreadable(self):
        """Re-test previously unreadable shares with current creds."""
        unreadable = self.state.load_unreadable_shares()

        # Apply --share / --exclude-share filters
        unreadable = self._filter_paths_by_share(unreadable)

        # Apply --exclusions host filter
        unreadable = self._filter_paths_by_exclusions(unreadable)

        if not unreadable:
            logger.warning("No unreadable shares in state DB — nothing to rescan")
            return

        logger.info(f"Rescan: testing {len(unreadable)} previously unreadable shares")

        from snaffler.discovery.shares import ShareFinder
        finder = ShareFinder(self.cfg)

        newly_readable = []
        errors = 0

        def _test_one(unc_path: str):
            computer = extract_unc_host(unc_path)
            share_name = extract_unc_share_name(unc_path)
            if computer is None or share_name is None:
                return None
            readable = finder.is_share_readable(computer, share_name)
            return readable

        try:
            with ThreadPoolExecutor(
                max_workers=self.cfg.advanced.share_threads or 2,
            ) as pool:
                futures = {pool.submit(_test_one, p): p for p in unreadable}
                try:
                    for future in as_completed(futures):
                        unc_path = futures[future]
                        try:
                            result = future.result()
                        except Exception as e:
                            check_fatal_os_error(e)
                            logger.debug(f"Rescan error for {unc_path}: {e}")
                            errors += 1
                            continue
                        if result is None:
                            # Malformed path
                            continue
                        if result:
                            logger.info(f"[NEW] Readable: {unc_path}")
                            self.state.update_share_readable(unc_path)
                            newly_readable.append(unc_path)
                        else:
                            logger.debug(f"Still unreadable: {unc_path}")
                except KeyboardInterrupt:
                    pool.shutdown(wait=False, cancel_futures=True)
                    raise
        finally:
            # Close all cached connections from rescan's ShareFinder
            try:
                finder.close()
            except Exception:
                pass

        still_denied = len(unreadable) - len(newly_readable) - errors
        msg = f"Rescan: {len(newly_readable)} newly readable, {still_denied} still denied"
        if errors:
            msg += f", {errors} errors"
        logger.info(msg)

        if newly_readable:
            self.progress.shares_found = len(newly_readable)
            self._run_file_pipeline(newly_readable)

    def _detect_scan_mode(self) -> str:
        """Determine the current scan mode from config."""
        if self.cfg.targets.rescan_unreadable:
            return "rescan"
        if self.cfg.targets.ftp_targets:
            return "ftp"
        if self.cfg.targets.local_targets:
            return "local"
        if self.cfg.targets.unc_targets:
            return "unc"
        if self.cfg.targets.computer_targets:
            return "computer"
        if self.cfg.auth.domain:
            return "domain"
        return "unknown"

    def _check_scan_mode_changed(self):
        """Reset phase flags if scan mode changed since last run."""
        if not self.state:
            return
        mode = self._detect_scan_mode()
        prev = self.state.get_sync_value(_SYNC_SCAN_MODE)
        if prev and prev != mode:
            logger.warning(
                f"Scan mode changed ({prev} -> {mode}) — "
                f"resetting discovery phase flags (findings preserved)"
            )
            self.state.clear_phase_flags()
        self.state.set_sync_value(_SYNC_SCAN_MODE, mode)

    def _validate_credentials(self):
        """Preflight auth check — try a single login before starting the scan.

        Hard-fails with a clear error if credentials are invalid so we don't
        silently scan thousands of hosts with bad creds and come back empty.

        Skipped for --local-fs (no auth) and domain mode (LDAP connect
        validates creds as its first operation).
        """
        cfg = self.cfg

        # Local mode — no auth needed
        if cfg.targets.local_targets:
            return

        # Domain mode — LDAP connect is the first thing that happens,
        # it already raises on bad creds with a clear error.
        if (not cfg.targets.unc_targets
                and not cfg.targets.computer_targets
                and not cfg.targets.rescan_unreadable
                and not cfg.targets.ftp_targets
                and cfg.auth.domain):
            return

        # FTP mode — test FTP login
        if cfg.targets.ftp_targets:
            from snaffler.discovery.ftp_tree_walker import parse_ftp_url
            from snaffler.transport.ftp import FTPTransport

            target = cfg.targets.ftp_targets[0]
            parsed = parse_ftp_url(target)
            if not parsed:
                return
            host, port, _ = parsed
            transport = FTPTransport(cfg)
            try:
                ftp = transport.connect(host, port)
                try:
                    ftp.quit()
                except Exception:
                    pass
                logger.info(f"Auth OK: FTP login to {host}:{port} succeeded")
            except OSError as e:
                raise SystemExit(
                    f"FATAL: cannot reach FTP server {host}:{port} — {e}\n"
                    f"Check network connectivity and retry."
                ) from e
            except Exception as e:
                raise SystemExit(
                    f"FATAL: FTP authentication failed against {host}:{port} — {e}\n"
                    f"Fix credentials and retry."
                ) from e
            return

        # SMB modes — pick the first available target
        target = None
        if cfg.targets.rescan_unreadable and self.state:
            unreadable = self.state.load_unreadable_shares()
            if unreadable:
                target = extract_unc_host(unreadable[0])
        elif cfg.targets.unc_targets:
            for p in cfg.targets.unc_targets:
                host = extract_unc_host(p)
                if host is not None:
                    target = host
                    break
        elif cfg.targets.computer_targets:
            target = cfg.targets.computer_targets[0]

        if not target:
            return

        from snaffler.transport.smb import SMBTransport

        transport = SMBTransport(cfg)
        try:
            smb = transport.connect(target)
            try:
                smb.close()
            except Exception:
                pass
            logger.info(f"Auth OK: SMB login to {target} succeeded")
        except OSError as e:
            raise SystemExit(
                f"FATAL: cannot reach SMB target {target}:445 — {e}\n"
                f"Check network connectivity and retry."
            ) from e
        except Exception as e:
            raise SystemExit(
                f"FATAL: SMB authentication failed against {target} — {e}\n"
                f"Fix credentials and retry."
            ) from e

    def execute(self):
        self.start_time = datetime.now()
        logger.info(f"Starting Snaffler at {self.start_time:%Y-%m-%d %H:%M:%S}")

        self._start_status_thread()
        start_hotkey_listener(self._stop_event)
        self._check_scan_mode_changed()
        interrupted = False
        try:
            self._validate_credentials()

            if self.cfg.web.enabled:
                try:
                    from snaffler.web.server import start_web_server
                    start_web_server(self.progress, self.cfg.state.state_db, self.start_time, self.cfg.web.port)
                except ImportError as exc:
                    raise SystemExit(
                        f"FATAL: --web requires Flask: {exc}\n"
                        f"Install with: pip install snaffler-ng[web]"
                    ) from exc

            # ---------- rescan unreadable shares ----------
            if self.cfg.targets.rescan_unreadable:
                # Warn if other targeting modes were also specified
                other = []
                if self.cfg.targets.unc_targets:
                    other.append("--unc")
                if self.cfg.targets.computer_targets:
                    other.append("--computer")
                if self.cfg.auth.domain:
                    other.append("--domain")
                if other:
                    logger.warning(
                        f"--rescan-unreadable takes priority — ignoring {', '.join(other)}"
                    )
                self._rescan_unreadable()

            # ---------- FTP targets ----------
            elif self.cfg.targets.ftp_targets:
                if self.cfg.targets.shares_only:
                    logger.warning("--shares-only has no effect in --ftp mode")
                if self.cfg.targets.exclusions:
                    logger.warning("--exclusions has no effect in --ftp mode")
                paths = self.cfg.targets.ftp_targets
                self.progress.shares_found = len(paths)
                self._run_file_pipeline(paths)

            # ---------- Local filesystem paths ----------
            elif self.cfg.targets.local_targets:
                if self.cfg.targets.shares_only:
                    logger.warning("--shares-only has no effect in --local-fs mode")
                if self.cfg.targets.exclusions:
                    logger.warning("--exclusions has no effect in --local-fs mode")
                paths = self.cfg.targets.local_targets
                self.progress.shares_found = len(paths)
                self._run_file_pipeline(paths)

            # ---------- Direct UNC paths ----------
            elif self.cfg.targets.unc_targets:
                paths = self._filter_paths_by_share(self.cfg.targets.unc_targets)
                paths = self._filter_paths_by_exclusions(paths)
                # --max-hosts: keep only paths belonging to the first N hosts
                limit = self.cfg.targets.max_hosts
                if isinstance(limit, int):
                    seen_hosts = {}
                    capped = []
                    for p in paths:
                        host = extract_unc_host(p)
                        if host is None:
                            host = p
                        else:
                            host = host.lower()
                        if host not in seen_hosts:
                            if len(seen_hosts) >= limit:
                                continue
                            seen_hosts[host] = True
                        capped.append(p)
                    if len(paths) != len(capped):
                        logger.info(f"--max-hosts {limit}: kept {len(seen_hosts)} hosts, {len(capped)}/{len(paths)} paths")
                    paths = capped
                # Seed progress counters from UNC paths so summary stats
                # include computer/share counts even without SharePipeline.
                hosts = {
                    extract_unc_host(p)
                    for p in paths
                    if extract_unc_host(p) is not None
                }
                self.progress.computers_total = len(hosts)
                self.progress.computers_done = len(hosts)
                self.progress.shares_found = len(paths)
                self._run_file_pipeline(paths)

            # ---------- Explicit computer list ----------
            elif self.cfg.targets.computer_targets:
                computers = self._apply_exclusions(
                    self.cfg.targets.computer_targets
                )
                computers = self._cap_hosts(computers)
                resolved = self._resolve_computers(computers) if computers else []
                share_paths = self._resume_share_discovery(resolved) if resolved else []
                self._run_file_pipeline(share_paths)

            # ---------- Domain discovery ----------
            elif self.cfg.auth.domain:
                logger.info("Starting full domain discovery")
                domain_pipeline = DomainPipeline(self.cfg, exclusion_set=self._exclusion_set)
                computers = self._resume_computer_discovery(domain_pipeline)
                computers = self._cap_hosts(computers)
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

                if not self.cfg.targets.shares_only:
                    self._run_file_pipeline(all_paths)

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
                # Close all cached network connections (SMB/FTP sockets)
                try:
                    self.file_pipeline.close()
                except Exception:
                    pass
                if self.share_pipeline:
                    try:
                        self.share_pipeline.close()
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
