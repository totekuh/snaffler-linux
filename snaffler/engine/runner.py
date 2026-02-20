"""
Main Snaffler controller - orchestrates all components
"""
import logging
import threading
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

        self.share_pipeline = SharePipeline(cfg=cfg, progress=self.progress)
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
            logger.info(f"Progress: {self.progress.format_status()}")

    def execute(self):
        self.start_time = datetime.now()
        logger.info(f"Starting Snaffler at {self.start_time:%Y-%m-%d %H:%M:%S}")

        self._start_status_thread()
        try:
            # ---------- Direct UNC paths ----------
            if self.cfg.targets.unc_targets:
                self.file_pipeline.run(self.cfg.targets.unc_targets)

            # ---------- Explicit computer list ----------
            elif self.cfg.targets.computer_targets:
                share_paths = self.share_pipeline.run(self.cfg.targets.computer_targets)
                if share_paths:
                    self.file_pipeline.run(share_paths)

            # ---------- Domain discovery ----------
            elif self.cfg.auth.domain:
                logger.info("Starting full domain discovery")
                domain_pipeline = DomainPipeline(self.cfg)
                computers = domain_pipeline.run()
                share_paths = self.share_pipeline.run(computers) if computers else []

                # DFS discovery via LDAP
                dfs_paths = domain_pipeline.get_dfs_shares()
                if dfs_paths:
                    logger.info(f"Discovered {len(dfs_paths)} DFS target paths via LDAP")

                # Merge + dedup
                all_paths = _deduplicate_paths(share_paths, dfs_paths)
                dfs_only = len(all_paths) - len(share_paths)
                if dfs_only > 0:
                    logger.info(f"Added {dfs_only} new paths from DFS discovery")

                if all_paths:
                    self.file_pipeline.run(all_paths)

            else:
                logger.error("No targets specified")
                return

            print_completion_stats(start_time=self.start_time, progress=self.progress)

        except KeyboardInterrupt:
            logger.warning("Interrupted by user")
            raise
        finally:
            self._stop_status_thread()
