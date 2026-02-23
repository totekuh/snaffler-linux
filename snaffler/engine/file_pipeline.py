import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from snaffler.accessors.smb_file_accessor import SMBFileAccessor
from snaffler.analysis.file_scanner import FileScanner
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.discovery.tree import TreeWalker
from snaffler.resume.scan_state import ScanState
from snaffler.utils.progress import ProgressState

logger = logging.getLogger("snaffler")


class FilePipeline:
    def __init__(
            self,
            cfg: SnafflerConfiguration,
            state: ScanState | None = None,
            progress: ProgressState | None = None,
    ):
        self.cfg = cfg
        self.state = state
        self.progress = progress

        self.tree_threads = cfg.advanced.tree_threads
        self.file_threads = cfg.advanced.file_threads

        self.tree_walker = TreeWalker(cfg,
                                      state=state)

        file_accessor = SMBFileAccessor(cfg)
        rule_evaluator = RuleEvaluator(
            file_rules=cfg.rules.file,
            content_rules=cfg.rules.content,
            postmatch_rules=cfg.rules.postmatch,
        )
        self.file_scanner = FileScanner(
            cfg=cfg,
            file_accessor=file_accessor,
            rule_evaluator=rule_evaluator,
        )

    def run(self, paths: List[str]) -> int:
        logger.info(f"Starting file discovery on {len(paths)} paths")

        # ---------- Resume: skip fully-processed shares ----------
        skipped_shares = 0
        if self.state:
            before = len(paths)
            paths = [p for p in paths if not self.state.should_skip_share(p)]
            skipped_shares = before - len(paths)
            if skipped_shares:
                logger.info(f"Resume: skipped {skipped_shares} fully-processed shares")

        if self.progress:
            self.progress.shares_total = len(paths) + skipped_shares
            self.progress.shares_walked = skipped_shares

        all_files: list[tuple[str, object]] = []
        walked_shares: list[str] = []

        # ---------- Tree walking ----------
        with ThreadPoolExecutor(max_workers=self.tree_threads) as executor:
            future_to_path = {
                executor.submit(self.tree_walker.walk_tree, path): path
                for path in paths
            }
            try:
                for future in as_completed(future_to_path):
                    path = future_to_path[future]
                    try:
                        files = future.result()
                        all_files.extend(files)
                    except Exception as e:
                        logger.debug(f"Error walking {path}: {e}")
                    else:
                        # Track success — mark done only after file scanning completes
                        walked_shares.append(path)
                    finally:
                        if self.progress:
                            self.progress.shares_walked += 1
            except KeyboardInterrupt:
                executor.shutdown(wait=False, cancel_futures=True)
                raise

        if not all_files:
            self._mark_shares_done(walked_shares)
            logger.warning("No files found")
            return 0

        # ---------- Resume filtering (files only) ----------
        skipped_files = 0
        if self.state:
            before = len(all_files)
            all_files = [
                (file_path, file_info)
                for file_path, file_info in all_files
                if not self.state.should_skip_file(file_path)
            ]
            skipped_files = before - len(all_files)
            if skipped_files:
                logger.info(f"Resume: skipped {skipped_files} already-checked files")

        if not all_files:
            self._mark_shares_done(walked_shares)
            logger.info("No files left to scan after resume filtering")
            if self.progress and skipped_files:
                self.progress.files_total = skipped_files
                self.progress.files_scanned = skipped_files
            return 0

        if self.progress:
            self.progress.files_total = len(all_files) + skipped_files
            self.progress.files_scanned = skipped_files

        # ---------- File scanning ----------
        results_count = 0

        with ThreadPoolExecutor(max_workers=self.file_threads) as executor:
            future_to_file = {
                executor.submit(
                    self.file_scanner.scan_file, file_path, file_info
                ): file_path
                for file_path, file_info in all_files
            }
            try:
                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        result = future.result()

                        # Mark as checked once scan attempt completes
                        if self.state:
                            self.state.mark_file_done(file_path)

                        if self.progress:
                            self.progress.files_scanned += 1

                        if result:
                            results_count += 1
                            if self.progress:
                                self.progress.files_matched += 1
                                self._count_severity(result)

                    except Exception as e:
                        logger.debug(f"Error scanning {file_path}: {e}")
            except KeyboardInterrupt:
                executor.shutdown(wait=False, cancel_futures=True)
                raise

        # Mark shares as fully processed only after all files are scanned.
        # On KeyboardInterrupt the raise above skips this, so interrupted
        # shares get re-walked on resume (cheap — dirs already checked).
        self._mark_shares_done(walked_shares)

        logger.info(f"Scan completed: {results_count} files matched")
        return results_count

    def _mark_shares_done(self, walked_shares: list):
        """Mark successfully walked shares as fully processed in state DB."""
        if self.state:
            for share_path in walked_shares:
                self.state.mark_share_done(share_path)

    def _count_severity(self, result):
        """Increment the per-severity counter on progress state."""
        from snaffler.classifiers.rules import Triage

        triage = result.triage
        if triage == Triage.BLACK:
            self.progress.severity_black += 1
        elif triage == Triage.RED:
            self.progress.severity_red += 1
        elif triage == Triage.YELLOW:
            self.progress.severity_yellow += 1
        elif triage == Triage.GREEN:
            self.progress.severity_green += 1
