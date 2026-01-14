import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from snaffler.accessors.smb_file_accessor import SMBFileAccessor
from snaffler.analysis.file_scanner import FileScanner
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.discovery.tree import TreeWalker
from snaffler.resume.scan_state import ScanState

logger = logging.getLogger("snaffler")


class FilePipeline:
    def __init__(
            self,
            cfg: SnafflerConfiguration,
            state: ScanState | None = None,
    ):
        self.cfg = cfg
        self.state = state

        self.tree_threads = cfg.advanced.tree_threads
        self.file_threads = cfg.advanced.file_threads

        # Shared accessor for both tree walking and file scanning
        file_accessor = SMBFileAccessor(cfg)

        self.tree_walker = TreeWalker(
            cfg,
            file_accessor=file_accessor,
            state=state,
        )

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

        all_files: list[tuple[str, object]] = []
        all_walked_dirs: list[str] = []

        # ---------- Tree walking ----------
        with ThreadPoolExecutor(max_workers=self.tree_threads) as executor:
            future_to_path = {
                executor.submit(self.tree_walker.walk_tree, path): path
                for path in paths
            }

            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    files, walked_dirs = future.result()
                    all_files.extend(files)
                    all_walked_dirs.extend(walked_dirs)
                except Exception as e:
                    logger.debug(f"Error walking {path}: {e}")

        if not all_files:
            logger.warning("No files found")
            return 0

        # ---------- Resume filtering (files only) ----------
        if self.state:
            before = len(all_files)
            all_files = [
                (file_path, file_info)
                for file_path, file_info in all_files
                if not self.state.should_skip_file(file_path)
            ]
            skipped = before - len(all_files)
            if skipped:
                logger.info(f"Resume: skipped {skipped} already-checked files")

        if not all_files:
            logger.info("No files left to scan after resume filtering")
            return 0

        # ---------- File scanning ----------
        results_count = 0

        with ThreadPoolExecutor(max_workers=self.file_threads) as executor:
            future_to_file = {
                executor.submit(
                    self.file_scanner.scan_file, file_path, file_info
                ): file_path
                for file_path, file_info in all_files
            }

            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    result = future.result()

                    # Mark as checked once scan attempt completes
                    if self.state:
                        self.state.mark_file_done(file_path)

                    if result:
                        results_count += 1

                except Exception as e:
                    logger.debug(f"Error scanning {file_path}: {e}")

        # ---------- Mark directories done AFTER all file scanning completes ----------
        if self.state and all_walked_dirs:
            for dir_path in all_walked_dirs:
                self.state.mark_dir_done(dir_path)
            logger.debug(f"Marked {len(all_walked_dirs)} directories as completed")

        logger.info(f"Scan completed: {results_count} files matched")
        return results_count
