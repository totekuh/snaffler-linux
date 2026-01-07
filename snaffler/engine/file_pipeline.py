import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from snaffler.accessors.smb_file_accessor import SMBFileAccessor
from snaffler.analysis.file_scanner import FileScanner
from snaffler.classifiers.evaluator import RuleEvaluator
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.discovery.tree import TreeWalker

logger = logging.getLogger("snaffler")


class FilePipeline:
    def __init__(self, cfg: SnafflerConfiguration):
        self.cfg = cfg

        self.tree_threads = cfg.advanced.tree_threads
        self.file_threads = cfg.advanced.file_threads

        self.tree_walker = TreeWalker(cfg)

        file_accessor = SMBFileAccessor(cfg)
        rule_evaluator = RuleEvaluator(
            file_rules=cfg.rules.file,
            content_rules=cfg.rules.content,
            postmatch_rules=cfg.rules.postmatch,
        )
        self.file_scanner = FileScanner(cfg=cfg,
                                        file_accessor=file_accessor,
                                        rule_evaluator=rule_evaluator)

    def run(self, paths: List[str]) -> int:
        """
        Execute file discovery + scanning

        Args:
            paths: UNC paths to scan

        Returns:
            Number of interesting files found
        """
        logger.info(f"Starting file discovery on {len(paths)} paths")

        all_files = []

        # ---------- Tree walking ----------
        with ThreadPoolExecutor(max_workers=self.tree_threads) as executor:
            future_to_path = {
                executor.submit(self.tree_walker.walk_tree, path): path
                for path in paths
            }

            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    files = future.result()
                    all_files.extend(files)
                except Exception as e:
                    logger.debug(f"Error walking {path}: {e}")

        if not all_files:
            logger.warning("No files found")
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
                    if result:
                        results_count += 1
                except Exception as e:
                    logger.debug(f"Error scanning {file_path}: {e}")

        logger.info(f"Scan completed: {results_count} files matched")
        return results_count
