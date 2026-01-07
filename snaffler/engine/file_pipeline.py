import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from snaffler.config.configuration import SnafflerConfiguration
from snaffler.discovery.files import FileScanner
from snaffler.discovery.tree import TreeWalker

logger = logging.getLogger("snaffler")


class FilePipeline:
    """
    File discovery + scanning pipeline
    - Walks directory trees
    - Scans files with FileScanner
    """

    def __init__(self, cfg: SnafflerConfiguration):
        self.cfg = cfg

        self.tree_threads = self.cfg.advanced.tree_threads
        self.file_threads = self.cfg.advanced.file_threads

        # internal workers
        self.tree_walker = TreeWalker(cfg)
        self.file_scanner = FileScanner(cfg)

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
