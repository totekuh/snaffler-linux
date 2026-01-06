import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

logger = logging.getLogger("snaffler")


class FilePipeline:
    """
    File discovery + scanning pipeline
    - Walks directory trees
    - Scans files with FileScanner
    """

    def __init__(self, tree_walker, file_scanner, tree_threads: int, file_threads: int):
        self.tree_walker = tree_walker
        self.file_scanner = file_scanner
        self.tree_threads = tree_threads
        self.file_threads = file_threads

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
                    logger.info(f"Found {len(files)} files in {path}")
                except Exception as e:
                    logger.debug(f"Error walking {path}: {e}")

        if not all_files:
            logger.warning("No files found")
            return 0

        logger.info(f"Found total of {len(all_files)} files, beginning scan")

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

        logger.info(f"Scan complete! Found {results_count} interesting files")
        return results_count
