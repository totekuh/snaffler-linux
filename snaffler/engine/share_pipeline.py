"""
Share discovery pipeline
Responsible for enumerating readable SMB shares on target computers
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

from snaffler.config.configuration import SnafflerConfiguration
from snaffler.discovery.shares import ShareFinder
from snaffler.utils.progress import ProgressState

logger = logging.getLogger("snaffler")


class SharePipeline:

    def __init__(self, cfg: SnafflerConfiguration, progress: ProgressState | None = None):
        self.cfg = cfg
        self.progress = progress

        self.max_workers = self.cfg.advanced.share_threads
        self.shares_only = self.cfg.targets.shares_only

        # Internal worker
        self.share_finder = ShareFinder(cfg)

        if self.max_workers < 1:
            raise ValueError("Invalid share_threads configuration")

    def run(self, computers: List[str]) -> List[str]:
        """
        Enumerate readable shares on target computers

        Args:
            computers: List of computer names or IPs

        Returns:
            List of UNC share paths
        """
        logger.info(f"Starting share discovery on {len(computers)} computers")

        if self.progress:
            self.progress.computers_total = len(computers)

        all_shares: List[Tuple[str, object]] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_computer = {
                executor.submit(self.share_finder.get_computer_shares, computer): computer
                for computer in computers
            }

            for future in as_completed(future_to_computer):
                computer = future_to_computer[future]
                try:
                    shares = future.result()
                    if shares:
                        all_shares.extend(shares)
                        logger.info(f"Found {len(shares)} readable shares on {computer}")
                        if self.progress:
                            self.progress.shares_found += len(shares)
                except Exception as e:
                    logger.debug(f"Error processing {computer}: {e}")
                finally:
                    if self.progress:
                        self.progress.computers_done += 1

        if not all_shares:
            logger.warning("No readable shares found")
            return []

        if self.shares_only:
            logger.info("Shares-only mode enabled, skipping file enumeration")
            return []

        # Extract UNC paths only
        return [unc_path for unc_path, _ in all_shares]
