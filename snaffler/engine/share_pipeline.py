"""
Share discovery pipeline
Responsible for enumerating readable SMB shares on target computers
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

logger = logging.getLogger("snaffler")


class SharePipeline:
    def __init__(self, share_finder, max_workers: int, shares_only: bool = False):
        """
        Initialize SharePipeline

        Args:
            share_finder: ShareFinder instance
            max_workers: Number of concurrent share enumeration threads
            shares_only: If True, only enumerate shares (no file scanning)
        """
        self.share_finder = share_finder
        self.max_workers = max_workers
        self.shares_only = shares_only

    def run(self, computers: List[str]) -> List[str]:
        """
        Enumerate readable shares on target computers

        Args:
            computers: List of computer names or IPs

        Returns:
            List of UNC share paths
        """
        logger.info(f"Starting share discovery on {len(computers)} computers")

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
                except Exception as e:
                    logger.debug(f"Error processing {computer}: {e}")

        if not all_shares:
            logger.warning("No readable shares found")
            return []

        logger.info(f"Found total of {len(all_shares)} readable shares")

        if self.shares_only:
            logger.info("Shares-only mode enabled, skipping file enumeration")
            return []

        # Extract UNC paths only
        return [unc_path for unc_path, _ in all_shares]
