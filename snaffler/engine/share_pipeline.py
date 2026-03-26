"""
Share discovery pipeline
Responsible for enumerating readable SMB shares on target computers
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

from snaffler.config.configuration import SnafflerConfiguration
from snaffler.discovery.shares import ShareFinder
from snaffler.resume.scan_state import ScanState
from snaffler.utils.fatal import check_fatal_os_error
from snaffler.utils.progress import ProgressState

logger = logging.getLogger("snaffler")


class SharePipeline:

    def __init__(
        self,
        cfg: SnafflerConfiguration,
        state: ScanState | None = None,
        progress: ProgressState | None = None,
    ):
        self.cfg = cfg
        self.state = state
        self.progress = progress

        self.max_workers = self.cfg.advanced.share_threads
        self.shares_only = self.cfg.targets.shares_only

        # Internal worker
        self.share_finder = ShareFinder(cfg)

        if self.max_workers < 1:
            raise ValueError("Invalid share_threads configuration")

    def close(self):
        """Close all cached connections held by the share finder."""
        try:
            self.share_finder.close()
        except Exception:
            pass

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
            self.progress.shares_start = time.monotonic()

        all_shares: List[Tuple[str, object]] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_computer = {
                executor.submit(self.share_finder.get_computer_shares, computer): computer
                for computer in computers
            }

            try:
                for future in as_completed(future_to_computer):
                    computer = future_to_computer[future]
                    try:
                        shares = future.result()
                        if shares:
                            all_shares.extend(shares)
                            readable_count = sum(1 for _, s in shares if s.readable)
                            logger.debug(f"Found {readable_count} readable shares on {computer}")
                            if self.progress:
                                with self.progress._lock:
                                    self.progress.shares_found += readable_count
                            # Store all shares (readable + unreadable) for resume / rescan
                            if self.state:
                                self.state.store_shares(
                                    [(unc, s.readable) for unc, s in shares]
                                )
                    except Exception as e:
                        check_fatal_os_error(e)
                        logger.debug(f"Error processing {computer}: {e}")
                    finally:
                        if self.progress:
                            with self.progress._lock:
                                self.progress.computers_done += 1
                        # Mark done on success or error (no DNS, access denied — no point retrying).
                        # On KeyboardInterrupt the for-loop breaks, so un-yielded futures
                        # never reach here and their computers get retried on resume.
                        if self.state:
                            self.state.mark_computer_done(computer)
            except KeyboardInterrupt:
                executor.shutdown(wait=False, cancel_futures=True)
                raise

        readable = [(unc, s) for unc, s in all_shares if s.readable]
        if not readable:
            logger.warning("No readable shares found")
            return []

        if self.shares_only:
            logger.info("Shares-only mode enabled, skipping file enumeration")
            return []

        # Extract UNC paths only (readable shares)
        return [unc_path for unc_path, _ in readable]
