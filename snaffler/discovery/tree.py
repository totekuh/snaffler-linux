"""
Directory tree walking over SMB
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Any

from impacket.smbconnection import SessionError

from snaffler.classifiers.rules import MatchAction, EnumerationScope, MatchLocation
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.transport.smb import SMBTransport

logger = logging.getLogger('snaffler')


class TreeWalker:
    def __init__(self, cfg: SnafflerConfiguration):
        self.cfg = cfg
        self.smb_transport = SMBTransport(cfg)

        self.dir_classifiers = [
            r for r in cfg.rules.directory
            if r.enumeration_scope == EnumerationScope.DIRECTORY_ENUMERATION
        ]

    def walk_tree(self, unc_path: str) -> List[str]:
        """
        Walk a directory tree and return all files

        Args:
            unc_path: UNC path to start from (//server/share or //server/share/path)

        Returns:
            List of UNC paths to files
        """
        files = []

        try:
            # Parse UNC path
            parts = unc_path.replace('\\', '/').split('/')
            parts = [p for p in parts if p]  # Remove empty parts

            if len(parts) < 2:
                logger.error(f"Invalid UNC path: {unc_path}")
                return files

            server = parts[0]
            share = parts[1]
            path = '/' + '/'.join(parts[2:]) if len(parts) > 2 else '/'

            logger.debug(f"Walking tree: {unc_path}")

            # Recursively walk the tree
            self._walk_directory(server, share, path, files)

            logger.info(f"Found {len(files)} files in {unc_path}")

        except Exception as e:
            logger.debug(f"Error walking tree {unc_path}: {e}")

        return files

    def _walk_directory(self, server: str, share: str, path: str, files: List):
        try:
            smb = self.smb_transport.connect(server)

            if not path.endswith('/'):
                path += '/'

            try:
                entries = smb.listPath(share, path + '*')
            except SessionError as e:
                logger.debug(f"Cannot list {server}/{share}{path}: {e}")
                smb.logoff()
                return

            for entry in entries:
                name = entry.get_longname()
                if name in ('.', '..'):
                    continue

                entry_path = path + name
                unc_full = f"//{server}/{share}{entry_path}"

                if entry.is_directory():
                    if self._should_scan_directory(unc_full):
                        self._walk_directory(server, share, entry_path, files)
                else:
                    files.append((unc_full, entry))

            smb.logoff()

        except Exception as e:
            logger.debug(f"Error walking {server}/{share}{path}: {e}")

    def _should_scan_directory(self, dir_path: str) -> bool:
        """
        Check if a directory should be scanned based on classifiers

        Args:
            dir_path: Full UNC path to directory

        Returns:
            True if should scan, False if should skip
        """
        # Apply directory classifiers
        for rule in self.dir_classifiers:
            if rule.match_location == MatchLocation.FILE_PATH:
                match = rule.matches(dir_path)

                if match:
                    if rule.match_action == MatchAction.DISCARD:
                        # Skip this directory
                        logger.debug(f"Skipped scanning on {dir_path} due to Discard rule match: {rule.rule_name}")
                        return False
                    elif rule.match_action == MatchAction.SNAFFLE:
                        # Log interesting directory and continue scanning
                        logger.warning(f"[{rule.triage.value}] [{rule.rule_name}] Directory: {dir_path}")
                        # Continue scanning (don't break, check other rules)

        # By default, scan the directory
        return True

    def batch_walk_trees(self, unc_paths: List[str], max_workers: int = 20) -> List[Tuple[str, Any]]:
        """
        Walk multiple directory trees concurrently

        Args:
            unc_paths: List of UNC paths to walk
            max_workers: Maximum number of concurrent threads

        Returns:
            List of tuples (file_path, file_info)
        """
        all_files = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_path = {
                executor.submit(self.walk_tree, unc_path): unc_path
                for unc_path in unc_paths
            }

            # Collect results as they complete
            for future in as_completed(future_to_path):
                unc_path = future_to_path[future]
                try:
                    files = future.result()
                    all_files.extend(files)
                except Exception as e:
                    logger.error(f"Exception walking {unc_path}: {e}")

        return all_files
