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
                logger.error(f"Invalid UNC path: {unc_path}; example: //10.10.10.10/SHARE$")
                return files

            server = parts[0]
            share = parts[1]
            path = '/' + '/'.join(parts[2:]) if len(parts) > 2 else '/'

            logger.debug(f"Walking tree: {unc_path}")

            # Recursively walk the tree
            smb = self.smb_transport.connect(server)
            try:
                self._walk_directory(smb, server, share, path, files)
            finally:
                smb.logoff()

            logger.info(f"Found {len(files)} files in {unc_path}")

        except Exception as e:
            logger.debug(f"Error walking tree {unc_path}: {e}")

        return files

    def _walk_directory(self, smb, server: str, share: str, path: str, files: List):
        try:
            if not path.endswith('/'):
                path += '/'

            try:
                entries = smb.listPath(share, path + '*')
            except SessionError as e:
                logger.debug(f"Cannot list {server}/{share}{path}: {e}")
                return

            for entry in entries:
                name = entry.get_longname()
                if name in ('.', '..'):
                    continue

                entry_path = path + name
                unc_full = f"//{server}/{share}{entry_path}"

                if entry.is_directory():
                    if self._should_scan_directory(unc_full):
                        self._walk_directory(smb, server, share, entry_path, files)
                else:
                    files.append((unc_full, entry))

        except Exception as e:
            logger.debug(f"Error walking {server}/{share}{path}: {e}")

    def _should_scan_directory(self, dir_path: str) -> bool:
        for rule in self.dir_classifiers:
            if rule.match_location != MatchLocation.FILE_PATH:
                continue

            if not rule.matches(dir_path):
                continue

            if rule.match_action == MatchAction.DISCARD:
                logger.debug(
                    f"Skipped scanning on {dir_path} due to Discard rule match: {rule.rule_name}"
                )
                return False

            if rule.match_action == MatchAction.SNAFFLE:
                logger.warning(
                    f"[{rule.triage.value}] [{rule.rule_name}] Directory: {dir_path}"
                )

        return True
