"""
Directory tree walking over SMB with resume support
"""

import logging
from typing import List, Tuple, Any

from snaffler.accessors.file_accessor import FileAccessor
from snaffler.classifiers.rules import (
    MatchAction,
    EnumerationScope,
    MatchLocation,
)
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.resume.scan_state import ScanState
from snaffler.utils.path_utils import parse_unc_base

logger = logging.getLogger("snaffler")


class TreeWalker:
    def __init__(
            self,
            cfg: SnafflerConfiguration,
            file_accessor: FileAccessor,
            state: ScanState | None = None,
    ):
        self.cfg = cfg
        self.state = state
        self.file_accessor = file_accessor

        self.dir_classifiers = [
            r for r in cfg.rules.directory
            if r.enumeration_scope == EnumerationScope.DIRECTORY_ENUMERATION
        ]

    def walk_tree(self, unc_path: str) -> Tuple[List[Tuple[str, Any]], List[str]]:
        """
        Walk a directory tree and return all files and walked directories.

        Resume semantics:
        - Directories are skipped if already marked as checked
        - Directories are NOT marked here - caller must mark them after file scanning

        Returns:
            Tuple of (files, walked_directories)
        """
        files: List[Tuple[str, Any]] = []
        walked_dirs: List[str] = []

        try:
            parsed = parse_unc_base(unc_path)
            if not parsed:
                logger.error(
                    f"Invalid UNC path: {unc_path}; example: //10.10.10.10/SHARE$"
                )
                return files, walked_dirs

            server, share, path = parsed

            self._walk_directory(server, share, path, files, walked_dirs)

            if files:
                logger.info(f"Found {len(files)} files in {unc_path}")

        except Exception as e:
            logger.debug(f"Error walking tree {unc_path}: {e}")

        return files, walked_dirs

    def _walk_directory(
            self,
            server: str,
            share: str,
            path: str,
            files: List[Tuple[str, Any]],
            walked_dirs: List[str],
    ):
        if not path.endswith("/"):
            path += "/"

        unc_dir = f"//{server}/{share}{path}"
        logger.debug(f"Walking tree: {unc_dir}")

        # ---------- Resume: directory already fully scanned ----------
        if self.state and self.state.should_skip_dir(unc_dir):
            logger.debug(f"Resume: skipping directory {unc_dir}")
            return

        try:
            entries = self.file_accessor.list_path(server, share, path + "*")
            if not entries:
                logger.debug(f"Cannot list or empty: {unc_dir}")
                return

            for entry in entries:
                name = entry.get_longname()
                if name in (".", ".."):
                    continue

                entry_path = path + name
                unc_full = f"//{server}/{share}{entry_path}"

                if entry.is_directory():
                    if self._should_scan_directory(unc_full):
                        self._walk_directory(
                            server, share, entry_path, files, walked_dirs
                        )
                else:
                    files.append((unc_full, entry))

            # ---------- Collect directory for later marking ----------
            walked_dirs.append(unc_dir)

        except Exception as e:
            logger.debug(f"Error walking {unc_dir}: {e}")

    def _should_scan_directory(self, dir_path: str) -> bool:
        for rule in self.dir_classifiers:
            if rule.match_location != MatchLocation.FILE_PATH:
                continue

            if not rule.matches(dir_path):
                continue

            if rule.match_action == MatchAction.DISCARD:
                logger.debug(
                    f"Skipped scanning on {dir_path} due to Discard rule match: "
                    f"{rule.rule_name}"
                )
                return False

            if rule.match_action == MatchAction.SNAFFLE:
                logger.warning(
                    f"[{rule.triage.value}] [{rule.rule_name}] Directory: {dir_path}"
                )

        return True
