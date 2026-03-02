"""
Abstract base class for directory tree walking with rule-based filtering.
"""

import fnmatch
import logging
import threading
from abc import ABC, abstractmethod

from snaffler.classifiers.rules import (
    MatchAction,
    EnumerationScope,
    MatchLocation,
)
from snaffler.config.configuration import SnafflerConfiguration

logger = logging.getLogger("snaffler")


class TreeWalker(ABC):
    def __init__(self, cfg: SnafflerConfiguration):
        self.cfg = cfg
        self.dir_classifiers = [
            r for r in cfg.rules.directory
            if r.enumeration_scope == EnumerationScope.DIRECTORY_ENUMERATION
        ]

    @abstractmethod
    def walk_directory(self, unc_path: str, on_file=None, on_dir=None,
                       cancel: threading.Event | None = None) -> list:
        """Walk a single directory (non-recursive) and return subdirectory paths.

        Args:
            unc_path: Full path to the directory
            on_file: callable(path, size, mtime_epoch) -- called for each file
            on_dir: callable(path) -- called for each subdirectory
            cancel: optional threading.Event -- checked before listing

        Returns:
            List of subdirectory paths discovered.
        """
        ...

    def _should_scan_directory(self, dir_path: str) -> bool:
        exclude_unc = self.cfg.targets.exclude_unc
        if exclude_unc:
            path_lower = dir_path.lower()
            if any(fnmatch.fnmatch(path_lower, p.lower()) for p in exclude_unc):
                logger.debug(f"Skipped directory {dir_path} due to --exclude-unc filter")
                return False

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
                    f"[{rule.triage.label}] [{rule.rule_name}] Directory: {dir_path}"
                )

        return True
