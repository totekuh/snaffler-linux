"""
Abstract base class for directory tree walking with rule-based filtering.

The ``should_scan_directory`` module-level function is the single source of
truth for directory filtering — used by both the CLI pipeline (via
``TreeWalker._should_scan_directory``) and the library API (via
``Snaffler._check_dir``).
"""

import fnmatch
import logging
import threading
from abc import ABC, abstractmethod
from typing import List, Optional

from snaffler.classifiers.rules import (
    ClassifierRule,
    MatchAction,
    EnumerationScope,
    MatchLocation,
)

logger = logging.getLogger("snaffler")


def should_scan_directory(
    dir_path: str,
    dir_rules: List[ClassifierRule],
    exclude_unc: List[str],
) -> bool:
    """Check whether a directory should be walked.

    This is the shared implementation used by both the CLI pipeline
    (``TreeWalker._should_scan_directory``) and the library API
    (``Snaffler._check_dir``).  One function, no divergence.

    Returns ``False`` if the path matches an exclusion glob or a
    directory DISCARD rule.
    """
    if exclude_unc:
        path_lower = dir_path.lower()
        if any(fnmatch.fnmatch(path_lower, p.lower()) for p in exclude_unc):
            logger.debug(f"Skipped directory {dir_path} due to --exclude-unc filter")
            return False

    for rule in dir_rules:
        if rule.match_location == MatchLocation.FILE_PATH:
            match_target = dir_path
        elif rule.match_location == MatchLocation.FILE_NAME:
            # Match against the directory name (last path component)
            match_target = dir_path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
            if not match_target:
                continue
        else:
            continue

        if not rule.matches(match_target):
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


class TreeWalker(ABC):
    def __init__(
        self,
        dir_rules: Optional[List[ClassifierRule]] = None,
        exclude_unc: Optional[List[str]] = None,
    ):
        self.dir_classifiers = dir_rules or []
        self._exclude_unc = exclude_unc or []

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
        """Delegate to the shared module-level function."""
        return should_scan_directory(dir_path, self.dir_classifiers, self._exclude_unc)
