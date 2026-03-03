"""Local filesystem tree walker — os.scandir() based, single directory listing."""

import logging
import os

from snaffler.discovery.tree import TreeWalker

logger = logging.getLogger("snaffler")


class LocalTreeWalker(TreeWalker):
    """Walk local directories using os.scandir().

    Extends TreeWalker ABC so directory rule filtering (``_should_scan_directory``)
    is shared with SMBTreeWalker — both branches use the same code.
    """

    def __init__(self, dir_rules=None, exclude_unc=None):
        super().__init__(dir_rules=dir_rules, exclude_unc=exclude_unc)

    def walk_directory(self, dir_path, on_file=None, on_dir=None, cancel=None):
        """List one directory, call callbacks, return list of subdirectory paths."""
        if cancel and cancel.is_set():
            return []

        subdirs = []
        try:
            entries = os.scandir(dir_path)
        except OSError as e:
            logger.debug(f"Cannot list {dir_path}: {e}")
            return []

        with entries:
            for entry in entries:
                try:
                    if entry.is_dir(follow_symlinks=False):
                        if self._should_scan_directory(entry.path):
                            subdirs.append(entry.path)
                            if on_dir:
                                on_dir(entry.path)
                    elif entry.is_file(follow_symlinks=True):
                        try:
                            stat = entry.stat()
                            size = stat.st_size
                            mtime = stat.st_mtime
                        except OSError:
                            size = 0
                            mtime = 0.0
                        if on_file:
                            on_file(entry.path, size, mtime)
                except OSError as e:
                    logger.debug(f"Skipping {entry.path}: {e}")
                    continue

        return subdirs
