"""Local filesystem file reader — plain open() based."""

import logging
import os
import shutil

from snaffler.accessors.file_accessor import FileAccessor

logger = logging.getLogger("snaffler")


class LocalFileAccessor(FileAccessor):
    """Read and copy local files.

    Extends FileAccessor ABC so both local and SMB branches share the
    same interface contract.
    """

    def read(self, file_path, max_bytes=None):
        """Read up to *max_bytes* from *file_path*. Returns bytes or None on error."""
        try:
            with open(file_path, "rb") as f:
                return f.read(max_bytes)
        except OSError as e:
            logger.debug(f"Cannot read {file_path}: {e}")
            return None

    def copy_to_local(self, file_path, dest_root):
        """Copy *file_path* into *dest_root*, preserving the basename."""
        try:
            os.makedirs(dest_root, exist_ok=True)
            dest = os.path.join(dest_root, os.path.basename(file_path))
            shutil.copy2(file_path, dest)
        except OSError as e:
            logger.debug(f"Cannot copy {file_path} to {dest_root}: {e}")
