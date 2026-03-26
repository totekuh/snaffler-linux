"""Local filesystem file reader — plain open() based."""

import logging
import os
import shutil

from snaffler.accessors.file_accessor import FileAccessor
from snaffler.utils.fatal import check_fatal_os_error

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
            check_fatal_os_error(e)
            logger.debug(f"Cannot read {file_path}: {e}")
            return None

    def copy_to_local(self, file_path, dest_root):
        """Copy *file_path* into *dest_root*, preserving directory structure."""
        try:
            # Strip leading separator to make path relative under dest_root
            rel = os.path.relpath(file_path, "/")
            dest = os.path.join(dest_root, rel)

            # Guard against path traversal via '..' components
            real_dest = os.path.realpath(dest)
            real_root = os.path.realpath(dest_root)
            if not real_dest.startswith(real_root + os.sep) and real_dest != real_root:
                logger.warning(f"Path traversal blocked: {file_path}")
                return

            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copy2(file_path, dest)
        except OSError as e:
            check_fatal_os_error(e)
            logger.debug(f"Cannot copy {file_path} to {dest_root}: {e}")
