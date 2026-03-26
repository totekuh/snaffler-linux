"""FTP file reader — ftplib retrbinary based."""

import logging
from io import BytesIO
from pathlib import Path
from typing import Optional

from snaffler.accessors.file_accessor import FileAccessor
from snaffler.discovery.ftp_tree_walker import parse_ftp_url
from snaffler.transport.ftp import FTPTransport
from snaffler.utils.connection_cache import ThreadLocalConnectionCache
from snaffler.utils.fatal import check_fatal_os_error

logger = logging.getLogger("snaffler")


class _TransferAborted(Exception):
    """Raised inside retrbinary callback to abort data transfer early."""
    pass


class FTPFileAccessor(FileAccessor):
    def __init__(self, cfg):
        self._transport = FTPTransport(cfg)
        self._max_file_bytes = cfg.scanning.max_file_bytes
        self._cache = ThreadLocalConnectionCache(
            connect_fn=lambda key: self._transport.connect(key[0], key[1]),
            health_check_fn=lambda ftp: ftp.voidcmd("NOOP"),
            disconnect_fn=lambda ftp: ftp.quit(),
            cache_attr="ftp_cache",
        )

    def close(self):
        """Close all cached FTP connections across all threads."""
        self._cache.close_all()

    def read(self, file_path: str, max_bytes: Optional[int] = None) -> Optional[bytes]:
        parsed = parse_ftp_url(file_path)
        if not parsed:
            return None

        host, port, remote_path = parsed
        read_size = max_bytes if max_bytes is not None else self._max_file_bytes
        key = (host, port)

        try:
            ftp = self._cache.get(key)
            buf = BytesIO()
            bytes_read = [0]

            def callback(data):
                remaining = read_size - bytes_read[0]
                if remaining <= 0:
                    # Abort the transfer — raising inside the callback
                    # causes retrbinary to close the data socket instead
                    # of downloading the entire file for nothing.
                    raise _TransferAborted()
                chunk = data[:remaining]
                buf.write(chunk)
                bytes_read[0] += len(chunk)

            try:
                ftp.retrbinary(f"RETR {remote_path}", callback)
            except _TransferAborted:
                # Intentional abort — the control connection may be in a
                # bad state after an aborted data transfer, so invalidate
                # it to force a fresh connection on the next operation.
                self._cache.invalidate(key)
            return buf.getvalue()
        except Exception as e:
            check_fatal_os_error(e)
            logger.debug(f"FTP read failed for {file_path}: {e}")
            self._cache.invalidate(key)
            return None

    def copy_to_local(self, file_path: str, dest_root) -> None:
        parsed = parse_ftp_url(file_path)
        if not parsed:
            return

        host, port, remote_path = parsed
        try:
            clean = remote_path.lstrip("/")
            local = (Path(dest_root) / host / clean).resolve()
            root = Path(dest_root).resolve()
            if not local.is_relative_to(root):
                logger.warning(f"Path traversal blocked: {file_path}")
                return

            local.parent.mkdir(parents=True, exist_ok=True)

            data = self.read(file_path, max_bytes=self._max_file_bytes)
            if data:
                local.write_bytes(data)
        except Exception as e:
            check_fatal_os_error(e)
            logger.debug(f"FTP copy failed for {file_path}: {e}")
