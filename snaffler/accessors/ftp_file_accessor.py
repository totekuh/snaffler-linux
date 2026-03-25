"""FTP file reader — ftplib retrbinary based."""

import logging
import os
import threading
from io import BytesIO
from pathlib import Path
from typing import Optional

from snaffler.accessors.file_accessor import FileAccessor
from snaffler.discovery.ftp_tree_walker import parse_ftp_url
from snaffler.transport.ftp import FTPTransport

logger = logging.getLogger("snaffler")


class FTPFileAccessor(FileAccessor):
    def __init__(self, cfg):
        self._transport = FTPTransport(cfg)
        self._thread_local = threading.local()
        self._max_file_bytes = cfg.scanning.max_file_bytes
        self._all_connections = []
        self._conn_lock = threading.Lock()

    def _get_ftp(self, host: str, port: int):
        cache = getattr(self._thread_local, "ftp_cache", {})
        self._thread_local.ftp_cache = cache

        key = (host, port)
        ftp = cache.get(key)
        if ftp:
            try:
                ftp.voidcmd("NOOP")
                return ftp
            except Exception:
                with self._conn_lock:
                    try:
                        self._all_connections.remove(ftp)
                    except ValueError:
                        pass
                try:
                    ftp.quit()
                except Exception:
                    pass
                cache.pop(key, None)

        ftp = self._transport.connect(host, port)
        cache[key] = ftp
        with self._conn_lock:
            self._all_connections.append(ftp)
        return ftp

    def _invalidate_ftp(self, host: str, port: int):
        cache = getattr(self._thread_local, "ftp_cache", None)
        if cache:
            key = (host, port)
            ftp = cache.pop(key, None)
            if ftp:
                with self._conn_lock:
                    try:
                        self._all_connections.remove(ftp)
                    except ValueError:
                        pass
                try:
                    ftp.quit()
                except Exception:
                    pass

    def close(self):
        """Close all cached FTP connections across all threads."""
        with self._conn_lock:
            for ftp in self._all_connections:
                try:
                    ftp.quit()
                except Exception:
                    pass
            self._all_connections.clear()

    def read(self, file_path: str, max_bytes: Optional[int] = None) -> Optional[bytes]:
        parsed = parse_ftp_url(file_path)
        if not parsed:
            return None

        host, port, remote_path = parsed
        read_size = max_bytes if max_bytes is not None else self._max_file_bytes

        try:
            ftp = self._get_ftp(host, port)
            buf = BytesIO()
            bytes_read = [0]

            def callback(data):
                remaining = read_size - bytes_read[0]
                if remaining <= 0:
                    return
                chunk = data[:remaining]
                buf.write(chunk)
                bytes_read[0] += len(chunk)

            ftp.retrbinary(f"RETR {remote_path}", callback)
            return buf.getvalue()
        except Exception as e:
            logger.debug(f"FTP read failed for {file_path}: {e}")
            self._invalidate_ftp(host, port)
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
            logger.debug(f"FTP copy failed for {file_path}: {e}")
