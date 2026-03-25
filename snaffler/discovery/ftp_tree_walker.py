"""FTP-based directory tree walking using ftplib."""

import logging
import threading
from urllib.parse import urlparse

from snaffler.config.configuration import SnafflerConfiguration
from snaffler.discovery.tree import TreeWalker
from snaffler.transport.ftp import FTPTransport

logger = logging.getLogger("snaffler")


def parse_ftp_url(ftp_url: str):
    """Parse ftp://host:port/path into (host, port, remote_path) or None."""
    if not ftp_url.startswith("ftp://"):
        return None
    parsed = urlparse(ftp_url)
    host = parsed.hostname
    if not host:
        return None
    port = parsed.port or 21
    path = parsed.path or "/"
    return host, port, path


def build_ftp_url(host: str, port: int, path: str) -> str:
    """Build ftp://host:port/path from components."""
    if port == 21:
        return f"ftp://{host}{path}"
    return f"ftp://{host}:{port}{path}"


def extract_ftp_root(ftp_url: str) -> str:
    """Extract ftp://host:port as the 'share' key for resume DB grouping."""
    parsed = parse_ftp_url(ftp_url)
    if not parsed:
        return ftp_url
    host, port, _ = parsed
    if port == 21:
        return f"ftp://{host}"
    return f"ftp://{host}:{port}"


class FTPTreeWalker(TreeWalker):
    def __init__(self, cfg: SnafflerConfiguration):
        super().__init__(
            dir_rules=cfg.rules.directory,
            exclude_unc=cfg.targets.exclude_unc,
        )
        self.ftp_transport = FTPTransport(cfg)
        self._local = threading.local()
        self._all_connections = []
        self._conn_lock = threading.Lock()

    def _get_ftp(self, host: str, port: int):
        """Return a cached FTP connection, creating one if needed.

        Uses thread-local storage so each worker thread maintains its own
        connection cache — same pattern as SMBTreeWalker._get_smb().
        """
        cache = getattr(self._local, "connections", None)
        if cache is None:
            cache = {}
            self._local.connections = cache

        key = (host, port)
        ftp = cache.get(key)
        if ftp is not None:
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

        ftp = self.ftp_transport.connect(host, port)
        cache[key] = ftp
        with self._conn_lock:
            self._all_connections.append(ftp)
        return ftp

    def _invalidate_ftp(self, host: str, port: int):
        """Quit and remove a cached connection."""
        cache = getattr(self._local, "connections", None)
        if cache is None:
            return
        key = (host, port)
        ftp = cache.pop(key, None)
        if ftp is not None:
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

    def walk_directory(self, ftp_path: str, on_file=None, on_dir=None,
                       cancel: threading.Event | None = None) -> list:
        """Walk a single FTP directory (non-recursive) and return subdirectory paths.

        Args:
            ftp_path: Full FTP URL (e.g. ftp://host/path/to/dir)
            on_file: callable(ftp_url, size, mtime_epoch) -- called for each file
            on_dir: callable(ftp_url) -- called for each subdirectory
            cancel: optional threading.Event -- checked before listing

        Returns:
            List of subdirectory FTP URL paths discovered.
        """
        if cancel and cancel.is_set():
            from concurrent.futures import CancelledError
            raise CancelledError("walk cancelled")

        parsed = parse_ftp_url(ftp_path)
        if parsed is None:
            logger.error(f"Invalid FTP URL: {ftp_path}; example: ftp://10.0.0.5/data")
            return []

        host, port, remote_path = parsed
        if not remote_path.endswith("/"):
            remote_path += "/"

        logger.debug(f"Walking directory: {ftp_path}")
        try:
            ftp = self._get_ftp(host, port)
            return self._list_directory(ftp, host, port, remote_path, on_file, on_dir)
        except Exception as e:
            self._invalidate_ftp(host, port)
            logger.debug(f"Error walking FTP directory {ftp_path}: {e}")
            raise

    def _list_directory(self, ftp, host, port, remote_path, on_file, on_dir):
        """List one FTP directory using MLSD, with fallback to NLST."""
        subdir_paths = []

        try:
            entries = list(ftp.mlsd(remote_path))
            for name, facts in entries:
                if name in (".", ".."):
                    continue

                entry_path = remote_path + name
                full_url = build_ftp_url(host, port, entry_path)
                entry_type = facts.get("type", "").lower()

                if entry_type in ("dir", "cdir", "pdir"):
                    if entry_type in ("cdir", "pdir"):
                        continue
                    if self._should_scan_directory(full_url):
                        subdir_paths.append(full_url)
                        if on_dir:
                            on_dir(full_url)
                elif entry_type == "file":
                    size = int(facts.get("size", 0))
                    mtime = self._parse_mlsd_modify(facts.get("modify", ""))
                    if on_file:
                        on_file(full_url, size, mtime)

        except Exception as mlsd_err:
            logger.debug(f"MLSD not supported ({mlsd_err}), falling back to NLST")
            subdir_paths = self._list_directory_nlst(
                ftp, host, port, remote_path, on_file, on_dir,
            )

        return subdir_paths

    def _list_directory_nlst(self, ftp, host, port, remote_path, on_file, on_dir):
        """Fallback directory listing using NLST + SIZE/MDTM per entry."""
        subdir_paths = []
        names = ftp.nlst(remote_path)

        for full_remote in names:
            name = full_remote.rsplit("/", 1)[-1]
            if not name or name in (".", ".."):
                continue

            entry_path = remote_path + name
            full_url = build_ftp_url(host, port, entry_path)

            # Try SIZE to determine if it's a file — dirs typically error
            try:
                size = ftp.size(entry_path)
                if size is None:
                    size = 0
                # It's a file
                mtime = self._get_mdtm(ftp, entry_path)
                if on_file:
                    on_file(full_url, size, mtime)
            except Exception:
                # Likely a directory
                if self._should_scan_directory(full_url):
                    subdir_paths.append(full_url)
                    if on_dir:
                        on_dir(full_url)

        return subdir_paths

    @staticmethod
    def _parse_mlsd_modify(modify_str: str) -> float:
        """Parse MLSD modify fact (YYYYMMDDhhmmss) to epoch float."""
        if not modify_str or len(modify_str) < 14:
            return 0.0
        try:
            from datetime import datetime, timezone
            dt = datetime(
                int(modify_str[0:4]),
                int(modify_str[4:6]),
                int(modify_str[6:8]),
                int(modify_str[8:10]),
                int(modify_str[10:12]),
                int(modify_str[12:14]),
                tzinfo=timezone.utc,
            )
            return dt.timestamp()
        except (ValueError, OverflowError):
            return 0.0

    @staticmethod
    def _get_mdtm(ftp, path: str) -> float:
        """Get file modification time via MDTM command, return epoch float."""
        try:
            resp = ftp.sendcmd(f"MDTM {path}")
            # Response format: "213 YYYYMMDDhhmmss"
            if resp.startswith("213 "):
                return FTPTreeWalker._parse_mlsd_modify(resp[4:].strip())
        except Exception:
            pass
        return 0.0
