"""
SMB-based directory tree walking using impacket SMBConnection.
"""

import logging
import threading
from concurrent.futures import CancelledError

from impacket.smbconnection import SessionError

from snaffler.config.configuration import SnafflerConfiguration
from snaffler.discovery.tree import TreeWalker
from snaffler.transport.smb import SMBTransport

logger = logging.getLogger("snaffler")


class SMBTreeWalker(TreeWalker):
    def __init__(self, cfg: SnafflerConfiguration):
        super().__init__(
            dir_rules=cfg.rules.directory,
            exclude_unc=cfg.targets.exclude_unc,
        )
        self.smb_transport = SMBTransport(cfg)
        self._local = threading.local()
        self._all_connections = []
        self._conn_lock = threading.Lock()

    def _get_smb(self, server: str):
        """Return a cached SMB connection for *server*, creating one if needed.

        Uses thread-local storage so each worker thread maintains its own
        connection cache — the same pattern used by SMBFileAccessor.
        """
        cache = getattr(self._local, "connections", None)
        if cache is None:
            cache = {}
            self._local.connections = cache

        smb = cache.get(server)
        if smb is not None:
            try:
                smb.getServerName()
                return smb
            except Exception:
                try:
                    smb.logoff()
                except Exception:
                    pass
                cache.pop(server, None)

        smb = self.smb_transport.connect(server)
        cache[server] = smb
        with self._conn_lock:
            self._all_connections.append(smb)
        return smb

    def _invalidate_smb(self, server: str):
        """Logoff and remove a cached connection for *server*."""
        cache = getattr(self._local, "connections", None)
        if cache is None:
            return
        smb = cache.pop(server, None)
        if smb is not None:
            with self._conn_lock:
                try:
                    self._all_connections.remove(smb)
                except ValueError:
                    pass
            try:
                smb.logoff()
            except Exception:
                pass

    def close(self):
        """Close all cached SMB connections across all threads."""
        with self._conn_lock:
            for smb in self._all_connections:
                try:
                    smb.logoff()
                except Exception:
                    pass
            self._all_connections.clear()

    @staticmethod
    def _parse_unc(unc_path: str):
        """Parse UNC path into (server, share, path) or None on invalid input."""
        parts = unc_path.replace("\\", "/").split("/")
        parts = [p for p in parts if p]

        if len(parts) < 2:
            return None

        server = parts[0]
        share = parts[1]
        path = "/" + "/".join(parts[2:]) if len(parts) > 2 else "/"
        return server, share, path

    def walk_directory(self, unc_path: str, on_file=None, on_dir=None,
                       cancel: threading.Event | None = None) -> list:
        """Walk a single directory (non-recursive) and return subdirectory UNC paths.

        Args:
            unc_path: Full UNC path to the directory (e.g. //HOST/SHARE/subdir)
            on_file: callable(unc_path, size, mtime_epoch) -- called for each file
            on_dir: callable(unc_path) -- called for each subdirectory
            cancel: optional threading.Event -- checked before listing

        Returns:
            List of subdirectory UNC paths discovered.
        """
        parsed = self._parse_unc(unc_path)
        if parsed is None:
            logger.error(
                f"Invalid UNC path: {unc_path}; example: //10.10.10.10/SHARE$"
            )
            return []

        server, share, path = parsed
        try:
            smb = self._get_smb(server)
            subdir_paths = self._list_directory(
                smb, server, share, path, on_file, on_dir, cancel,
            )
            # Convert relative paths to full UNC paths
            return [f"//{server}/{share}{p}" for p in subdir_paths]
        except SessionError as e:
            # SMB-level error (ACCESS_DENIED, etc.) — connection is still valid,
            # don't invalidate it.  Re-raise so the caller can track the failure.
            logger.debug(f"Cannot list {unc_path}: {e}")
            raise
        except Exception as e:
            self._invalidate_smb(server)
            logger.debug(f"Error walking directory {unc_path}: {e}")
            raise

    def _list_directory(
            self,
            smb,
            server: str,
            share: str,
            path: str,
            on_file,
            on_dir,
            cancel: threading.Event | None = None,
    ) -> list:
        """List one directory: call on_file for files, on_dir for subdirs.

        Returns list of relative subdirectory paths within the share
        (e.g. ['/subdir1', '/subdir2']). Does NOT recurse.
        """
        if cancel and cancel.is_set():
            raise CancelledError("walk cancelled")

        if not path.endswith("/"):
            path += "/"

        unc_dir = f"//{server}/{share}{path}"
        logger.debug(f"Walking directory: {unc_dir}")

        subdir_paths = []
        entries = smb.listPath(share, path + "*")

        for entry in entries:
            name = entry.get_longname()
            if name in (".", ".."):
                continue

            entry_path = path + name
            unc_full = f"//{server}/{share}{entry_path}"

            if entry.is_directory():
                if self._should_scan_directory(unc_full):
                    subdir_paths.append(entry_path)
                    if on_dir:
                        on_dir(unc_full)
            else:
                try:
                    size = entry.get_filesize()
                except Exception:
                    size = 0
                try:
                    mtime = entry.get_mtime_epoch()
                except Exception:
                    mtime = 0.0
                if on_file:
                    on_file(unc_full, size, mtime)

        return subdir_paths
