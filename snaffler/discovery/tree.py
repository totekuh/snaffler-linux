"""
Directory tree walking over SMB with resume support
"""

import logging
import threading

from impacket.smbconnection import SessionError

from snaffler.classifiers.rules import (
    MatchAction,
    EnumerationScope,
    MatchLocation,
)
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.resume.scan_state import ScanState
from snaffler.transport.smb import SMBTransport

logger = logging.getLogger("snaffler")


class TreeWalker:
    def __init__(
            self,
            cfg: SnafflerConfiguration,
            state: ScanState | None = None,
    ):
        self.cfg = cfg
        self.state = state
        self.smb_transport = SMBTransport(cfg)
        self._local = threading.local()

        self.dir_classifiers = [
            r for r in cfg.rules.directory
            if r.enumeration_scope == EnumerationScope.DIRECTORY_ENUMERATION
        ]

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
        return smb

    def _invalidate_smb(self, server: str):
        """Logoff and remove a cached connection for *server*."""
        cache = getattr(self._local, "connections", None)
        if cache is None:
            return
        smb = cache.pop(server, None)
        if smb is not None:
            try:
                smb.logoff()
            except Exception:
                pass

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

    def walk_tree(self, unc_path: str, on_file=None, cancel: threading.Event | None = None):
        """Walk a directory tree using iterative DFS, calling on_file for each file.

        Args:
            unc_path: UNC path to the share root (e.g. //HOST/SHARE)
            on_file: callable(unc_path, size, mtime_epoch) -- called for each file
            cancel: optional threading.Event -- checked before each directory listing
        """
        parsed = self._parse_unc(unc_path)
        if parsed is None:
            logger.error(
                f"Invalid UNC path: {unc_path}; example: //10.10.10.10/SHARE$"
            )
            return

        server, share, path = parsed
        try:
            smb = self._get_smb(server)
            # Iterative DFS with explicit stack (relative paths within the share)
            stack = [path]
            while stack:
                if cancel and cancel.is_set():
                    return
                current = stack.pop()
                subdir_paths = self._list_directory(
                    smb, server, share, current, on_file, None, cancel,
                )
                # Push subdirs in reverse order so left-most is processed first
                stack.extend(reversed(subdir_paths))
        except Exception as e:
            self._invalidate_smb(server)
            logger.debug(f"Error walking tree {unc_path}: {e}")

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
        except Exception as e:
            self._invalidate_smb(server)
            logger.debug(f"Error walking directory {unc_path}: {e}")
            return []

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
            return []

        if not path.endswith("/"):
            path += "/"

        unc_dir = f"//{server}/{share}{path}"
        logger.debug(f"Walking directory: {unc_dir}")

        subdir_paths = []
        try:
            try:
                entries = smb.listPath(share, path + "*")
            except SessionError as e:
                logger.debug(f"Cannot list {unc_dir}: {e}")
                return []

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

        except Exception as e:
            self._invalidate_smb(server)
            logger.debug(f"Error walking {unc_dir}: {e}")

        return subdir_paths

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
