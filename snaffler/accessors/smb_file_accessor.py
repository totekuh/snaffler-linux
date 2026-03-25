# snaffler/accessors/smb_file_accessor.py

import threading
from pathlib import Path
from typing import Optional

from impacket.smb import FILE_READ_DATA, FILE_READ_ATTRIBUTES, FILE_SHARE_READ

from snaffler.accessors.file_accessor import FileAccessor
from snaffler.transport.smb import SMBTransport
from snaffler.utils.path_utils import parse_unc_path


class SMBFileAccessor(FileAccessor):
    def __init__(self, cfg):
        self._transport = SMBTransport(cfg)
        self._thread_local = threading.local()
        self._max_file_bytes = cfg.scanning.max_file_bytes
        self._all_connections = []
        self._conn_lock = threading.Lock()

    @staticmethod
    def _parse(file_path: str):
        """Parse a UNC path into (server, share, smb_path) or None."""
        parsed = parse_unc_path(file_path)
        if not parsed:
            return None
        server, share, smb_path, _name, _ext = parsed
        return server, share, smb_path

    def _get_smb(self, server: str):
        cache = getattr(self._thread_local, "smb_cache", {})
        self._thread_local.smb_cache = cache

        smb = cache.get(server)
        if smb:
            try:
                smb.getServerName()
                return smb
            except Exception:
                with self._conn_lock:
                    try:
                        self._all_connections.remove(smb)
                    except ValueError:
                        pass
                try:
                    smb.logoff()
                except Exception:
                    pass
                cache.pop(server, None)

        smb = self._transport.connect(server)
        cache[server] = smb
        with self._conn_lock:
            self._all_connections.append(smb)
        return smb

    def read(self, file_path: str, max_bytes: Optional[int] = None) -> Optional[bytes]:
        parsed = self._parse(file_path)
        if not parsed:
            return None
        server, share, smb_path = parsed
        try:
            smb = self._get_smb(server)
            tid = smb.connectTree(share)
            try:
                fid = smb.openFile(
                    tid,
                    smb_path,
                    desiredAccess=FILE_READ_DATA | FILE_READ_ATTRIBUTES,
                    shareMode=FILE_SHARE_READ,
                )
                try:
                    read_size = max_bytes if max_bytes is not None else self._max_file_bytes
                    data = smb.readFile(tid, fid, offset=0, bytesToRead=read_size)
                    return data if data else b""
                finally:
                    smb.closeFile(tid, fid)
            finally:
                smb.disconnectTree(tid)
        except Exception:
            cache = getattr(self._thread_local, "smb_cache", None)
            if cache:
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
            return None

    def close(self):
        """Close all cached SMB connections across all threads."""
        with self._conn_lock:
            for smb in self._all_connections:
                try:
                    smb.logoff()
                except Exception:
                    pass
            self._all_connections.clear()

    def copy_to_local(self, file_path: str, dest_root) -> None:
        parsed = self._parse(file_path)
        if not parsed:
            return
        server, share, smb_path = parsed
        try:
            clean = smb_path.lstrip("\\/").replace("\\", "/")
            local = (Path(dest_root) / server / share / clean).resolve()
            root = Path(dest_root).resolve()
            if not local.is_relative_to(root):
                return

            local.parent.mkdir(parents=True, exist_ok=True)

            data = self.read(file_path, max_bytes=self._max_file_bytes)
            if data:
                local.write_bytes(data)
        except Exception:
            pass
