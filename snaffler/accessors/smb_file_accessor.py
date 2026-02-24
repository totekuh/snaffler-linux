# snaffler/transport/smb_file_accessor.py

import threading
from pathlib import Path
from typing import Optional

from impacket.smb import FILE_READ_DATA, FILE_READ_ATTRIBUTES, FILE_SHARE_READ

from snaffler.accessors.file_accessor import FileAccessor
from snaffler.transport.smb import SMBTransport


class SMBFileAccessor(FileAccessor):
    def __init__(self, cfg):
        self._transport = SMBTransport(cfg)
        self._thread_local = threading.local()
        self._max_file_bytes = cfg.scanning.max_file_bytes

    def _get_smb(self, server: str):
        cache = getattr(self._thread_local, "smb_cache", {})
        self._thread_local.smb_cache = cache

        smb = cache.get(server)
        if smb:
            try:
                smb.getServerName()
                return smb
            except Exception:
                try:
                    smb.logoff()
                except Exception:
                    pass
                cache.pop(server, None)

        smb = self._transport.connect(server)
        cache[server] = smb
        return smb

    def read(self, server: str, share: str, path: str, max_bytes: Optional[int] = None) -> Optional[bytes]:
        try:
            smb = self._get_smb(server)
            tid = smb.connectTree(share)
            try:
                fid = smb.openFile(
                    tid,
                    path,
                    desiredAccess=FILE_READ_DATA | FILE_READ_ATTRIBUTES,
                    shareMode=FILE_SHARE_READ,
                )
                try:
                    data = smb.readFile(tid, fid, offset=0, bytesToRead=max_bytes or 0)
                    return data if data else b""
                finally:
                    smb.closeFile(tid, fid)
            finally:
                smb.disconnectTree(tid)
        except Exception:
            cache = getattr(self._thread_local, "smb_cache", None)
            if cache:
                cache.pop(server, None)
            return None

    def copy_to_local(self, server, share, path, dest_root):
        try:
            clean = path.lstrip("\\/")
            local = (Path(dest_root) / server / share / clean).resolve()
            root = Path(dest_root).resolve()
            if not local.is_relative_to(root):
                return

            local.parent.mkdir(parents=True, exist_ok=True)

            data = self.read(server, share, path, max_bytes=self._max_file_bytes)
            if data:
                local.write_bytes(data)
        except Exception:
            pass
