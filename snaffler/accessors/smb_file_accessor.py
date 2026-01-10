# snaffler/transport/smb_file_accessor.py

import threading
from io import BytesIO
from pathlib import Path
from typing import Optional

from snaffler.accessors.file_accessor import FileAccessor
from snaffler.transport.smb import SMBTransport


class SMBFileAccessor(FileAccessor):
    def __init__(self, cfg):
        self._transport = SMBTransport(cfg)
        self._thread_local = threading.local()

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

    def can_read(self, server: str, share: str, path: str) -> bool:
        try:
            smb = self._get_smb(server)
            buf = BytesIO()
            smb.getFile(share, path, buf.write, 0, 1)
            return True
        except Exception:
            return False

    def read(self, server: str, share: str, path: str, max_bytes: Optional[int] = None) -> Optional[bytes]:
        try:
            smb = self._get_smb(server)
            buf = BytesIO()

            if max_bytes is None:
                smb.getFile(share, path, buf.write)
            else:
                smb.getFile(share, path, buf.write, 0, max_bytes)

            return buf.getvalue()
        except Exception:
            return None

    def copy_to_local(self, server, share, path, dest_root):
        try:
            clean = path.lstrip("\\/")
            local = Path(dest_root) / server / share / clean
            local.parent.mkdir(parents=True, exist_ok=True)

            data = self.read(server, share, path)
            if data:
                local.write_bytes(data)
        except Exception:
            pass
