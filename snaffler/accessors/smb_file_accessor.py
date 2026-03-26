# snaffler/accessors/smb_file_accessor.py

from pathlib import Path
from typing import Optional

from impacket.smb import FILE_READ_DATA, FILE_READ_ATTRIBUTES, FILE_SHARE_READ
from impacket.smbconnection import SessionError

from snaffler.accessors.file_accessor import FileAccessor
from snaffler.transport.smb import SMBTransport
from snaffler.utils.connection_cache import ThreadLocalConnectionCache
from snaffler.utils.fatal import check_fatal_os_error
from snaffler.utils.path_utils import parse_unc_path


class SMBFileAccessor(FileAccessor):
    def __init__(self, cfg):
        self._transport = SMBTransport(cfg)
        self._max_file_bytes = cfg.scanning.max_file_bytes
        self._cache = ThreadLocalConnectionCache(
            connect_fn=lambda server: self._transport.connect(server),
            health_check_fn=lambda smb: smb.getServerName(),
            disconnect_fn=lambda smb: smb.logoff(),
            cache_attr="smb_cache",
        )

    @staticmethod
    def _parse(file_path: str):
        """Parse a UNC path into (server, share, smb_path) or None."""
        parsed = parse_unc_path(file_path)
        if not parsed:
            return None
        server, share, smb_path, _name, _ext = parsed
        return server, share, smb_path

    def read(self, file_path: str, max_bytes: Optional[int] = None) -> Optional[bytes]:
        parsed = self._parse(file_path)
        if not parsed:
            return None
        server, share, smb_path = parsed
        try:
            smb = self._cache.get(server)
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
        except SessionError:
            # SMB-level error (ACCESS_DENIED, etc.) -- the connection is still
            # valid, don't tear it down.  Just return None for this file.
            return None
        except Exception as e:
            check_fatal_os_error(e)
            # Transport-level error (timeout, disconnect, etc.) -- connection
            # is likely dead, evict it from the cache.
            self._cache.invalidate(server)
            return None

    def close(self):
        """Close all cached SMB connections across all threads."""
        self._cache.close_all()

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
        except Exception as e:
            check_fatal_os_error(e)
