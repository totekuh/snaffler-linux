from impacket.smbconnection import SMBConnection

from snaffler.config.configuration import SnafflerConfiguration
from snaffler.transport.auth import authenticate_smb
from snaffler.utils.fatal import check_fatal_os_error


class SMBTransport:
    def __init__(self, cfg: SnafflerConfiguration):
        self.cfg = cfg
        self.auth = cfg.auth

    def connect(self, target: str, timeout: int = None) -> SMBConnection:
        if timeout is None:
            timeout = self.auth.smb_timeout

        smb = SMBConnection(
            remoteName=target,
            remoteHost=target,
            sess_port=445,
            timeout=timeout,
        )

        try:
            authenticate_smb(smb, self.auth)
            return smb
        except Exception as e:
            check_fatal_os_error(e)
            # Login failed — close the underlying TCP socket to avoid leaks
            try:
                smb.close()
            except Exception:
                pass
            raise
