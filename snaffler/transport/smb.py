from impacket.smbconnection import SMBConnection
from snaffler.config.configuration import SnafflerConfiguration


class SMBTransport:
    def __init__(self, cfg: SnafflerConfiguration):
        self.cfg = cfg
        self.auth = cfg.auth

        self.username = self.auth.username
        self.password = self.auth.password or ""
        self.nthash = self.auth.nthash or ""
        self.domain = self.auth.domain or ""
        self.lmhash = ""

    def connect(self, target: str, timeout: int = 30) -> SMBConnection:
        smb = SMBConnection(
            remoteName=target,
            remoteHost=target,
            sess_port=445,
            timeout=timeout,
        )

        if self.nthash:
            smb.login(
                self.username,
                "",
                self.domain,
                self.lmhash,
                self.nthash,
            )
        else:
            smb.login(
                self.username,
                self.password,
                self.domain,
            )

        return smb
