from impacket.smbconnection import SMBConnection

from snaffler.config.configuration import SnafflerConfiguration


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

        # ---------------- Kerberos ----------------
        if self.auth.kerberos:
            smb.kerberosLogin(
                user=self.auth.username or "",
                password=self.auth.password or "",
                domain=self.auth.domain or "",
                lmhash="",
                nthash=self.auth.nthash or "",
                aesKey=None,
                kdcHost=self.auth.dc_host,
                useCache=self.auth.use_kcache,
            )
            return smb

        # ---------------- NTLM ----------------
        if self.auth.nthash:
            smb.login(
                self.auth.username,
                "",
                self.auth.domain or "",
                "",
                self.auth.nthash,
                )
        else:
            smb.login(
                self.auth.username,
                self.auth.password or "",
                self.auth.domain or "",
                )

        return smb
