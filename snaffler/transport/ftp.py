"""FTP transport — connection factory with optional TLS support."""

import ftplib
import logging

from snaffler.config.configuration import SnafflerConfiguration

logger = logging.getLogger("snaffler")


class FTPTransport:
    def __init__(self, cfg: SnafflerConfiguration):
        self.cfg = cfg
        self.auth = cfg.auth

    def connect(self, host: str, port: int = 21) -> ftplib.FTP:
        timeout = self.auth.smb_timeout

        if self.cfg.targets.ftp_tls:
            ftp = ftplib.FTP_TLS(timeout=timeout)
        else:
            ftp = ftplib.FTP(timeout=timeout)

        ftp.connect(host, port)

        username = self.auth.username or "anonymous"
        password = self.auth.password or ""
        ftp.login(username, password)

        if self.cfg.targets.ftp_tls:
            ftp.prot_p()  # secure data channel

        ftp.set_pasv(True)
        # Binary mode for consistent transfers
        ftp.sendcmd("TYPE I")

        logger.debug(f"FTP connected to {host}:{port} as {username}")
        return ftp
