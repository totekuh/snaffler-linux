"""FTP transport — connection factory with optional TLS support."""

import ftplib
import logging

from snaffler.config.configuration import SnafflerConfiguration
from snaffler.utils.fatal import check_fatal_os_error

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

        try:
            username = self.auth.username or "anonymous"
            password = self.auth.password or ""
            ftp.login(username, password)

            if self.cfg.targets.ftp_tls:
                ftp.prot_p()  # secure data channel

            ftp.set_pasv(True)
            # Binary mode for consistent transfers
            ftp.sendcmd("TYPE I")
        except Exception as e:
            check_fatal_os_error(e)
            # Close the TCP socket if any post-connect step fails
            # (login, TLS upgrade, passive mode, TYPE I) to prevent
            # leaked sockets.
            try:
                ftp.quit()
            except Exception:
                try:
                    ftp.close()
                except Exception:
                    pass
            raise

        logger.debug(f"FTP connected to {host}:{port} as {username}")
        return ftp
