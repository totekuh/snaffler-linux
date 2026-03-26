from unittest.mock import MagicMock, patch

import pytest

from snaffler.transport.ftp import FTPTransport


# ---------- helpers ----------

def make_cfg(username="user", password="pass", tls=False, timeout=5):
    cfg = MagicMock()
    cfg.auth.username = username
    cfg.auth.password = password
    cfg.auth.smb_timeout = timeout
    cfg.targets.ftp_tls = tls
    return cfg


# ---------- tests ----------

def test_connect_plain():
    cfg = make_cfg()

    with patch("snaffler.transport.ftp.ftplib") as mock_ftplib:
        ftp_inst = MagicMock()
        mock_ftplib.FTP.return_value = ftp_inst

        transport = FTPTransport(cfg)
        result = transport.connect("10.0.0.5", 21)

    mock_ftplib.FTP.assert_called_once_with(timeout=5)
    ftp_inst.connect.assert_called_once_with("10.0.0.5", 21)
    ftp_inst.login.assert_called_once_with("user", "pass")
    ftp_inst.set_pasv.assert_called_once_with(True)
    ftp_inst.sendcmd.assert_called_once_with("TYPE I")
    assert result is ftp_inst


def test_connect_tls():
    cfg = make_cfg(tls=True)

    with patch("snaffler.transport.ftp.ftplib") as mock_ftplib:
        ftp_inst = MagicMock()
        mock_ftplib.FTP_TLS.return_value = ftp_inst

        transport = FTPTransport(cfg)
        result = transport.connect("10.0.0.5")

    mock_ftplib.FTP_TLS.assert_called_once_with(timeout=5)
    ftp_inst.login.assert_called_once_with("user", "pass")
    ftp_inst.prot_p.assert_called_once()
    assert result is ftp_inst


def test_connect_anonymous():
    cfg = make_cfg(username="", password="")

    with patch("snaffler.transport.ftp.ftplib") as mock_ftplib:
        ftp_inst = MagicMock()
        mock_ftplib.FTP.return_value = ftp_inst

        transport = FTPTransport(cfg)
        transport.connect("10.0.0.5")

    ftp_inst.login.assert_called_once_with("anonymous", "")


def test_connect_custom_port():
    cfg = make_cfg()

    with patch("snaffler.transport.ftp.ftplib") as mock_ftplib:
        ftp_inst = MagicMock()
        mock_ftplib.FTP.return_value = ftp_inst

        transport = FTPTransport(cfg)
        transport.connect("10.0.0.5", 2121)

    ftp_inst.connect.assert_called_once_with("10.0.0.5", 2121)


def test_connect_custom_timeout():
    cfg = make_cfg(timeout=30)

    with patch("snaffler.transport.ftp.ftplib") as mock_ftplib:
        ftp_inst = MagicMock()
        mock_ftplib.FTP.return_value = ftp_inst

        transport = FTPTransport(cfg)
        transport.connect("10.0.0.5")

    mock_ftplib.FTP.assert_called_once_with(timeout=30)


def test_connect_none_username_becomes_anonymous():
    cfg = make_cfg(username=None, password=None)

    with patch("snaffler.transport.ftp.ftplib") as mock_ftplib:
        ftp_inst = MagicMock()
        mock_ftplib.FTP.return_value = ftp_inst

        transport = FTPTransport(cfg)
        transport.connect("10.0.0.5")

    ftp_inst.login.assert_called_once_with("anonymous", "")


# ---------- socket leak prevention on intermediate failure ----------

def test_connect_login_failure_closes_socket():
    """If login() fails after connect(), the TCP socket must be closed."""
    cfg = make_cfg()

    with patch("snaffler.transport.ftp.ftplib") as mock_ftplib:
        ftp_inst = MagicMock()
        mock_ftplib.FTP.return_value = ftp_inst
        ftp_inst.login.side_effect = Exception("530 Login incorrect")

        transport = FTPTransport(cfg)
        with pytest.raises(Exception, match="530 Login incorrect"):
            transport.connect("10.0.0.5")

    # quit() is tried first for graceful close
    ftp_inst.quit.assert_called_once()


def test_connect_prot_p_failure_closes_socket():
    """If prot_p() fails after login, the TCP socket must be closed."""
    cfg = make_cfg(tls=True)

    with patch("snaffler.transport.ftp.ftplib") as mock_ftplib:
        ftp_inst = MagicMock()
        mock_ftplib.FTP_TLS.return_value = ftp_inst
        ftp_inst.prot_p.side_effect = Exception("TLS handshake failed")

        transport = FTPTransport(cfg)
        with pytest.raises(Exception, match="TLS handshake failed"):
            transport.connect("10.0.0.5")

    ftp_inst.quit.assert_called_once()


def test_connect_type_i_failure_closes_socket():
    """If TYPE I fails after login, the TCP socket must be closed."""
    cfg = make_cfg()

    with patch("snaffler.transport.ftp.ftplib") as mock_ftplib:
        ftp_inst = MagicMock()
        mock_ftplib.FTP.return_value = ftp_inst
        ftp_inst.sendcmd.side_effect = Exception("500 TYPE not supported")

        transport = FTPTransport(cfg)
        with pytest.raises(Exception, match="500 TYPE not supported"):
            transport.connect("10.0.0.5")

    ftp_inst.quit.assert_called_once()


def test_connect_quit_failure_falls_back_to_close():
    """If quit() itself fails during cleanup, close() is used as fallback."""
    cfg = make_cfg()

    with patch("snaffler.transport.ftp.ftplib") as mock_ftplib:
        ftp_inst = MagicMock()
        mock_ftplib.FTP.return_value = ftp_inst
        ftp_inst.login.side_effect = Exception("530 Login incorrect")
        ftp_inst.quit.side_effect = Exception("already disconnected")

        transport = FTPTransport(cfg)
        with pytest.raises(Exception, match="530 Login incorrect"):
            transport.connect("10.0.0.5")

    ftp_inst.quit.assert_called_once()
    ftp_inst.close.assert_called_once()
