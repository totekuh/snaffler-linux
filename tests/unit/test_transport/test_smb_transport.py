from unittest.mock import MagicMock, patch

from snaffler.transport.smb import SMBTransport


# ---------- helpers ----------

def make_cfg():
    cfg = MagicMock()

    cfg.auth.username = "user"
    cfg.auth.password = "pass"
    cfg.auth.domain = "example.com"
    cfg.auth.nthash = None
    cfg.auth.kerberos = False
    cfg.auth.dc_host = None
    cfg.auth.use_kcache = False
    cfg.auth.smb_timeout = 30

    return cfg


# ---------- tests ----------

def test_smb_connect_uses_default_timeout():
    cfg = make_cfg()

    with patch("snaffler.transport.smb.SMBConnection") as smb_cls:
        smb = smb_cls.return_value

        transport = SMBTransport(cfg)
        result = transport.connect("TARGET")

    smb_cls.assert_called_once_with(
        remoteName="TARGET",
        remoteHost="TARGET",
        sess_port=445,
        timeout=30,
    )
    assert result is smb


def test_smb_connect_custom_timeout():
    cfg = make_cfg()

    with patch("snaffler.transport.smb.SMBConnection") as smb_cls:
        transport = SMBTransport(cfg)
        transport.connect("TARGET", timeout=10)

    smb_cls.assert_called_once_with(
        remoteName="TARGET",
        remoteHost="TARGET",
        sess_port=445,
        timeout=10,
    )


def test_smb_kerberos_login():
    cfg = make_cfg()
    cfg.auth.kerberos = True
    cfg.auth.nthash = "NTHASH"

    with patch("snaffler.transport.smb.SMBConnection") as smb_cls:
        smb = smb_cls.return_value

        transport = SMBTransport(cfg)
        result = transport.connect("TARGET")

    smb.kerberosLogin.assert_called_once_with(
        user="user",
        password="pass",
        domain="example.com",
        lmhash="",
        nthash="NTHASH",
        aesKey=None,
        kdcHost=None,
        useCache=False,
    )
    assert result is smb


def test_smb_ntlm_with_nthash():
    cfg = make_cfg()
    cfg.auth.nthash = "NTHASH"

    with patch("snaffler.transport.smb.SMBConnection") as smb_cls:
        smb = smb_cls.return_value

        transport = SMBTransport(cfg)
        result = transport.connect("TARGET")

    smb.login.assert_called_once_with(
        "user",
        "",
        "example.com",
        "",
        "NTHASH",
    )
    assert result is smb


def test_smb_ntlm_with_password():
    cfg = make_cfg()

    with patch("snaffler.transport.smb.SMBConnection") as smb_cls:
        smb = smb_cls.return_value

        transport = SMBTransport(cfg)
        result = transport.connect("TARGET")

    smb.login.assert_called_once_with(
        "user",
        "pass",
        "example.com",
    )
    assert result is smb
