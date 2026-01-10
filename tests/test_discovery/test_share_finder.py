from unittest.mock import MagicMock, patch

from impacket.smbconnection import SessionError

from snaffler.discovery.shares import ShareFinder, ShareInfo


# ---------- helpers ----------

def make_cfg():
    cfg = MagicMock()

    cfg.auth.username = "user"
    cfg.auth.password = "pass"
    cfg.auth.domain = "example.com"
    cfg.auth.nthash = None
    cfg.auth.kerberos = False

    cfg.targets.scan_sysvol = True
    cfg.targets.scan_netlogon = True

    cfg.rules.share = []

    return cfg


def make_smb(shares=None, readable=True):
    smb = MagicMock()

    if shares is not None:
        smb.listShares.return_value = shares

    if readable:
        smb.connectTree.return_value = 1
    else:
        smb.connectTree.side_effect = SessionError(0, "denied")

    return smb


# ---------- tests ----------

def test_get_smb_cached():
    cfg = make_cfg()
    finder = ShareFinder(cfg)

    smb = MagicMock()

    with patch.object(
            finder.smb_transport, "connect", return_value=smb
    ) as connect:
        a = finder._get_smb("HOST")
        b = finder._get_smb("HOST")

    assert a is b
    connect.assert_called_once_with("HOST", timeout=10)


def test_get_smb_reconnect_on_dead():
    cfg = make_cfg()
    finder = ShareFinder(cfg)

    smb_dead = MagicMock()
    smb_dead.getServerName.side_effect = Exception("dead")

    smb_new = MagicMock()

    with patch.object(
        finder.smb_transport,
        "connect",
        side_effect=[smb_dead, smb_new],
    ):
        a = finder._get_smb("HOST")
        b = finder._get_smb("HOST")

    assert b is smb_new


def test_enumerate_shares_smb():
    cfg = make_cfg()
    finder = ShareFinder(cfg)

    smb = make_smb(
        shares=[
            {
                "shi1_netname": "DATA$\x00",
                "shi1_type": 0,
                "shi1_remark": "Data\x00",
            }
        ]
    )

    with patch.object(finder, "_get_smb", return_value=smb):
        shares = finder.enumerate_shares_smb("HOST")

    assert len(shares) == 1
    assert shares[0].name == "DATA$"
    assert isinstance(shares[0], ShareInfo)


def test_is_share_readable_true():
    cfg = make_cfg()
    finder = ShareFinder(cfg)

    smb = make_smb(readable=True)

    with patch.object(finder, "_get_smb", return_value=smb):
        assert finder.is_share_readable("HOST", "DATA") is True


def test_is_share_readable_false():
    cfg = make_cfg()
    finder = ShareFinder(cfg)

    smb = make_smb(readable=False)

    with patch.object(finder, "_get_smb", return_value=smb):
        assert finder.is_share_readable("HOST", "DATA") is False


def test_get_computer_shares_basic():
    cfg = make_cfg()
    finder = ShareFinder(cfg)

    share = ShareInfo("DATA", 0, "Data")
    share.readable = True

    with patch.object(
        finder, "enumerate_shares_rpc", return_value=[]
    ), patch.object(
        finder, "enumerate_shares_smb", return_value=[share]
    ), patch.object(
        finder, "is_share_readable", return_value=True
    ):
        result = finder.get_computer_shares("HOST")

    assert result == [("//HOST/DATA", share)]


def test_get_computer_shares_never_scan():
    cfg = make_cfg()
    finder = ShareFinder(cfg)

    share = ShareInfo("IPC$", 0, "")

    with patch.object(
        finder, "enumerate_shares_rpc", return_value=[share]
    ):
        result = finder.get_computer_shares("HOST")

    assert result == []
