from unittest.mock import MagicMock, patch

from impacket.smbconnection import SessionError

from snaffler.discovery.shares import ShareFinder, ShareInfo, share_matches_filter


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
    cfg.targets.share_filter = []
    cfg.targets.exclude_share = []

    cfg.rules.share = []

    return cfg


def make_smb(shares=None, readable=True):
    smb = MagicMock()

    if shares is not None:
        smb.listShares.return_value = shares

    if readable:
        smb.listPath.return_value = []
    else:
        smb.listPath.side_effect = SessionError(0, "denied")

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
    connect.assert_called_once_with("HOST", timeout=cfg.auth.smb_timeout)


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


def test_enumerate_shares():
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
        shares = finder.enumerate_shares("HOST")

    assert len(shares) == 1
    assert shares[0].name == "DATA$"
    assert isinstance(shares[0], ShareInfo)


def test_enumerate_shares_session_error():
    cfg = make_cfg()
    finder = ShareFinder(cfg)

    smb = MagicMock()
    smb.listShares.side_effect = SessionError(0, "access denied")

    with patch.object(finder, "_get_smb", return_value=smb):
        shares = finder.enumerate_shares("HOST")

    assert shares == []


def test_is_share_readable_true():
    cfg = make_cfg()
    finder = ShareFinder(cfg)

    smb = make_smb(readable=True)

    with patch.object(finder, "_get_smb", return_value=smb):
        assert finder.is_share_readable("HOST", "DATA") is True

    smb.listPath.assert_called_once_with("DATA", "*")


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

    with patch.object(
        finder, "enumerate_shares", return_value=[share]
    ), patch.object(
        finder, "is_share_readable", return_value=True
    ):
        result = finder.get_computer_shares("HOST")

    assert result == [("//HOST/DATA", share)]


def test_get_computer_shares_never_scan():
    cfg = make_cfg()
    finder = ShareFinder(cfg)

    ipc = ShareInfo("IPC$", 0, "")
    data = ShareInfo("DATA", 0, "Data")

    with patch.object(
        finder, "enumerate_shares", return_value=[ipc, data]
    ), patch.object(
        finder, "is_share_readable", return_value=True
    ):
        result = finder.get_computer_shares("HOST")

    # IPC$ should be skipped
    assert len(result) == 1
    assert result[0][0] == "//HOST/DATA"


def test_get_computer_shares_no_shares():
    cfg = make_cfg()
    finder = ShareFinder(cfg)

    with patch.object(
        finder, "enumerate_shares", return_value=[]
    ):
        result = finder.get_computer_shares("HOST")

    assert result == []


# ---------- share_matches_filter ----------

def test_filter_no_patterns_allows_all():
    assert share_matches_filter("DATA", [], []) is True
    assert share_matches_filter("IPC$", [], []) is True


def test_filter_include_matches():
    assert share_matches_filter("IT_Share", ["IT*"], []) is True
    assert share_matches_filter("HR_Share", ["IT*"], []) is False


def test_filter_include_multiple_patterns():
    assert share_matches_filter("IT_Share", ["IT*", "HR*"], []) is True
    assert share_matches_filter("HR_Share", ["IT*", "HR*"], []) is True
    assert share_matches_filter("Finance", ["IT*", "HR*"], []) is False


def test_filter_exclude_matches():
    assert share_matches_filter("IPC$", [], ["IPC$"]) is False
    assert share_matches_filter("DATA", [], ["IPC$"]) is True


def test_filter_exclude_multiple_patterns():
    assert share_matches_filter("IPC$", [], ["IPC$", "print$"]) is False
    assert share_matches_filter("print$", [], ["IPC$", "print$"]) is False
    assert share_matches_filter("DATA", [], ["IPC$", "print$"]) is True


def test_filter_include_then_exclude():
    """Include applied first, then exclude."""
    # HR_Share matches include, but HR_Archive* matches exclude
    assert share_matches_filter("HR_Data", ["HR*"], ["HR_Archive*"]) is True
    assert share_matches_filter("HR_Archive_2024", ["HR*"], ["HR_Archive*"]) is False


def test_filter_case_insensitive():
    assert share_matches_filter("DATA", ["data"], []) is True
    assert share_matches_filter("data", ["DATA"], []) is True
    assert share_matches_filter("Data", [], ["data"]) is False
    assert share_matches_filter("DATA", [], ["data"]) is False


def test_filter_glob_wildcards():
    assert share_matches_filter("Users$", ["*$"], []) is True
    assert share_matches_filter("Users", ["*$"], []) is False
    assert share_matches_filter("backup-2024", ["backup-????"], []) is True
    assert share_matches_filter("backup-24", ["backup-????"], []) is False


def test_filter_exact_match():
    assert share_matches_filter("DATA", ["DATA"], []) is True
    assert share_matches_filter("DATA", ["NOTDATA"], []) is False


# ---------- ShareFinder with share filters ----------

def test_get_computer_shares_include_filter():
    cfg = make_cfg()
    cfg.targets.share_filter = ["IT*"]
    finder = ShareFinder(cfg)

    it_share = ShareInfo("IT_Data", 0, "")
    hr_share = ShareInfo("HR_Data", 0, "")

    with patch.object(
        finder, "enumerate_shares", return_value=[it_share, hr_share]
    ), patch.object(
        finder, "is_share_readable", return_value=True
    ):
        result = finder.get_computer_shares("HOST")

    assert len(result) == 1
    assert result[0][0] == "//HOST/IT_Data"


def test_get_computer_shares_exclude_filter():
    cfg = make_cfg()
    cfg.targets.exclude_share = ["*Archive*"]
    finder = ShareFinder(cfg)

    data = ShareInfo("DATA", 0, "")
    archive = ShareInfo("HR_Archive", 0, "")

    with patch.object(
        finder, "enumerate_shares", return_value=[data, archive]
    ), patch.object(
        finder, "is_share_readable", return_value=True
    ):
        result = finder.get_computer_shares("HOST")

    assert len(result) == 1
    assert result[0][0] == "//HOST/DATA"


def test_get_computer_shares_include_and_exclude():
    cfg = make_cfg()
    cfg.targets.share_filter = ["HR*"]
    cfg.targets.exclude_share = ["HR_Archive*"]
    finder = ShareFinder(cfg)

    hr_data = ShareInfo("HR_Data", 0, "")
    hr_archive = ShareInfo("HR_Archive", 0, "")
    finance = ShareInfo("Finance", 0, "")

    with patch.object(
        finder, "enumerate_shares", return_value=[hr_data, hr_archive, finance]
    ), patch.object(
        finder, "is_share_readable", return_value=True
    ):
        result = finder.get_computer_shares("HOST")

    # Only HR_Data passes: Finance excluded by include filter, HR_Archive excluded by exclude
    assert len(result) == 1
    assert result[0][0] == "//HOST/HR_Data"


def test_get_computer_shares_filter_excludes_all():
    cfg = make_cfg()
    cfg.targets.share_filter = ["NonExistent*"]
    finder = ShareFinder(cfg)

    data = ShareInfo("DATA", 0, "")

    with patch.object(
        finder, "enumerate_shares", return_value=[data]
    ), patch.object(
        finder, "is_share_readable", return_value=True
    ):
        result = finder.get_computer_shares("HOST")

    assert result == []


def test_get_computer_shares_filter_case_insensitive():
    cfg = make_cfg()
    cfg.targets.share_filter = ["data"]
    finder = ShareFinder(cfg)

    share = ShareInfo("DATA", 0, "")

    with patch.object(
        finder, "enumerate_shares", return_value=[share]
    ), patch.object(
        finder, "is_share_readable", return_value=True
    ):
        result = finder.get_computer_shares("HOST")

    assert len(result) == 1
    assert result[0][0] == "//HOST/DATA"
