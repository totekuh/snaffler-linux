from unittest.mock import MagicMock, patch

from impacket.smbconnection import SessionError
from impacket.dcerpc.v5 import srvs

from snaffler.discovery.shares import ShareFinder, ShareInfo
from snaffler.classifiers.rules import (
    ClassifierRule,
    EnumerationScope,
    MatchAction,
    MatchListType,
    MatchLocation,
    Triage,
)


# ============================================================================
# Test Helpers
# ============================================================================

def make_cfg():
    """Create a mock configuration for testing"""
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
    """Create a mock SMB connection"""
    smb = MagicMock()
    if shares is not None:
        smb.listShares.return_value = shares
    if readable:
        smb.connectTree.return_value = 1
    else:
        smb.connectTree.side_effect = SessionError(0, "denied")
    return smb


def make_rpc_share_response(shares_data):
    """Create a mock RPC response for NetShareEnum.

    Args:
        shares_data: list of (name, type, remark) tuples
    """
    buffer = []
    for name, share_type, remark in shares_data:
        buffer.append({
            'shi1_netname': name + '\x00',
            'shi1_type': share_type,
            'shi1_remark': (remark + '\x00') if remark else None,
        })
    return {
        'InfoStruct': {
            'ShareInfo': {
                'Level1': {
                    'Buffer': buffer
                }
            }
        }
    }


# ============================================================================
# Connection Management Tests
# ============================================================================

def test_get_smb_cached():
    """SMB connections should be cached per host"""
    cfg = make_cfg()
    finder = ShareFinder(cfg)
    smb = MagicMock()

    with patch.object(finder.smb_transport, "connect", return_value=smb) as connect:
        a = finder._get_smb("HOST")
        b = finder._get_smb("HOST")

    assert a is b
    connect.assert_called_once_with("HOST", timeout=10)


def test_get_smb_reconnect_on_dead():
    """Dead connections should be detected and reconnected"""
    cfg = make_cfg()
    finder = ShareFinder(cfg)

    smb_dead = MagicMock()
    smb_dead.getServerName.side_effect = Exception("dead")
    smb_new = MagicMock()

    with patch.object(finder.smb_transport, "connect", side_effect=[smb_dead, smb_new]):
        a = finder._get_smb("HOST")
        b = finder._get_smb("HOST")

    assert b is smb_new


def test_get_smb_different_hosts():
    """Different hosts should have separate connections"""
    cfg = make_cfg()
    finder = ShareFinder(cfg)
    smb1, smb2 = MagicMock(), MagicMock()

    with patch.object(finder.smb_transport, "connect", side_effect=[smb1, smb2]):
        a = finder._get_smb("HOST1")
        b = finder._get_smb("HOST2")

    assert a is smb1 and b is smb2


# ============================================================================
# RPC Share Enumeration Tests
# ============================================================================

def test_enumerate_shares_rpc_success():
    """RPC enumeration should return all shares with proper cleanup"""
    cfg = make_cfg()
    finder = ShareFinder(cfg)

    mock_dce = MagicMock()
    mock_transport = MagicMock()
    mock_transport.get_dce_rpc.return_value = mock_dce

    rpc_response = make_rpc_share_response([
        ("C$", 0, "Default share"),
        ("ADMIN$", 0x80000000, "Remote Admin"),
        ("DATA", 0, "User data"),
    ])

    with patch('snaffler.discovery.shares.transport.DCERPCTransportFactory',
               return_value=mock_transport), \
         patch('snaffler.discovery.shares.srvs.hNetrShareEnum',
               return_value=rpc_response):

        shares = finder.enumerate_shares_rpc("192.168.1.10")

    assert len(shares) == 3
    assert shares[0].name == "C$"
    assert shares[0].share_type == 0
    assert shares[1].name == "ADMIN$"
    mock_dce.connect.assert_called_once()
    mock_dce.disconnect.assert_called_once()


def test_enumerate_shares_rpc_with_nthash():
    """RPC enumeration should use NT hash when provided"""
    cfg = make_cfg()
    cfg.auth.nthash = "aad3b435b51404eeaad3b435b51404ee"
    finder = ShareFinder(cfg)

    mock_transport = MagicMock()
    mock_transport.get_dce_rpc.return_value = MagicMock()

    with patch('snaffler.discovery.shares.transport.DCERPCTransportFactory',
               return_value=mock_transport), \
         patch('snaffler.discovery.shares.srvs.hNetrShareEnum',
               return_value=make_rpc_share_response([("DATA", 0, "")])):

        finder.enumerate_shares_rpc("HOST")

        mock_transport.set_credentials.assert_called_once_with(
            "user", "pass", "example.com", "", "aad3b435b51404eeaad3b435b51404ee"
        )


def test_enumerate_shares_rpc_failures():
    """RPC enumeration should return empty list on any failure"""
    cfg = make_cfg()
    finder = ShareFinder(cfg)

    # Test connection failure
    with patch('snaffler.discovery.shares.transport.DCERPCTransportFactory',
               side_effect=Exception("Connection refused")):
        assert finder.enumerate_shares_rpc("HOST") == []

    # Test bind failure
    mock_dce = MagicMock()
    mock_dce.bind.side_effect = Exception("Access denied")
    mock_transport = MagicMock()
    mock_transport.get_dce_rpc.return_value = mock_dce

    with patch('snaffler.discovery.shares.transport.DCERPCTransportFactory',
               return_value=mock_transport):
        assert finder.enumerate_shares_rpc("HOST") == []


# ============================================================================
# SMB Share Enumeration Tests
# ============================================================================

def test_enumerate_shares_smb_multiple():
    """SMB enumeration should handle multiple shares and null remarks"""
    cfg = make_cfg()
    finder = ShareFinder(cfg)

    smb = make_smb(shares=[
        {"shi1_netname": "C$\x00", "shi1_type": 0, "shi1_remark": "Admin\x00"},
        {"shi1_netname": "DATA\x00", "shi1_type": 0, "shi1_remark": "Files\x00"},
        {"shi1_netname": "BACKUP\x00", "shi1_type": 0, "shi1_remark": None},
    ])

    with patch.object(finder, "_get_smb", return_value=smb):
        shares = finder.enumerate_shares_smb("HOST")

    assert len(shares) == 3
    assert shares[0].name == "C$"
    assert shares[0].remark == "Admin"
    assert shares[2].remark == ""  # None remark becomes empty string


def test_enumerate_shares_smb_error():
    """SMB enumeration should return empty list on error"""
    cfg = make_cfg()
    finder = ShareFinder(cfg)
    smb = MagicMock()
    smb.listShares.side_effect = Exception("Network error")

    with patch.object(finder, "_get_smb", return_value=smb):
        assert finder.enumerate_shares_smb("HOST") == []


# ============================================================================
# Share Classification Tests
# ============================================================================

def test_classify_share_discard_rule():
    """DISCARD rules should prevent share scanning"""
    cfg = make_cfg()
    cfg.rules.share = [ClassifierRule(
        rule_name="DiscardPrintShares",
        enumeration_scope=EnumerationScope.SHARE_ENUMERATION,
        match_action=MatchAction.DISCARD,
        match_location=MatchLocation.SHARE_NAME,
        wordlist_type=MatchListType.REGEX,
        wordlist=[r".*PRINT.*"],
        triage=Triage.GREEN,
    )]
    finder = ShareFinder(cfg)

    assert finder._classify_share("//HOST/PRINT$") is True
    assert finder._classify_share("//HOST/PRINTSERVER") is True
    assert finder._classify_share("//HOST/DATA") is False


def test_classify_share_snaffle_rule():
    """SNAFFLE rules should log interesting shares but not discard them"""
    cfg = make_cfg()
    cfg.rules.share = [ClassifierRule(
        rule_name="InterestingShare",
        enumeration_scope=EnumerationScope.SHARE_ENUMERATION,
        match_action=MatchAction.SNAFFLE,
        match_location=MatchLocation.SHARE_NAME,
        wordlist_type=MatchListType.CONTAINS,
        wordlist=["BACKUP"],
        triage=Triage.RED,
    )]
    finder = ShareFinder(cfg)

    with patch.object(finder, "is_share_readable", return_value=True):
        assert finder._classify_share("//HOST/BACKUP") is False


def test_classify_share_wrong_location():
    """Classifiers should ignore rules for wrong match location"""
    cfg = make_cfg()
    cfg.rules.share = [ClassifierRule(
        rule_name="FileRule",
        enumeration_scope=EnumerationScope.FILE_ENUMERATION,
        match_action=MatchAction.DISCARD,
        match_location=MatchLocation.FILE_NAME,
        wordlist_type=MatchListType.REGEX,
        wordlist=[r".*"],
        triage=Triage.GREEN,
    )]
    finder = ShareFinder(cfg)

    assert finder._classify_share("//HOST/ANYTHING") is False


# ============================================================================
# Share Readability Tests
# ============================================================================

def test_is_share_readable_never_scan():
    """IPC$ and PRINT$ should always be unreadable"""
    cfg = make_cfg()
    finder = ShareFinder(cfg)

    assert finder.is_share_readable("HOST", "IPC$") is False
    assert finder.is_share_readable("HOST", "PRINT$") is False


def test_is_share_readable_error_handling():
    """Share readability errors should return False"""
    cfg = make_cfg()
    finder = ShareFinder(cfg)

    # SessionError
    smb = MagicMock()
    smb.connectTree.side_effect = SessionError(0xc0000022, "Access denied")
    with patch.object(finder, "_get_smb", return_value=smb):
        assert finder.is_share_readable("HOST", "PROTECTED") is False

    # Generic exception
    smb = MagicMock()
    smb.connectTree.side_effect = Exception("Network unreachable")
    with patch.object(finder, "_get_smb", return_value=smb):
        assert finder.is_share_readable("HOST", "DATA") is False


def test_is_share_readable_success():
    """Readable shares should properly connect and disconnect"""
    cfg = make_cfg()
    finder = ShareFinder(cfg)
    smb = MagicMock()
    smb.connectTree.return_value = 12345

    with patch.object(finder, "_get_smb", return_value=smb):
        result = finder.is_share_readable("HOST", "DATA")

    assert result is True
    smb.connectTree.assert_called_once_with("DATA")
    smb.disconnectTree.assert_called_once_with(12345)


# ============================================================================
# get_computer_shares Integration Tests
# ============================================================================

def test_get_computer_shares_rpc_fallback():
    """SMB should be used when RPC returns no shares"""
    cfg = make_cfg()
    finder = ShareFinder(cfg)
    share = ShareInfo("DATA", 0, "Files")

    with patch.object(finder, "enumerate_shares_rpc", return_value=[]) as rpc_enum, \
         patch.object(finder, "enumerate_shares_smb", return_value=[share]) as smb_enum, \
         patch.object(finder, "is_share_readable", return_value=True):

        result = finder.get_computer_shares("HOST")

    rpc_enum.assert_called_once()
    smb_enum.assert_called_once()
    assert len(result) == 1


def test_get_computer_shares_rpc_success():
    """SMB should not be called when RPC succeeds"""
    cfg = make_cfg()
    finder = ShareFinder(cfg)
    share = ShareInfo("DATA", 0, "Files")

    with patch.object(finder, "enumerate_shares_rpc", return_value=[share]) as rpc_enum, \
         patch.object(finder, "enumerate_shares_smb") as smb_enum, \
         patch.object(finder, "is_share_readable", return_value=True):

        result = finder.get_computer_shares("HOST")

    rpc_enum.assert_called_once()
    smb_enum.assert_not_called()
    assert len(result) == 1


def test_get_computer_shares_never_scan():
    """IPC$ and PRINT$ should always be filtered"""
    cfg = make_cfg()
    finder = ShareFinder(cfg)

    with patch.object(finder, "enumerate_shares_rpc",
                     return_value=[ShareInfo("IPC$", 0, ""), ShareInfo("PRINT$", 1, "")]):
        assert finder.get_computer_shares("HOST") == []


def test_get_computer_shares_mixed_readable():
    """Only readable shares should be returned"""
    cfg = make_cfg()
    finder = ShareFinder(cfg)
    shares = [
        ShareInfo("PUBLIC", 0, "Public"),
        ShareInfo("PRIVATE", 0, "Private"),
        ShareInfo("SHARED", 0, "Shared"),
    ]

    def mock_readable(computer, share_name):
        return share_name in ["PUBLIC", "SHARED"]

    with patch.object(finder, "enumerate_shares_rpc", return_value=shares), \
         patch.object(finder, "is_share_readable", side_effect=mock_readable):

        result = finder.get_computer_shares("HOST")

    assert len(result) == 2
    assert result[0][0] == "//HOST/PUBLIC"
    assert result[1][0] == "//HOST/SHARED"


def test_get_computer_shares_classifier_discard():
    """Shares matching DISCARD rules should be filtered"""
    cfg = make_cfg()
    cfg.rules.share = [ClassifierRule(
        rule_name="DiscardPrint",
        enumeration_scope=EnumerationScope.SHARE_ENUMERATION,
        match_action=MatchAction.DISCARD,
        match_location=MatchLocation.SHARE_NAME,
        wordlist_type=MatchListType.CONTAINS,
        wordlist=["PRINT"],
        triage=Triage.GREEN,
    )]
    finder = ShareFinder(cfg)

    with patch.object(finder, "enumerate_shares_rpc",
                     return_value=[ShareInfo("PRINT$", 0, "")]):
        assert finder.get_computer_shares("HOST") == []


# ============================================================================
# SYSVOL/NETLOGON Replica Handling Tests
# ============================================================================

def test_sysvol_replica_handling():
    """Only first SYSVOL replica should be scanned"""
    cfg = make_cfg()
    cfg.targets.scan_sysvol = True
    finder = ShareFinder(cfg)
    sysvol = ShareInfo("SYSVOL", 0, "")

    # First replica - should scan
    with patch.object(finder, "enumerate_shares_rpc", return_value=[sysvol]), \
         patch.object(finder, "is_share_readable", return_value=True):
        result = finder.get_computer_shares("DC01")

    assert len(result) == 1
    assert result[0][0] == "//DC01/SYSVOL"
    assert cfg.targets.scan_sysvol is False

    # Second replica - should skip
    with patch.object(finder, "enumerate_shares_rpc", return_value=[sysvol]):
        result = finder.get_computer_shares("DC02")
    assert len(result) == 0


def test_netlogon_replica_handling():
    """Only first NETLOGON replica should be scanned"""
    cfg = make_cfg()
    cfg.targets.scan_netlogon = True
    finder = ShareFinder(cfg)
    netlogon = ShareInfo("NETLOGON", 0, "")

    # First replica
    with patch.object(finder, "enumerate_shares_rpc", return_value=[netlogon]), \
         patch.object(finder, "is_share_readable", return_value=True):
        result = finder.get_computer_shares("DC01")

    assert len(result) == 1
    assert cfg.targets.scan_netlogon is False

    # Second replica
    with patch.object(finder, "enumerate_shares_rpc", return_value=[netlogon]):
        assert finder.get_computer_shares("DC02") == []


def test_sysvol_bypasses_classifiers():
    """SYSVOL should bypass share classifiers"""
    cfg = make_cfg()
    cfg.targets.scan_sysvol = True
    cfg.rules.share = [ClassifierRule(
        rule_name="DiscardAll",
        enumeration_scope=EnumerationScope.SHARE_ENUMERATION,
        match_action=MatchAction.DISCARD,
        match_location=MatchLocation.SHARE_NAME,
        wordlist_type=MatchListType.REGEX,
        wordlist=[r".*"],
        triage=Triage.GREEN,
    )]
    finder = ShareFinder(cfg)
    sysvol = ShareInfo("SYSVOL", 0, "")

    with patch.object(finder, "enumerate_shares_rpc", return_value=[sysvol]), \
         patch.object(finder, "is_share_readable", return_value=True):
        result = finder.get_computer_shares("DC01")

    assert len(result) == 1


# ============================================================================
# ShareInfo Class Tests
# ============================================================================

def test_shareinfo_repr():
    """ShareInfo __repr__ should include all important fields"""
    share = ShareInfo("DATA", 0, "User files")
    repr_str = repr(share)

    assert "ShareInfo" in repr_str
    assert "name=DATA" in repr_str
    assert "type=0" in repr_str


def test_shareinfo_defaults():
    """ShareInfo should have correct default values"""
    share = ShareInfo("TEST", 0, "")

    assert share.name == "TEST"
    assert share.share_type == 0
    assert share.remark == ""
    assert share.readable is False
    assert share.writable is False


# ============================================================================
# Initialization Tests
# ============================================================================

def test_init_null_session_warning():
    """Warning should be logged when no credentials provided"""
    cfg = make_cfg()
    cfg.auth.username = None
    cfg.auth.password = None
    cfg.auth.nthash = None
    cfg.auth.kerberos = False

    with patch('snaffler.discovery.shares.logger') as mock_logger:
        ShareFinder(cfg)
        mock_logger.warning.assert_called_once()
        assert "NULL session" in mock_logger.warning.call_args[0][0]


def test_init_with_credentials():
    """No warning should be logged when credentials provided"""
    cfg = make_cfg()

    with patch('snaffler.discovery.shares.logger') as mock_logger:
        ShareFinder(cfg)
        mock_logger.warning.assert_not_called()


def test_init_with_kerberos():
    """No warning should be logged when Kerberos enabled"""
    cfg = make_cfg()
    cfg.auth.username = None
    cfg.auth.password = None
    cfg.auth.nthash = None
    cfg.auth.kerberos = True

    with patch('snaffler.discovery.shares.logger') as mock_logger:
        ShareFinder(cfg)
        mock_logger.warning.assert_not_called()
