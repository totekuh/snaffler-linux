import threading
from unittest.mock import MagicMock, patch

import pytest

from snaffler.discovery.tree import TreeWalker
from snaffler.classifiers.rules import MatchAction, EnumerationScope, MatchLocation


# ---------- helpers ----------

class FakeEntry:
    def __init__(self, name, is_dir, size=100, mtime=1700000000.0):
        self._name = name
        self._is_dir = is_dir
        self._size = size
        self._mtime = mtime

    def get_longname(self):
        return self._name

    def is_directory(self):
        return self._is_dir

    def get_filesize(self):
        return self._size

    def get_mtime_epoch(self):
        return self._mtime


def make_cfg():
    cfg = MagicMock()
    cfg.rules.directory = []
    return cfg


def make_rule(action):
    rule = MagicMock()
    rule.enumeration_scope = EnumerationScope.DIRECTORY_ENUMERATION
    rule.match_location = MatchLocation.FILE_PATH
    rule.match_action = action
    rule.rule_name = "RULE"
    rule.triage.value = "HIGH"
    rule.matches.return_value = True
    return rule


def collect_callback():
    """Return (callback, collected_list) for use with walk_directory on_file."""
    collected = []
    def on_file(path, size, mtime):
        collected.append((path, size, mtime))
    return on_file, collected


def collect_dir_callback():
    """Return (callback, collected_list) for use with walk_directory on_dir."""
    collected = []
    def on_dir(path):
        collected.append(path)
    return on_dir, collected


# ---------- _should_scan_directory tests ----------

def test_should_scan_directory_discard():
    cfg = make_cfg()
    rule = make_rule(MatchAction.DISCARD)
    cfg.rules.directory = [rule]

    walker = TreeWalker(cfg)

    assert walker._should_scan_directory("//HOST/SHARE/dir") is False


def test_should_scan_directory_snaffle():
    cfg = make_cfg()
    rule = make_rule(MatchAction.SNAFFLE)
    cfg.rules.directory = [rule]

    walker = TreeWalker(cfg)

    assert walker._should_scan_directory("//HOST/SHARE/dir") is True


def test_should_scan_directory_exclude_dir_match():
    """--exclude-dir glob blocks matching directories."""
    cfg = make_cfg()
    cfg.targets.exclude_dir = ["*/C$/Windows"]

    walker = TreeWalker(cfg)

    assert walker._should_scan_directory("//HOST/C$/Windows") is False


def test_should_scan_directory_exclude_dir_no_match():
    """--exclude-dir glob does not block non-matching directories."""
    cfg = make_cfg()
    cfg.targets.exclude_dir = ["*/C$/Windows"]

    walker = TreeWalker(cfg)

    assert walker._should_scan_directory("//HOST/C$/Users") is True


def test_should_scan_directory_exclude_dir_case_insensitive():
    """--exclude-dir matching is case-insensitive."""
    cfg = make_cfg()
    cfg.targets.exclude_dir = ["*/C$/WINDOWS"]

    walker = TreeWalker(cfg)

    assert walker._should_scan_directory("//HOST/C$/windows") is False
    assert walker._should_scan_directory("//HOST/C$/Windows") is False


def test_should_scan_directory_exclude_dir_multiple_patterns():
    """Multiple --exclude-dir patterns are OR'd together."""
    cfg = make_cfg()
    cfg.targets.exclude_dir = ["*/C$/Windows", "*/C$/ProgramData"]

    walker = TreeWalker(cfg)

    assert walker._should_scan_directory("//HOST/C$/Windows") is False
    assert walker._should_scan_directory("//HOST/C$/ProgramData") is False
    assert walker._should_scan_directory("//HOST/C$/Users") is True


def test_should_scan_directory_exclude_dir_recursive_glob():
    """--exclude-dir with recursive glob pattern."""
    cfg = make_cfg()
    cfg.targets.exclude_dir = ["*/C$/Windows*"]

    walker = TreeWalker(cfg)

    assert walker._should_scan_directory("//HOST/C$/Windows") is False
    assert walker._should_scan_directory("//HOST/C$/Windows.old") is False
    assert walker._should_scan_directory("//HOST/C$/Users") is True


# ---------- connection caching tests ----------

def test_connection_reuse_same_server():
    """Two walk_directory() calls to the same server should reuse the connection."""
    cfg = make_cfg()
    walker = TreeWalker(cfg)

    smb = MagicMock()
    smb.listPath.return_value = [FakeEntry("file.txt", False)]
    smb.getServerName.return_value = "HOST"

    with patch.object(
        walker.smb_transport, "connect", return_value=smb
    ) as mock_connect:
        on_file, collected = collect_callback()
        walker.walk_directory("//HOST/SHARE1", on_file)
        walker.walk_directory("//HOST/SHARE2", on_file)

    # connect() should be called only once — second call reuses the cache
    mock_connect.assert_called_once_with("HOST")
    assert len(collected) == 2


def test_connection_different_servers():
    """walk_directory() to different servers should create separate connections."""
    cfg = make_cfg()
    walker = TreeWalker(cfg)

    smb_a = MagicMock()
    smb_a.listPath.return_value = [FakeEntry("a.txt", False)]
    smb_a.getServerName.return_value = "HOST_A"

    smb_b = MagicMock()
    smb_b.listPath.return_value = [FakeEntry("b.txt", False)]
    smb_b.getServerName.return_value = "HOST_B"

    def connect_side_effect(server):
        return smb_a if server == "HOST_A" else smb_b

    with patch.object(
        walker.smb_transport, "connect", side_effect=connect_side_effect
    ) as mock_connect:
        on_file, collected = collect_callback()
        walker.walk_directory("//HOST_A/SHARE", on_file)
        walker.walk_directory("//HOST_B/SHARE", on_file)

    assert mock_connect.call_count == 2
    assert len(collected) == 2
    assert collected[0][0] == "//HOST_A/SHARE/a.txt"
    assert collected[1][0] == "//HOST_B/SHARE/b.txt"


def test_stale_connection_reconnects():
    """If the cached connection goes stale, _get_smb evicts it and reconnects."""
    cfg = make_cfg()
    walker = TreeWalker(cfg)

    stale_smb = MagicMock()
    stale_smb.listPath.return_value = [FakeEntry("file.txt", False)]
    stale_smb.getServerName.side_effect = [
        "HOST",
    ]

    fresh_smb = MagicMock()
    fresh_smb.listPath.return_value = [FakeEntry("fresh.txt", False)]
    fresh_smb.getServerName.return_value = "HOST"

    call_count = [0]

    def connect_side_effect(server):
        call_count[0] += 1
        if call_count[0] == 1:
            return stale_smb
        return fresh_smb

    with patch.object(
        walker.smb_transport, "connect", side_effect=connect_side_effect
    ) as mock_connect:
        on_file, collected = collect_callback()

        # First call: connection created and cached, walk succeeds
        walker.walk_directory("//HOST/SHARE1", on_file)
        assert len(collected) == 1
        assert collected[0][0] == "//HOST/SHARE1/file.txt"
        mock_connect.assert_called_once_with("HOST")

        # Simulate connection going stale: getServerName() now fails
        stale_smb.getServerName.side_effect = Exception("connection reset")

        # Second call: _get_smb health check fails → evicts → reconnects
        walker.walk_directory("//HOST/SHARE2", on_file)
        assert len(collected) == 2
        assert collected[1][0] == "//HOST/SHARE2/fresh.txt"

    assert mock_connect.call_count == 2


# ---------- walk_directory tests ----------

def test_walk_directory_returns_subdirs():
    """walk_directory() returns subdirectory UNC paths."""
    cfg = make_cfg()
    walker = TreeWalker(cfg)

    smb = MagicMock()
    smb.listPath.return_value = [
        FakeEntry("subdir1", True),
        FakeEntry("subdir2", True),
        FakeEntry("file.txt", False),
    ]

    with patch.object(walker.smb_transport, "connect", return_value=smb):
        on_file, files = collect_callback()
        subdirs = walker.walk_directory("//HOST/SHARE", on_file)

    assert sorted(subdirs) == [
        "//HOST/SHARE/subdir1",
        "//HOST/SHARE/subdir2",
    ]
    assert len(files) == 1
    assert files[0][0] == "//HOST/SHARE/file.txt"


def test_walk_directory_on_dir_callback():
    """walk_directory() calls on_dir for each subdirectory."""
    cfg = make_cfg()
    walker = TreeWalker(cfg)

    smb = MagicMock()
    smb.listPath.return_value = [
        FakeEntry("subdir1", True),
        FakeEntry("file.txt", False),
    ]

    with patch.object(walker.smb_transport, "connect", return_value=smb):
        on_file, _ = collect_callback()
        on_dir, dirs = collect_dir_callback()
        subdirs = walker.walk_directory("//HOST/SHARE", on_file, on_dir)

    assert subdirs == ["//HOST/SHARE/subdir1"]
    assert dirs == ["//HOST/SHARE/subdir1"]


def test_walk_directory_cancel():
    """walk_directory() raises CancelledError when cancel is set."""
    from concurrent.futures import CancelledError

    cfg = make_cfg()
    walker = TreeWalker(cfg)

    smb = MagicMock()
    smb.listPath.return_value = [FakeEntry("file.txt", False)]

    cancel = threading.Event()
    cancel.set()

    with patch.object(walker.smb_transport, "connect", return_value=smb):
        on_file, files = collect_callback()
        with pytest.raises(CancelledError):
            walker.walk_directory("//HOST/SHARE", on_file, cancel=cancel)

    assert files == []
    smb.listPath.assert_not_called()


def test_walk_directory_discard_rule():
    """walk_directory() excludes dirs matching Discard rules from subdirs."""
    cfg = make_cfg()
    rule = make_rule(MatchAction.DISCARD)
    cfg.rules.directory = [rule]

    walker = TreeWalker(cfg)

    smb = MagicMock()
    smb.listPath.return_value = [
        FakeEntry("excluded_dir", True),
        FakeEntry("file.txt", False),
    ]

    with patch.object(walker.smb_transport, "connect", return_value=smb):
        on_file, files = collect_callback()
        subdirs = walker.walk_directory("//HOST/SHARE", on_file)

    assert subdirs == []  # dir excluded by Discard rule
    assert len(files) == 1


def test_walk_directory_session_error_propagates():
    """SessionError from listPath propagates so the caller can track the failure."""
    from impacket.smbconnection import SessionError
    from impacket.nt_errors import STATUS_ACCESS_DENIED

    cfg = make_cfg()
    walker = TreeWalker(cfg)

    smb = MagicMock()
    smb.listPath.side_effect = SessionError(STATUS_ACCESS_DENIED)

    with patch.object(walker.smb_transport, "connect", return_value=smb):
        with pytest.raises(SessionError):
            walker.walk_directory("//HOST/SHARE")

    # Connection should NOT be invalidated for SessionError — it's still valid
    smb.logoff.assert_not_called()


def test_walk_directory_connection_error_invalidates():
    """Non-SessionError (e.g. connection drop) invalidates the cached connection."""
    cfg = make_cfg()
    walker = TreeWalker(cfg)

    smb = MagicMock()
    smb.listPath.side_effect = OSError("connection reset")

    with patch.object(walker.smb_transport, "connect", return_value=smb):
        with pytest.raises(OSError):
            walker.walk_directory("//HOST/SHARE")

    # Connection should be invalidated on non-SessionError
    smb.logoff.assert_called_once()


def test_walk_directory_invalid_unc():
    """walk_directory() with invalid UNC returns empty list."""
    cfg = make_cfg()
    walker = TreeWalker(cfg)

    subdirs = walker.walk_directory("INVALID")
    assert subdirs == []


def test_walk_directory_subpath():
    """walk_directory() works with a subdirectory UNC path."""
    cfg = make_cfg()
    walker = TreeWalker(cfg)

    smb = MagicMock()
    smb.listPath.return_value = [
        FakeEntry("nested", True),
        FakeEntry("data.csv", False, size=500),
    ]

    with patch.object(walker.smb_transport, "connect", return_value=smb):
        on_file, files = collect_callback()
        subdirs = walker.walk_directory("//HOST/SHARE/parent/child", on_file)

    assert subdirs == ["//HOST/SHARE/parent/child/nested"]
    assert len(files) == 1
    assert files[0][0] == "//HOST/SHARE/parent/child/data.csv"
    # listPath should have been called with the correct sub-path
    smb.listPath.assert_called_once_with("SHARE", "/parent/child/*")
