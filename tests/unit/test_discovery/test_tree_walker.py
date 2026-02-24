import threading
from unittest.mock import MagicMock, patch

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
    """Return (callback, collected_list) for use with walk_tree."""
    collected = []
    def on_file(path, size, mtime):
        collected.append((path, size, mtime))
    return on_file, collected


# ---------- tests ----------

def test_walk_tree_invalid_unc():
    cfg = make_cfg()
    walker = TreeWalker(cfg)

    on_file, collected = collect_callback()
    walker.walk_tree("INVALID", on_file)

    assert collected == []


def test_walk_tree_simple_file():
    cfg = make_cfg()
    walker = TreeWalker(cfg)

    smb = MagicMock()
    smb.listPath.return_value = [
        FakeEntry("file.txt", False)
    ]

    with patch.object(
        walker.smb_transport, "connect", return_value=smb
    ):
        on_file, collected = collect_callback()
        walker.walk_tree("//HOST/SHARE", on_file)

    assert len(collected) == 1
    assert collected[0][0] == "//HOST/SHARE/file.txt"
    assert collected[0][1] == 100   # size from FakeEntry
    assert collected[0][2] == 1700000000.0  # mtime from FakeEntry
    # Connection is cached (thread-local) — no logoff after each share
    smb.logoff.assert_not_called()


def test_walk_tree_recursive_directory():
    cfg = make_cfg()
    walker = TreeWalker(cfg)

    smb = MagicMock()

    def list_path(share, path):
        if path == "/*":
            return [FakeEntry("dir", True)]
        if path == "/dir/*":
            return [FakeEntry("file.txt", False)]
        return []

    smb.listPath.side_effect = list_path

    with patch.object(
        walker.smb_transport, "connect", return_value=smb
    ):
        on_file, collected = collect_callback()
        walker.walk_tree("//HOST/SHARE", on_file)

    assert len(collected) == 1
    assert collected[0][0] == "//HOST/SHARE/dir/file.txt"


def test_walk_tree_cancel_stops_early():
    """Setting cancel event stops walker from descending into further dirs."""
    cfg = make_cfg()
    walker = TreeWalker(cfg)

    smb = MagicMock()

    dirs_listed = []

    def list_path(share, path):
        dirs_listed.append(path)
        if path == "/*":
            return [
                FakeEntry("dir1", True),
                FakeEntry("dir2", True),
                FakeEntry("dir3", True),
            ]
        # Each subdir has a file
        return [FakeEntry("file.txt", False)]

    smb.listPath.side_effect = list_path

    cancel = threading.Event()
    on_file, collected = collect_callback()

    # Set cancel after the first file is found
    original_on_file = on_file
    def cancelling_on_file(path, size, mtime):
        original_on_file(path, size, mtime)
        cancel.set()

    with patch.object(
        walker.smb_transport, "connect", return_value=smb
    ):
        walker.walk_tree("//HOST/SHARE", cancelling_on_file, cancel)

    # Should have found at least 1 file but NOT all 3
    assert len(collected) >= 1
    assert len(collected) < 3


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


# ---------- connection caching tests ----------

def test_connection_reuse_same_server():
    """Two walk_tree() calls to the same server should reuse the connection."""
    cfg = make_cfg()
    walker = TreeWalker(cfg)

    smb = MagicMock()
    smb.listPath.return_value = [FakeEntry("file.txt", False)]
    # getServerName() succeeds → connection is considered alive
    smb.getServerName.return_value = "HOST"

    with patch.object(
        walker.smb_transport, "connect", return_value=smb
    ) as mock_connect:
        on_file, collected = collect_callback()
        walker.walk_tree("//HOST/SHARE1", on_file)
        walker.walk_tree("//HOST/SHARE2", on_file)

    # connect() should be called only once — second call reuses the cache
    mock_connect.assert_called_once_with("HOST")
    assert len(collected) == 2


def test_connection_different_servers():
    """walk_tree() to different servers should create separate connections."""
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
        walker.walk_tree("//HOST_A/SHARE", on_file)
        walker.walk_tree("//HOST_B/SHARE", on_file)

    assert mock_connect.call_count == 2
    assert len(collected) == 2
    assert collected[0][0] == "//HOST_A/SHARE/a.txt"
    assert collected[1][0] == "//HOST_B/SHARE/b.txt"


def test_stale_connection_reconnects():
    """If the cached connection goes stale, _get_smb evicts it and reconnects.

    Mirrors the SMBFileAccessor pattern: getServerName() is the health check.
    When it fails, the stale entry is evicted and connect() is called again.
    """
    cfg = make_cfg()
    walker = TreeWalker(cfg)

    stale_smb = MagicMock()
    stale_smb.listPath.return_value = [FakeEntry("file.txt", False)]
    # First getServerName() succeeds (initial cache), second fails (stale)
    stale_smb.getServerName.side_effect = [
        "HOST",          # health check on second walk_tree → succeeds? No...
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
        walker.walk_tree("//HOST/SHARE1", on_file)
        assert len(collected) == 1
        assert collected[0][0] == "//HOST/SHARE1/file.txt"
        mock_connect.assert_called_once_with("HOST")

        # Simulate connection going stale: getServerName() now fails
        stale_smb.getServerName.side_effect = Exception("connection reset")

        # Second call: _get_smb health check fails → evicts → reconnects
        walker.walk_tree("//HOST/SHARE2", on_file)
        assert len(collected) == 2
        assert collected[1][0] == "//HOST/SHARE2/fresh.txt"

    assert mock_connect.call_count == 2
