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
    smb.logoff.assert_called_once()


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
