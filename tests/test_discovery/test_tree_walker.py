from unittest.mock import MagicMock, patch

from snaffler.discovery.tree import TreeWalker
from snaffler.classifiers.rules import MatchAction, EnumerationScope, MatchLocation


# ---------- helpers ----------

class FakeEntry:
    def __init__(self, name, is_dir):
        self._name = name
        self._is_dir = is_dir

    def get_longname(self):
        return self._name

    def is_directory(self):
        return self._is_dir


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


# ---------- tests ----------

def test_walk_tree_invalid_unc():
    cfg = make_cfg()
    walker = TreeWalker(cfg)

    result = walker.walk_tree("INVALID")

    assert result == []


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
        files = walker.walk_tree("//HOST/SHARE")

    assert len(files) == 1
    assert files[0][0] == "//HOST/SHARE/file.txt"
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
        files = walker.walk_tree("//HOST/SHARE")

    assert files == [("//HOST/SHARE/dir/file.txt", smb.listPath.return_value)] or len(files) == 1


def test_resume_skips_directory():
    cfg = make_cfg()
    state = MagicMock()
    state.should_skip_dir.return_value = True

    walker = TreeWalker(cfg, state=state)

    smb = MagicMock()

    with patch.object(
        walker.smb_transport, "connect", return_value=smb
    ):
        files = walker.walk_tree("//HOST/SHARE")

    assert files == []
    state.should_skip_dir.assert_called()


def test_resume_marks_dir_done():
    cfg = make_cfg()
    state = MagicMock()
    state.should_skip_dir.return_value = False

    walker = TreeWalker(cfg, state=state)

    smb = MagicMock()
    smb.listPath.return_value = []

    with patch.object(
        walker.smb_transport, "connect", return_value=smb
    ):
        walker.walk_tree("//HOST/SHARE")

    state.mark_dir_done.assert_called_once_with("//HOST/SHARE/")


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
