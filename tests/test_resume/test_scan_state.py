from unittest.mock import MagicMock

from snaffler.resume.scan_state import ScanState


def test_scan_state_file_delegation():
    store = MagicMock()
    store.has_checked_file.return_value = True

    state = ScanState(store)

    assert state.should_skip_file("//HOST/share/file.txt") is True
    store.has_checked_file.assert_called_once_with("//HOST/share/file.txt")

    state.mark_file_done("//HOST/share/file.txt")
    store.mark_file_checked.assert_called_once_with("//HOST/share/file.txt")


def test_scan_state_dir_delegation():
    store = MagicMock()
    store.has_checked_dir.return_value = False

    state = ScanState(store)

    assert state.should_skip_dir("//HOST/share/dir") is False
    store.has_checked_dir.assert_called_once_with("//HOST/share/dir")

    state.mark_dir_done("//HOST/share/dir")
    store.mark_dir_checked.assert_called_once_with("//HOST/share/dir")


def test_scan_state_close():
    store = MagicMock()
    state = ScanState(store)

    state.close()
    store.close.assert_called_once()
