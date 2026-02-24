from unittest.mock import MagicMock

from snaffler.resume.scan_state import ScanState


def test_scan_state_file_delegation():
    store = MagicMock()
    store.load_checked_files.return_value = {"//host/share/file.txt"}

    state = ScanState(store)

    # should_skip_file uses in-memory set (no SQL delegation)
    assert state.should_skip_file("//HOST/share/file.txt") is True
    assert state.should_skip_file("//HOST/share/other.txt") is False

    # mark_file_done still delegates to store for persistence
    state.mark_file_done("//HOST/share/new.txt")
    store.mark_file_checked.assert_called_once_with("//HOST/share/new.txt")
    # ... and also updates the in-memory set
    assert state.should_skip_file("//HOST/share/new.txt") is True


def test_scan_state_close():
    store = MagicMock()
    store.load_checked_files.return_value = set()
    state = ScanState(store)

    state.close()
    store.close.assert_called_once()


def test_scan_state_phase_delegation():
    store = MagicMock()
    store.load_checked_files.return_value = set()
    store.get_sync_flag.return_value = True

    state = ScanState(store)

    assert state.is_phase_done("computer_discovery_done") is True
    store.get_sync_flag.assert_called_once_with("computer_discovery_done")

    state.mark_phase_done("share_discovery_done")
    store.set_sync_flag.assert_called_once_with("share_discovery_done")


def test_scan_state_computer_delegation():
    store = MagicMock()
    store.load_checked_files.return_value = set()
    store.load_computers.return_value = ["HOST1", "HOST2"]

    state = ScanState(store)

    state.store_computers(["HOST1", "HOST2"])
    store.store_computers.assert_called_once_with(["HOST1", "HOST2"])

    result = state.load_computers()
    assert result == ["HOST1", "HOST2"]
    store.load_computers.assert_called_once()


def test_scan_state_share_delegation():
    store = MagicMock()
    store.load_checked_files.return_value = set()
    store.load_shares.return_value = ["//HOST1/SHARE"]

    state = ScanState(store)

    state.store_shares(["//HOST1/SHARE"])
    store.store_shares.assert_called_once_with(["//HOST1/SHARE"])

    result = state.load_shares()
    assert result == ["//HOST1/SHARE"]
    store.load_shares.assert_called_once()


def test_scan_state_checked_computer_delegation():
    store = MagicMock()
    store.load_checked_files.return_value = set()
    store.has_checked_computer.return_value = True

    state = ScanState(store)

    assert state.should_skip_computer("HOST1") is True
    store.has_checked_computer.assert_called_once_with("HOST1")

    state.mark_computer_done("HOST1")
    store.mark_computer_checked.assert_called_once_with("HOST1")


def test_scan_state_checked_share_delegation():
    store = MagicMock()
    store.load_checked_files.return_value = set()
    store.has_checked_share.return_value = False

    state = ScanState(store)

    assert state.should_skip_share("//HOST/SHARE") is False
    store.has_checked_share.assert_called_once_with("//HOST/SHARE")

    state.mark_share_done("//HOST/SHARE")
    store.mark_share_checked.assert_called_once_with("//HOST/SHARE")


def test_scan_state_computer_ip_delegation():
    store = MagicMock()
    store.load_checked_files.return_value = set()

    state = ScanState(store)

    state.set_computer_ip("HOST1", "10.0.0.1")
    store.update_computer_ip.assert_called_once_with("HOST1", "10.0.0.1")


def test_scan_state_resolved_unresolved_delegation():
    store = MagicMock()
    store.load_checked_files.return_value = set()
    store.load_resolved_computers.return_value = ["HOST1"]
    store.load_unresolved_computers.return_value = ["HOST2", "HOST3"]

    state = ScanState(store)

    assert state.load_resolved_computers() == ["HOST1"]
    store.load_resolved_computers.assert_called_once()

    assert state.load_unresolved_computers() == ["HOST2", "HOST3"]
    store.load_unresolved_computers.assert_called_once()


def test_scan_state_computer_hostname_uppercased():
    """Hostnames are normalized to uppercase for case-insensitive matching."""
    store = MagicMock()
    store.load_checked_files.return_value = set()

    state = ScanState(store)

    state.store_computers(["dc1.corp.local", "DC2.CORP.LOCAL"])
    store.store_computers.assert_called_once_with(["DC1.CORP.LOCAL", "DC2.CORP.LOCAL"])

    state.set_computer_ip("dc1.corp.local", "10.0.0.1")
    store.update_computer_ip.assert_called_once_with("DC1.CORP.LOCAL", "10.0.0.1")

    state.should_skip_computer("dc1.corp.local")
    store.has_checked_computer.assert_called_once_with("DC1.CORP.LOCAL")

    state.mark_computer_done("dc1.corp.local")
    store.mark_computer_checked.assert_called_once_with("DC1.CORP.LOCAL")


def test_scan_state_count_delegation():
    store = MagicMock()
    store.load_checked_files.return_value = set()
    store.count_checked_computers.return_value = 10
    store.count_checked_shares.return_value = 20
    store.count_checked_files.return_value = 300

    state = ScanState(store)

    assert state.count_checked_computers() == 10
    assert state.count_checked_shares() == 20
    assert state.count_checked_files() == 300
