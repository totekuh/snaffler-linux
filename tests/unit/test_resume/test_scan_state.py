from unittest.mock import MagicMock

from snaffler.resume.scan_state import ScanState, _extract_share


def _make_store(**overrides):
    """Create a mock store with defaults for bloom filter init."""
    store = MagicMock()
    store.count_checked_files.return_value = overrides.pop("checked_count", 0)
    store.iter_checked_file_keys.return_value = overrides.pop("checked_keys", iter([]))
    for k, v in overrides.items():
        setattr(store, k, v)
    return store


# ---------- _extract_share ----------

def test_extract_share_unc_path():
    """UNC paths extract //server/share."""
    assert _extract_share("//HOST/SHARE/dir/file.txt") == "//HOST/SHARE"
    assert _extract_share("//HOST/SHARE") == "//HOST/SHARE"


def test_extract_share_local_path():
    """Local paths are returned unchanged."""
    assert _extract_share("/tmp/data") == "/tmp/data"
    assert _extract_share("/tmp/data/subdir/file.txt") == "/tmp/data/subdir/file.txt"
    assert _extract_share("/data") == "/data"


def test_extract_share_backslash_unc():
    """Backslash UNC paths are normalized and extracted."""
    assert _extract_share("\\\\HOST\\SHARE\\dir") == "//HOST/SHARE"


# ---------- delegation ----------

def test_scan_state_file_delegation():
    store = _make_store(
        checked_count=1,
        checked_keys=iter(["//host/share/file.txt"]),
    )
    # is_file_checked is called on bloom positive to verify via DB
    store.is_file_checked.return_value = True

    state = ScanState(store)

    # should_skip_file: bloom says yes, DB confirms
    assert state.should_skip_file("//HOST/share/file.txt") is True
    # should_skip_file: bloom says no for unknown file (no DB call needed)
    assert state.should_skip_file("//HOST/share/other.txt") is False

    # mark_file_done updates bloom filter (no store.mark_file_checked call --
    # DB write is batched by caller)
    state.mark_file_done("//HOST/share/new.txt")
    # After mark_file_done, bloom says yes; DB must confirm
    store.is_file_checked.return_value = True
    assert state.should_skip_file("//HOST/share/new.txt") is True


def test_scan_state_close():
    store = _make_store()
    state = ScanState(store)

    state.close()
    store.close.assert_called_once()


def test_scan_state_phase_delegation():
    store = _make_store()
    store.get_sync_flag.return_value = True

    state = ScanState(store)

    assert state.is_phase_done("computer_discovery_done") is True
    store.get_sync_flag.assert_called_once_with("computer_discovery_done")

    state.mark_phase_done("share_discovery_done")
    store.set_sync_flag.assert_called_once_with("share_discovery_done")


def test_scan_state_computer_delegation():
    store = _make_store()
    store.load_computers.return_value = ["HOST1", "HOST2"]

    state = ScanState(store)

    state.store_computers(["HOST1", "HOST2"])
    store.store_computers.assert_called_once_with(["HOST1", "HOST2"])

    result = state.load_computers()
    assert result == ["HOST1", "HOST2"]
    store.load_computers.assert_called_once()


def test_scan_state_share_delegation():
    store = _make_store()
    store.load_shares.return_value = ["//HOST1/SHARE"]

    state = ScanState(store)

    state.store_shares(["//HOST1/SHARE"])
    store.store_shares.assert_called_once_with(["//HOST1/SHARE"])

    result = state.load_shares()
    assert result == ["//HOST1/SHARE"]
    store.load_shares.assert_called_once()


def test_scan_state_checked_computer_delegation():
    store = _make_store()
    store.has_checked_computer.return_value = True

    state = ScanState(store)

    assert state.should_skip_computer("HOST1") is True
    store.has_checked_computer.assert_called_once_with("HOST1")

    state.mark_computer_done("HOST1")
    store.mark_computer_checked.assert_called_once_with("HOST1")


def test_scan_state_checked_share_delegation():
    store = _make_store()
    store.has_checked_share.return_value = False

    state = ScanState(store)

    assert state.should_skip_share("//HOST/SHARE") is False
    store.has_checked_share.assert_called_once_with("//HOST/SHARE")

    state.mark_share_done("//HOST/SHARE")
    store.mark_share_checked.assert_called_once_with("//HOST/SHARE")


def test_scan_state_computer_ip_delegation():
    store = _make_store()

    state = ScanState(store)

    state.set_computer_ip("HOST1", "10.0.0.1")
    store.update_computer_ip.assert_called_once_with("HOST1", "10.0.0.1")


def test_scan_state_resolved_unresolved_delegation():
    store = _make_store()
    store.load_resolved_computers.return_value = ["HOST1"]
    store.load_unresolved_computers.return_value = ["HOST2", "HOST3"]

    state = ScanState(store)

    assert state.load_resolved_computers() == ["HOST1"]
    store.load_resolved_computers.assert_called_once()

    assert state.load_unresolved_computers() == ["HOST2", "HOST3"]
    store.load_unresolved_computers.assert_called_once()


def test_scan_state_computer_hostname_uppercased():
    """Hostnames are normalized to uppercase for case-insensitive matching."""
    store = _make_store()

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
    store = _make_store(checked_count=300)
    store.count_checked_computers.return_value = 10
    store.count_checked_shares.return_value = 20

    state = ScanState(store)

    assert state.count_checked_computers() == 10
    assert state.count_checked_shares() == 20
    assert state.count_checked_files() == 300


# ---------- new method delegation tests ----------


def test_scan_state_dir_delegation():
    store = _make_store()
    store.load_unwalked_dirs.return_value = ["//HOST/SHARE/dir1"]

    state = ScanState(store)

    state.store_dir("//HOST/SHARE/dir1", "//HOST/SHARE")
    store.store_dir.assert_called_once_with("//HOST/SHARE/dir1", "//HOST/SHARE")

    state.store_dirs([("//HOST/SHARE/dir2", "//HOST/SHARE")])
    store.store_dirs.assert_called_once_with([("//HOST/SHARE/dir2", "//HOST/SHARE")])

    state.mark_dir_walked("//HOST/SHARE/dir1")
    store.mark_dir_walked.assert_called_once_with("//HOST/SHARE/dir1")

    result = state.load_unwalked_dirs(share="//HOST/SHARE")
    assert result == ["//HOST/SHARE/dir1"]
    store.load_unwalked_dirs.assert_called_once_with("//HOST/SHARE")


def test_scan_state_file_batch_delegation():
    store = _make_store()
    store.load_unchecked_files.return_value = [
        ("//HOST/SHARE/a.txt", 100, 0.0),
    ]
    store.count_target_files.return_value = 5

    state = ScanState(store)

    state.store_file("//HOST/SHARE/a.txt", "//HOST/SHARE", 100, 0.0)
    store.store_file.assert_called_once_with("//HOST/SHARE/a.txt", "//HOST/SHARE", 100, 0.0)

    state.store_files([("//HOST/SHARE/b.txt", "//HOST/SHARE", 200, 0.0)])
    store.store_files.assert_called_once_with(
        [("//HOST/SHARE/b.txt", "//HOST/SHARE", 200, 0.0)]
    )

    result = state.load_unchecked_files()
    assert result == [("//HOST/SHARE/a.txt", 100, 0.0)]
    store.load_unchecked_files.assert_called_once()

    assert state.count_target_files() == 5
    store.count_target_files.assert_called_once()


def test_scan_state_iter_unchecked_files_delegation():
    """iter_unchecked_files delegates to store."""
    store = _make_store()
    store.iter_unchecked_files.return_value = iter([
        ("//HOST/SHARE/a.txt", 100, 0.0),
        ("//HOST/SHARE/b.txt", 200, 1.0),
    ])

    state = ScanState(store)

    result = list(state.iter_unchecked_files())
    assert result == [
        ("//HOST/SHARE/a.txt", 100, 0.0),
        ("//HOST/SHARE/b.txt", 200, 1.0),
    ]
    store.iter_unchecked_files.assert_called_once()
