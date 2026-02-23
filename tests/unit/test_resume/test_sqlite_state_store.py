import tempfile
import os
import sqlite3

from snaffler.resume.scan_state import SQLiteStateStore


def test_sqlite_store_file_tracking():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        assert store.has_checked_file("//HOST/file") is False

        store.mark_file_checked("//HOST/file")
        assert store.has_checked_file("//HOST/file") is True

        # idempotent
        store.mark_file_checked("//HOST/file")
        assert store.has_checked_file("//HOST/file") is True

        store.close()

    finally:
        os.unlink(path)


def test_sqlite_store_dir_tracking():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        assert store.has_checked_dir("//HOST/dir") is False

        store.mark_dir_checked("//HOST/dir")
        assert store.has_checked_dir("//HOST/dir") is True

        # idempotent
        store.mark_dir_checked("//HOST/dir")
        assert store.has_checked_dir("//HOST/dir") is True

        store.close()

    finally:
        os.unlink(path)


def test_sqlite_store_sync_flags():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        assert store.get_sync_flag("computer_discovery_done") is False
        assert store.get_sync_flag("share_discovery_done") is False

        store.set_sync_flag("computer_discovery_done")
        assert store.get_sync_flag("computer_discovery_done") is True
        assert store.get_sync_flag("share_discovery_done") is False

        # idempotent
        store.set_sync_flag("computer_discovery_done")
        assert store.get_sync_flag("computer_discovery_done") is True

        store.close()
    finally:
        os.unlink(path)


def test_sqlite_store_computer_tracking():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        assert store.load_computers() == []

        store.store_computers(["HOST1", "HOST2", "HOST3"])
        loaded = store.load_computers()
        assert sorted(loaded) == ["HOST1", "HOST2", "HOST3"]

        # idempotent — duplicates ignored
        store.store_computers(["HOST2", "HOST4"])
        loaded = store.load_computers()
        assert sorted(loaded) == ["HOST1", "HOST2", "HOST3", "HOST4"]

        store.close()
    finally:
        os.unlink(path)


def test_sqlite_store_share_tracking():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        assert store.load_shares() == []

        store.store_shares(["//HOST1/SHARE", "//HOST2/DATA"])
        loaded = store.load_shares()
        assert sorted(loaded) == ["//HOST1/SHARE", "//HOST2/DATA"]

        # idempotent
        store.store_shares(["//HOST1/SHARE", "//HOST3/APPS"])
        loaded = store.load_shares()
        assert sorted(loaded) == ["//HOST1/SHARE", "//HOST2/DATA", "//HOST3/APPS"]

        store.close()
    finally:
        os.unlink(path)


def test_sqlite_store_checked_computer():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        assert store.has_checked_computer("HOST1") is False

        store.mark_computer_checked("HOST1")
        assert store.has_checked_computer("HOST1") is True
        assert store.has_checked_computer("HOST2") is False

        # idempotent
        store.mark_computer_checked("HOST1")
        assert store.has_checked_computer("HOST1") is True

        store.close()
    finally:
        os.unlink(path)


def test_sqlite_store_checked_share():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        assert store.has_checked_share("//HOST/SHARE") is False

        store.mark_share_checked("//HOST/SHARE")
        assert store.has_checked_share("//HOST/SHARE") is True
        assert store.has_checked_share("//HOST/OTHER") is False

        # idempotent
        store.mark_share_checked("//HOST/SHARE")
        assert store.has_checked_share("//HOST/SHARE") is True

        store.close()
    finally:
        os.unlink(path)


def test_sqlite_store_counts():
    """Count methods return correct totals."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        assert store.count_checked_computers() == 0
        assert store.count_checked_shares() == 0
        assert store.count_checked_files() == 0

        store.mark_computer_checked("HOST1")
        store.mark_computer_checked("HOST2")
        assert store.count_checked_computers() == 2

        store.mark_share_checked("//HOST1/SHARE")
        assert store.count_checked_shares() == 1

        store.mark_file_checked("//HOST1/SHARE/a.txt")
        store.mark_file_checked("//HOST1/SHARE/b.txt")
        store.mark_file_checked("//HOST1/SHARE/c.txt")
        assert store.count_checked_files() == 3

        # Idempotent — duplicates don't inflate count
        store.mark_computer_checked("HOST1")
        assert store.count_checked_computers() == 2

        store.close()
    finally:
        os.unlink(path)


def test_sqlite_store_computer_ip_tracking():
    """Store computers, update IPs, load resolved/unresolved."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        store.store_computers(["HOST1", "HOST2", "HOST3"])

        # All start unresolved
        assert sorted(store.load_unresolved_computers()) == ["HOST1", "HOST2", "HOST3"]
        assert store.load_resolved_computers() == []

        # Resolve HOST1 and HOST3
        store.update_computer_ip("HOST1", "10.0.0.1")
        store.update_computer_ip("HOST3", "10.0.0.3")

        assert sorted(store.load_resolved_computers()) == ["HOST1", "HOST3"]
        assert store.load_unresolved_computers() == ["HOST2"]

        # Update HOST2
        store.update_computer_ip("HOST2", "10.0.0.2")
        assert sorted(store.load_resolved_computers()) == ["HOST1", "HOST2", "HOST3"]
        assert store.load_unresolved_computers() == []

        store.close()
    finally:
        os.unlink(path)


def test_sqlite_store_computer_ip_migration():
    """Old DB without ip column gets it added; existing rows have ip=NULL."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        # Create old-style DB with target_computer lacking ip column
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE target_computer (name TEXT PRIMARY KEY)")
        conn.execute("INSERT INTO target_computer VALUES ('HOST1')")
        conn.execute("INSERT INTO target_computer VALUES ('HOST2')")
        conn.commit()
        conn.close()

        # Open with new store — should migrate
        store = SQLiteStateStore(path)

        # Existing rows should have ip=NULL (all unresolved)
        assert sorted(store.load_unresolved_computers()) == ["HOST1", "HOST2"]
        assert store.load_resolved_computers() == []

        # Can update IPs on migrated rows
        store.update_computer_ip("HOST1", "10.0.0.1")
        assert store.load_resolved_computers() == ["HOST1"]
        assert store.load_unresolved_computers() == ["HOST2"]

        store.close()
    finally:
        os.unlink(path)


def test_sqlite_store_backward_compat():
    """Old DB with checked_files/checked_dirs tables should be migrated."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        # Create an old-style DB manually
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE checked_files (unc_path TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE checked_dirs (unc_path TEXT PRIMARY KEY)")
        conn.execute("INSERT INTO checked_files VALUES ('//HOST/share/old_file.txt')")
        conn.execute("INSERT INTO checked_dirs VALUES ('//HOST/share/old_dir')")
        conn.commit()
        conn.close()

        # Open with new store — should migrate
        store = SQLiteStateStore(path)

        # Old data accessible via new table names
        assert store.has_checked_file("//HOST/share/old_file.txt") is True
        assert store.has_checked_dir("//HOST/share/old_dir") is True

        # Old tables should be gone
        cur = store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('checked_files', 'checked_dirs')"
        )
        assert cur.fetchall() == []

        # New tables exist
        cur = store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('checked_file', 'checked_dir')"
        )
        tables = {row[0] for row in cur.fetchall()}
        assert tables == {"checked_file", "checked_dir"}

        # New tables also work
        store.mark_file_checked("//HOST/share/new_file.txt")
        assert store.has_checked_file("//HOST/share/new_file.txt") is True

        # All 7 tables exist
        cur = store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        all_tables = {row[0] for row in cur.fetchall()}
        expected = {
            "sync", "target_computer", "target_share",
            "checked_computer", "checked_share",
            "checked_dir", "checked_file",
        }
        assert expected.issubset(all_tables)

        store.close()
    finally:
        os.unlink(path)
