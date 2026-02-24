import tempfile
import os
import sqlite3

from snaffler.resume.scan_state import SQLiteStateStore, ScanState


def test_sqlite_store_file_tracking():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        assert "//host/file" not in store.load_checked_files()

        store.mark_file_checked("//HOST/file")
        assert "//host/file" in store.load_checked_files()

        # idempotent
        store.mark_file_checked("//HOST/file")
        assert "//host/file" in store.load_checked_files()

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
    """mark_computer_checked creates target row if missing, then sets done=1."""
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
    """mark_share_checked creates target row if missing, then sets done=1."""
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


# ---------- findings ----------


def test_sqlite_store_finding_store_and_load():
    """Store a finding and load it back."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        assert store.count_findings() == 0
        assert store.load_findings() == []

        store.store_finding(
            finding_id="abc123",
            file_path="//HOST/SHARE/secret.txt",
            triage="Red",
            rule_name="KeepSecretRed",
            match_text="password=",
            context="password=hunter2",
            size=1024,
            mtime="2026-01-15",
            found_at="2026-02-24T12:00:00",
        )

        assert store.count_findings() == 1
        findings = store.load_findings()
        assert len(findings) == 1

        f0 = findings[0]
        assert f0["finding_id"] == "abc123"
        assert f0["file_path"] == "//HOST/SHARE/secret.txt"
        assert f0["triage"] == "Red"
        assert f0["rule_name"] == "KeepSecretRed"
        assert f0["match_text"] == "password="
        assert f0["context"] == "password=hunter2"
        assert f0["size"] == 1024
        assert f0["mtime"] == "2026-01-15"
        assert f0["found_at"] == "2026-02-24T12:00:00"

        store.close()
    finally:
        os.unlink(path)


def test_sqlite_store_finding_dedup():
    """Duplicate finding_id replaces the previous row."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        store.store_finding(
            finding_id="dup1",
            file_path="//HOST/SHARE/a.txt",
            triage="Yellow",
            rule_name="Rule1",
            found_at="2026-02-24T12:00:00",
        )
        store.store_finding(
            finding_id="dup1",
            file_path="//HOST/SHARE/a.txt",
            triage="Red",
            rule_name="Rule1",
            found_at="2026-02-24T12:01:00",
        )

        assert store.count_findings() == 1
        findings = store.load_findings()
        assert findings[0]["triage"] == "Red"

        store.close()
    finally:
        os.unlink(path)


def test_sqlite_store_finding_multiple():
    """Multiple findings stored and ordered by found_at."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        store.store_finding(
            finding_id="f2",
            file_path="//HOST/SHARE/b.txt",
            triage="Yellow",
            rule_name="Rule2",
            found_at="2026-02-24T12:01:00",
        )
        store.store_finding(
            finding_id="f1",
            file_path="//HOST/SHARE/a.txt",
            triage="Red",
            rule_name="Rule1",
            found_at="2026-02-24T12:00:00",
        )
        store.store_finding(
            finding_id="f3",
            file_path="//HOST/SHARE/c.txt",
            triage="Black",
            rule_name="Rule3",
            found_at="2026-02-24T12:02:00",
        )

        assert store.count_findings() == 3
        findings = store.load_findings()
        assert [f["finding_id"] for f in findings] == ["f1", "f2", "f3"]

        store.close()
    finally:
        os.unlink(path)


def test_sqlite_store_finding_optional_fields():
    """Findings with only required fields (nulls for optional)."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        store.store_finding(
            finding_id="min1",
            file_path="//HOST/SHARE/file.txt",
            triage="Green",
            rule_name="Rule1",
        )

        findings = store.load_findings()
        assert len(findings) == 1
        f0 = findings[0]
        assert f0["match_text"] is None
        assert f0["context"] is None
        assert f0["size"] is None
        assert f0["mtime"] is None
        assert f0["found_at"] is not None  # auto-generated

        store.close()
    finally:
        os.unlink(path)


def test_sqlite_store_finding_migration():
    """Old DB without finding table gets it added on open."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        # Create old-style DB without finding table but with legacy tables
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE sync (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute("CREATE TABLE target_computer (name TEXT PRIMARY KEY COLLATE NOCASE, ip TEXT)")
        conn.execute("CREATE TABLE checked_file (unc_path TEXT PRIMARY KEY COLLATE NOCASE)")
        conn.commit()
        conn.close()

        # Open with new store — should add finding table and drop legacy tables
        store = SQLiteStateStore(path)

        cur = store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='finding'"
        )
        assert cur.fetchone() is not None

        # Legacy tables should be dropped
        cur = store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='checked_file'"
        )
        assert cur.fetchone() is None

        # Can store findings after migration
        store.store_finding(
            finding_id="migrated1",
            file_path="//HOST/SHARE/file.txt",
            triage="Red",
            rule_name="Rule1",
        )
        assert store.count_findings() == 1

        store.close()
    finally:
        os.unlink(path)


# ---------- case-insensitive lookups (SMB/NTFS paths are case-insensitive) ----------


def test_case_insensitive_checked_file():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        store.mark_file_checked("//HOST/Share/File.txt")
        checked = store.load_checked_files()
        assert "//host/share/file.txt" in checked

        # Duplicate with different case is ignored (same file on NTFS)
        store.mark_file_checked("//host/share/file.txt")
        assert store.count_checked_files() == 1

        store.close()
    finally:
        os.unlink(path)


def test_case_insensitive_checked_share():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        store.mark_share_checked("//HOST/ShareName")
        assert store.has_checked_share("//host/sharename") is True
        assert store.has_checked_share("//HOST/SHARENAME") is True

        store.close()
    finally:
        os.unlink(path)


def test_case_insensitive_checked_computer():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        store.mark_computer_checked("DC01")
        assert store.has_checked_computer("dc01") is True
        assert store.has_checked_computer("Dc01") is True

        store.close()
    finally:
        os.unlink(path)


def test_case_insensitive_target_share():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        store.store_shares(["//HOST/Share"])
        store.store_shares(["//host/share"])
        loaded = store.load_shares()
        assert len(loaded) == 1

        store.close()
    finally:
        os.unlink(path)


# ---------- in-memory checked_file set (P1-E) ----------


def test_load_checked_files_returns_correct_set():
    """load_checked_files() returns all checked file paths as a lowercase set."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        store.mark_file_checked("//HOST/Share/File1.txt")
        store.mark_file_checked("//HOST/Share/File2.TXT")

        result = store.load_checked_files()

        assert isinstance(result, set)
        assert result == {"//host/share/file1.txt", "//host/share/file2.txt"}

        store.close()
    finally:
        os.unlink(path)


def test_load_checked_files_empty_db():
    """load_checked_files() returns empty set on fresh DB."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        result = store.load_checked_files()
        assert result == set()

        store.close()
    finally:
        os.unlink(path)


def test_scan_state_should_skip_file_uses_in_memory_set():
    """ScanState.should_skip_file() uses in-memory set, not SQL query."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)
        store.mark_file_checked("//HOST/Share/existing.txt")

        state = ScanState(store)

        # should_skip_file uses in-memory set — no SQL after init
        assert state.should_skip_file("//HOST/Share/existing.txt") is True
        assert state.should_skip_file("//host/share/existing.txt") is True
        assert state.should_skip_file("//HOST/Share/new.txt") is False

        store.close()
    finally:
        os.unlink(path)


def test_scan_state_mark_file_done_updates_both_db_and_set():
    """mark_file_done() writes to both SQLite and in-memory set."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)
        state = ScanState(store)

        assert state.should_skip_file("//HOST/Share/new.txt") is False

        state.mark_file_done("//HOST/Share/new.txt")

        # In-memory set is updated immediately
        assert state.should_skip_file("//HOST/Share/new.txt") is True

        # SQLite is also updated (for persistence across runs)
        assert "//host/share/new.txt" in store.load_checked_files()

        store.close()
    finally:
        os.unlink(path)


def test_scan_state_checked_files_case_insensitive():
    """In-memory checked file set is case-insensitive."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)
        state = ScanState(store)

        state.mark_file_done("//HOST/Share/CamelCase.TXT")

        assert state.should_skip_file("//HOST/Share/CamelCase.TXT") is True
        assert state.should_skip_file("//host/share/camelcase.txt") is True
        assert state.should_skip_file("//HOST/SHARE/CAMELCASE.TXT") is True

        store.close()
    finally:
        os.unlink(path)


# ---------- target_dir CRUD ----------


def test_sqlite_store_dir_crud():
    """Store dirs, mark walked, load unwalked."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        # Empty initially
        assert store.load_unwalked_dirs() == []

        # Store single dir
        store.store_dir("//HOST/SHARE/dir1", "//HOST/SHARE")
        unwalked = store.load_unwalked_dirs()
        assert unwalked == ["//HOST/SHARE/dir1"]

        # Store batch
        store.store_dirs([
            ("//HOST/SHARE/dir2", "//HOST/SHARE"),
            ("//HOST/SHARE/dir3", "//HOST/SHARE"),
        ])
        unwalked = store.load_unwalked_dirs()
        assert sorted(unwalked) == [
            "//HOST/SHARE/dir1",
            "//HOST/SHARE/dir2",
            "//HOST/SHARE/dir3",
        ]

        # Mark walked
        store.mark_dir_walked("//HOST/SHARE/dir1")
        unwalked = store.load_unwalked_dirs()
        assert sorted(unwalked) == ["//HOST/SHARE/dir2", "//HOST/SHARE/dir3"]

        # Idempotent insert
        store.store_dir("//HOST/SHARE/dir2", "//HOST/SHARE")
        assert len(store.load_unwalked_dirs()) == 2

        store.close()
    finally:
        os.unlink(path)


def test_sqlite_store_dir_share_filter():
    """load_unwalked_dirs(share=...) filters by share."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        store.store_dirs([
            ("//HOST/SHARE1/dir_a", "//HOST/SHARE1"),
            ("//HOST/SHARE1/dir_b", "//HOST/SHARE1"),
            ("//HOST/SHARE2/dir_c", "//HOST/SHARE2"),
        ])

        assert len(store.load_unwalked_dirs(share="//HOST/SHARE1")) == 2
        assert len(store.load_unwalked_dirs(share="//HOST/SHARE2")) == 1
        assert len(store.load_unwalked_dirs()) == 3

        store.close()
    finally:
        os.unlink(path)


def test_sqlite_store_dir_case_insensitive():
    """target_dir uses COLLATE NOCASE."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        store.store_dir("//HOST/Share/Dir", "//HOST/Share")
        store.store_dir("//host/share/dir", "//host/share")  # duplicate
        assert len(store.load_unwalked_dirs()) == 1

        # Mark walked with different case
        store.mark_dir_walked("//HOST/SHARE/DIR")
        assert store.load_unwalked_dirs() == []

        store.close()
    finally:
        os.unlink(path)


# ---------- target_file CRUD ----------


def test_sqlite_store_file_crud():
    """Store files, load unchecked, count."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        assert store.count_target_files() == 0
        assert store.load_unchecked_files() == []

        # Single insert
        store.store_file("//HOST/SHARE/a.txt", "//HOST/SHARE", 100, 1700000000.0)
        assert store.count_target_files() == 1

        # Batch insert
        store.store_files([
            ("//HOST/SHARE/b.txt", "//HOST/SHARE", 200, 1700000001.0),
            ("//HOST/SHARE/c.txt", "//HOST/SHARE", 300, 1700000002.0),
        ])
        assert store.count_target_files() == 3

        # All unchecked
        unchecked = store.load_unchecked_files()
        assert len(unchecked) == 3
        paths = [u[0] for u in unchecked]
        assert "//HOST/SHARE/a.txt" in paths

        # Mark one checked
        store.mark_file_checked("//HOST/SHARE/a.txt")
        unchecked = store.load_unchecked_files()
        assert len(unchecked) == 2
        assert store.count_checked_files() == 1

        store.close()
    finally:
        os.unlink(path)


def test_sqlite_store_file_batch_and_mark():
    """Batch-stored files can be individually marked checked."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        store.store_files([
            ("//HOST/SHARE/x.txt", "//HOST/SHARE", 50, 0.0),
            ("//HOST/SHARE/y.txt", "//HOST/SHARE", 60, 0.0),
        ])

        # mark_file_checked on existing row
        store.mark_file_checked("//HOST/SHARE/x.txt")
        assert store.count_checked_files() == 1

        # mark_file_checked on non-pre-stored file (INSERT fallback)
        store.mark_file_checked("//HOST/SHARE/z.txt")
        assert store.count_checked_files() == 2
        assert store.count_target_files() == 3

        store.close()
    finally:
        os.unlink(path)


def test_sqlite_store_file_case_insensitive():
    """target_file uses COLLATE NOCASE."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        store.store_file("//HOST/Share/File.TXT", "//HOST/Share", 100, 0.0)
        store.store_file("//host/share/file.txt", "//host/share", 200, 0.0)  # dup
        assert store.count_target_files() == 1

        store.close()
    finally:
        os.unlink(path)


# ---------- mark_dir_walked upsert (Bug 1 fix) ----------


def test_sqlite_store_mark_dir_walked_before_store():
    """mark_dir_walked works even if dir was never stored (upsert)."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        # mark_dir_walked on a dir that was never store_dir'd
        store.mark_dir_walked("//HOST/SHARE/dir_not_stored")

        # Should NOT appear in unwalked (it's marked walked)
        assert store.load_unwalked_dirs() == []

        store.close()
    finally:
        os.unlink(path)


def test_sqlite_store_mark_dir_walked_after_store():
    """mark_dir_walked on previously stored dir sets walked=1."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        store.store_dir("//HOST/SHARE/dir1", "//HOST/SHARE")
        assert len(store.load_unwalked_dirs()) == 1

        store.mark_dir_walked("//HOST/SHARE/dir1")
        assert store.load_unwalked_dirs() == []

        store.close()
    finally:
        os.unlink(path)


# ---------- mark_file_checked extracts share (Design fix) ----------


def test_sqlite_store_mark_file_checked_extracts_share():
    """mark_file_checked INSERT fallback extracts share from UNC path."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        store = SQLiteStateStore(path)

        # File not in target_file yet — INSERT fallback fires
        store.mark_file_checked("//HOST/SHARE/new_file.txt")

        # Verify the share column was populated (not empty string)
        with store.lock:
            row = store.conn.execute(
                "SELECT share FROM target_file WHERE unc_path = ?",
                ("//HOST/SHARE/new_file.txt",),
            ).fetchone()
        assert row is not None
        assert row[0] == "//HOST/SHARE"

        store.close()
    finally:
        os.unlink(path)


# ---------- legacy table drop ----------


def test_sqlite_store_drops_legacy_tables():
    """Opening a DB with checked_* tables drops them."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        # Create DB with legacy tables
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE checked_computer (name TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE checked_share (unc_path TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE checked_file (unc_path TEXT PRIMARY KEY)")
        conn.execute("INSERT INTO checked_computer VALUES ('HOST1')")
        conn.execute("INSERT INTO checked_share VALUES ('//HOST1/SHARE')")
        conn.execute("INSERT INTO checked_file VALUES ('//HOST1/SHARE/a.txt')")
        conn.commit()
        conn.close()

        store = SQLiteStateStore(path)

        # Legacy tables should be gone
        tables = {
            r[0] for r in store.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "checked_computer" not in tables
        assert "checked_share" not in tables
        assert "checked_file" not in tables

        # New tables should exist
        assert "target_computer" in tables
        assert "target_share" in tables
        assert "target_dir" in tables
        assert "target_file" in tables

        store.close()
    finally:
        os.unlink(path)


# ---------- migration: done column added to existing tables ----------


def test_sqlite_store_migration_adds_done_column():
    """Opening a DB with old target_computer/target_share (no done col) adds it."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        path = f.name

    try:
        # Create old-style tables without done column
        conn = sqlite3.connect(path)
        conn.execute(
            "CREATE TABLE target_computer "
            "(name TEXT PRIMARY KEY COLLATE NOCASE, ip TEXT)"
        )
        conn.execute(
            "CREATE TABLE target_share "
            "(unc_path TEXT PRIMARY KEY COLLATE NOCASE)"
        )
        conn.execute("INSERT INTO target_computer VALUES ('HOST1', '10.0.0.1')")
        conn.execute("INSERT INTO target_share VALUES ('//HOST1/SHARE')")
        conn.commit()
        conn.close()

        store = SQLiteStateStore(path)

        # done column should exist and default to 0
        assert store.has_checked_computer("HOST1") is False
        assert store.has_checked_share("//HOST1/SHARE") is False

        # Can mark done
        store.mark_computer_checked("HOST1")
        assert store.has_checked_computer("HOST1") is True

        store.mark_share_checked("//HOST1/SHARE")
        assert store.has_checked_share("//HOST1/SHARE") is True

        store.close()
    finally:
        os.unlink(path)
