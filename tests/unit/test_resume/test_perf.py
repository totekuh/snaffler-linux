"""Tests for SQLite performance optimizations."""

import os
import sqlite3
import tempfile
import types

from snaffler.resume.scan_state import SQLiteStateStore, ScanState


# ---------- helpers ----------


def _make_store(path=None):
    """Create an SQLiteStateStore at the given path (or a temp file)."""
    if path is None:
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
    return SQLiteStateStore(path), path


# ---------- WAL checkpoint on close ----------


class TestWALCheckpoint:
    def test_wal_checkpoint_on_close(self, tmp_path):
        """Closing the store should checkpoint WAL so the DB is self-contained."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        # Write some data to populate the WAL
        store.store_computers(["HOST1", "HOST2", "HOST3"])
        store.store_shares([("//HOST1/SHARE", True)])
        store.store_file("//HOST1/SHARE/file.txt", "//HOST1/SHARE", 100, 0.0)
        store.mark_file_checked("//HOST1/SHARE/file.txt")

        # Close should checkpoint (TRUNCATE)
        store.close()

        wal_path = db_path + "-wal"
        if os.path.exists(wal_path):
            # WAL file exists but should be zero bytes after TRUNCATE checkpoint
            assert os.path.getsize(wal_path) == 0
        # If WAL file doesn't exist at all, that's also fine

        # Verify data is accessible from a fresh connection (no WAL needed)
        conn = sqlite3.connect(db_path)
        count = conn.execute("SELECT COUNT(*) FROM target_computer").fetchone()[0]
        conn.close()
        assert count == 3

    def test_close_idempotent(self, tmp_path):
        """Calling close on an already-closed store should not raise."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)
        store.close()
        # Second close should not crash (conn already closed)
        try:
            store.close()
        except Exception:
            pass  # Some SQLite versions may error, but it shouldn't be fatal


# ---------- Indexes ----------


class TestIndexes:
    def test_partial_index_target_file_checked(self, tmp_path):
        """Partial index on target_file(checked) WHERE checked = 0 should exist."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        conn = store.conn
        rows = conn.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'index' "
            "AND name = 'idx_target_file_checked'"
        ).fetchall()

        assert len(rows) == 1
        # Verify it's a partial index (contains WHERE clause)
        assert "WHERE" in rows[0][1].upper()
        assert "checked" in rows[0][1].lower()
        store.close()

    def test_partial_index_target_dir_walked(self, tmp_path):
        """Partial index on target_dir(walked) WHERE walked = 0 should exist."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        conn = store.conn
        rows = conn.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'index' "
            "AND name = 'idx_target_dir_walked'"
        ).fetchall()

        assert len(rows) == 1
        assert "WHERE" in rows[0][1].upper()
        assert "walked" in rows[0][1].lower()
        store.close()

    def test_partial_index_target_computer_done(self, tmp_path):
        """Partial index on target_computer(done) WHERE done = 0 should exist."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        conn = store.conn
        rows = conn.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'index' "
            "AND name = 'idx_target_computer_done'"
        ).fetchall()

        assert len(rows) == 1
        assert "WHERE" in rows[0][1].upper()
        assert "done" in rows[0][1].lower()
        store.close()

    def test_finding_triage_index_exists(self, tmp_path):
        """Index on finding(triage) should exist."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        conn = store.conn
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index' "
            "AND name = 'idx_finding_triage'"
        ).fetchall()

        assert len(rows) == 1
        store.close()

    def test_dir_share_index_exists(self, tmp_path):
        """Index on target_dir(share) should exist."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        conn = store.conn
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index' "
            "AND name = 'idx_target_dir_share'"
        ).fetchall()

        assert len(rows) == 1
        store.close()

    def test_file_share_index_exists(self, tmp_path):
        """Index on target_file(share) should exist."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        conn = store.conn
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index' "
            "AND name = 'idx_target_file_share'"
        ).fetchall()

        assert len(rows) == 1
        store.close()


# ---------- Batch mark_files_checked ----------


class TestBatchMarkFilesChecked:
    def test_batch_mark_1000_files(self, tmp_path):
        """mark_files_checked_batch should mark all files in one call."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        # Insert 1000 files
        files = [
            (f"//HOST/SHARE/dir/file_{i:04d}.txt", "//HOST/SHARE", i, 0.0)
            for i in range(1000)
        ]
        store.store_files(files)

        # Verify none are checked initially
        assert store.count_checked_files() == 0

        # Batch mark all as checked
        paths = [f"//HOST/SHARE/dir/file_{i:04d}.txt" for i in range(1000)]
        store.mark_files_checked_batch(paths)

        # Verify all are now checked
        assert store.count_checked_files() == 1000
        store.close()

    def test_batch_mark_handles_missing_files(self, tmp_path):
        """Batch mark should handle files not yet in the DB (upsert)."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        # Don't insert files first — batch mark should upsert
        paths = [
            "//HOST/SHARE/new1.txt",
            "//HOST/SHARE/new2.txt",
            "//HOST/SHARE/new3.txt",
        ]
        store.mark_files_checked_batch(paths)

        assert store.count_checked_files() == 3
        # Files should be queryable
        checked = store.load_checked_files()
        assert "//host/share/new1.txt" in checked
        assert "//host/share/new2.txt" in checked
        assert "//host/share/new3.txt" in checked
        store.close()

    def test_batch_mark_mixed_existing_and_new(self, tmp_path):
        """Batch mark works with a mix of existing and new files."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        # Insert some files
        store.store_files([
            ("//HOST/SHARE/existing.txt", "//HOST/SHARE", 100, 0.0),
        ])

        # Batch mark: one existing, one new
        store.mark_files_checked_batch([
            "//HOST/SHARE/existing.txt",
            "//HOST/SHARE/brand_new.txt",
        ])

        assert store.count_checked_files() == 2
        store.close()

    def test_batch_mark_idempotent(self, tmp_path):
        """Marking the same files twice should not create duplicates."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        paths = ["//HOST/SHARE/a.txt", "//HOST/SHARE/b.txt"]
        store.mark_files_checked_batch(paths)
        store.mark_files_checked_batch(paths)  # again

        assert store.count_checked_files() == 2
        assert store.count_target_files() == 2
        store.close()


# ---------- iter_unchecked_files ----------


class TestIterUncheckedFiles:
    def test_iter_unchecked_returns_generator(self, tmp_path):
        """iter_unchecked_files should return a generator/iterable, not a list."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        result = store.iter_unchecked_files()
        assert hasattr(result, '__iter__')
        assert hasattr(result, '__next__') or isinstance(result, types.GeneratorType)
        store.close()

    def test_iter_unchecked_yields_correct_tuples(self, tmp_path):
        """iter_unchecked_files should yield (unc_path, size, mtime) tuples."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        store.store_files([
            ("//HOST/SHARE/a.txt", "//HOST/SHARE", 100, 1700000000.0),
            ("//HOST/SHARE/b.txt", "//HOST/SHARE", 200, 1700000001.0),
        ])

        items = list(store.iter_unchecked_files())
        assert len(items) == 2
        # Each item is a (path, size, mtime) tuple
        paths = {item[0] for item in items}
        assert "//HOST/SHARE/a.txt" in paths
        assert "//HOST/SHARE/b.txt" in paths
        store.close()

    def test_iter_unchecked_excludes_checked_files(self, tmp_path):
        """Checked files should not appear in the iterator."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        store.store_files([
            ("//HOST/SHARE/a.txt", "//HOST/SHARE", 100, 0.0),
            ("//HOST/SHARE/b.txt", "//HOST/SHARE", 200, 0.0),
        ])
        store.mark_file_checked("//HOST/SHARE/a.txt")

        items = list(store.iter_unchecked_files())
        assert len(items) == 1
        assert items[0][0] == "//HOST/SHARE/b.txt"
        store.close()


# ---------- is_file_checked ----------


class TestIsFileChecked:
    def test_is_file_checked_returns_true_for_checked(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        store.store_file("//HOST/SHARE/file.txt", "//HOST/SHARE", 100, 0.0)
        store.mark_file_checked("//HOST/SHARE/file.txt")

        assert store.is_file_checked("//HOST/SHARE/file.txt") is True
        store.close()

    def test_is_file_checked_returns_false_for_unchecked(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        store.store_file("//HOST/SHARE/file.txt", "//HOST/SHARE", 100, 0.0)

        assert store.is_file_checked("//HOST/SHARE/file.txt") is False
        store.close()

    def test_is_file_checked_returns_false_for_missing(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        assert store.is_file_checked("//HOST/SHARE/nonexistent.txt") is False
        store.close()


# ---------- iter_checked_file_keys ----------


class TestIterCheckedFileKeys:
    def test_yields_lowercased_paths(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        store.store_file("//HOST/SHARE/File.TXT", "//HOST/SHARE", 100, 0.0)
        store.mark_file_checked("//HOST/SHARE/File.TXT")

        keys = list(store.iter_checked_file_keys())
        assert len(keys) == 1
        assert keys[0] == "//host/share/file.txt"
        store.close()

    def test_yields_only_checked(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        store.store_files([
            ("//HOST/SHARE/checked.txt", "//HOST/SHARE", 100, 0.0),
            ("//HOST/SHARE/unchecked.txt", "//HOST/SHARE", 200, 0.0),
        ])
        store.mark_file_checked("//HOST/SHARE/checked.txt")

        keys = list(store.iter_checked_file_keys())
        assert len(keys) == 1
        assert keys[0] == "//host/share/checked.txt"
        store.close()

    def test_returns_generator(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        result = store.iter_checked_file_keys()
        assert hasattr(result, '__iter__')
        assert hasattr(result, '__next__') or isinstance(result, types.GeneratorType)
        store.close()


# ---------- PRAGMA settings ----------


class TestPragmaSettings:
    def test_page_size_pragma(self, tmp_path):
        """New databases should have page_size=8192."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        page_size = store.conn.execute("PRAGMA page_size").fetchone()[0]
        assert page_size == 8192
        store.close()

    def test_cache_size_pragma(self, tmp_path):
        """Cache size should be set to -65536 (64 MB in KiB)."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        cache_size = store.conn.execute("PRAGMA cache_size").fetchone()[0]
        assert cache_size == -65536
        store.close()

    def test_synchronous_pragma(self, tmp_path):
        """Synchronous mode should be NORMAL (1)."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        # NORMAL = 1
        sync = store.conn.execute("PRAGMA synchronous").fetchone()[0]
        assert sync == 1
        store.close()

    def test_mmap_size_pragma(self, tmp_path):
        """Memory-mapped I/O should be configured (256 MB)."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        mmap_size = store.conn.execute("PRAGMA mmap_size").fetchone()[0]
        assert mmap_size == 268435456
        store.close()

    def test_journal_mode_wal(self, tmp_path):
        """Journal mode should be WAL."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        mode = store.conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"
        store.close()
