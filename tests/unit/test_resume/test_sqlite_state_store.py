import tempfile
import os

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
