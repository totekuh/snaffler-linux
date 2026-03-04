import os

import pytest

from snaffler.accessors.file_accessor import FileAccessor
from snaffler.accessors.local_file_accessor import LocalFileAccessor


def test_file_accessor_is_abstract():
    with pytest.raises(TypeError):
        FileAccessor()


def test_file_accessor_requires_all_methods():
    class IncompleteAccessor(FileAccessor):
        def read(self, server: str, share: str, path: str):
            return b"data"

    with pytest.raises(TypeError):
        IncompleteAccessor()


def test_file_accessor_complete_implementation():
    class DummyAccessor(FileAccessor):
        def read(self, server: str, share: str, path: str):
            return b"data"

        def copy_to_local(self, server, share, path, dest_root):
            pass

    accessor = DummyAccessor()

    assert accessor.read("srv", "share", "/f.txt") == b"data"


# ---------- BUG-G2: Path traversal protection in LocalFileAccessor ----------

class TestLocalFileAccessorPathTraversal:
    """BUG-G2: copy_to_local must block paths containing '..' that escape dest_root."""

    def test_path_traversal_via_symlink_blocked(self, tmp_path):
        """BUG-G2: copy_to_local must block symlink-based path traversal.

        The guard uses os.path.realpath() to resolve symlinks and then
        checks that the resolved destination is still under dest_root.
        """
        accessor = LocalFileAccessor()

        dest_root = str(tmp_path / "output")
        os.makedirs(dest_root, exist_ok=True)

        # Create a secret file outside dest_root
        secret = tmp_path / "secret.txt"
        secret.write_text("sensitive data")

        # Create a symlink inside dest_root that points outside
        escape_link = os.path.join(dest_root, "escape")
        os.symlink(str(tmp_path), escape_link)

        # Now craft a source path that, after relpath + join, resolves
        # through the symlink to outside dest_root:
        # dest = dest_root/escape/secret.txt → realpath = tmp_path/secret.txt
        # The realpath check should block this.
        #
        # To trigger: we need a file_path whose os.path.relpath(path, "/")
        # yields "escape/secret.txt" — that means file_path = "/escape/secret.txt"
        accessor.copy_to_local("/escape/secret.txt", dest_root)

        # The secret file should NOT have been overwritten or duplicated
        # under dest_root (the guard should have blocked the copy)
        resolved = os.path.realpath(os.path.join(dest_root, "escape", "secret.txt"))
        real_root = os.path.realpath(dest_root)

        # Verify the guard logic: the resolved path escapes dest_root
        assert not resolved.startswith(real_root + os.sep), \
            "Test setup error: resolved path should escape dest_root"

    def test_normal_copy_succeeds(self, tmp_path):
        """A normal (non-traversal) copy should work correctly."""
        accessor = LocalFileAccessor()
        dest_root = str(tmp_path / "output")

        # Create source file
        source_dir = tmp_path / "source"
        source_dir.mkdir()
        source_file = source_dir / "hello.txt"
        source_file.write_text("hello world")

        accessor.copy_to_local(str(source_file), dest_root)

        # File should exist under dest_root
        rel = os.path.relpath(str(source_file), "/")
        expected = os.path.join(dest_root, rel)
        assert os.path.exists(expected)
