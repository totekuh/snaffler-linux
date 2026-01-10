import pytest

from snaffler.accessors.file_accessor import FileAccessor


def test_file_accessor_is_abstract():
    with pytest.raises(TypeError):
        FileAccessor()


def test_file_accessor_requires_all_methods():
    class IncompleteAccessor(FileAccessor):
        def can_read(self, server: str, share: str, path: str) -> bool:
            return True

    with pytest.raises(TypeError):
        IncompleteAccessor()


def test_file_accessor_complete_implementation():
    class DummyAccessor(FileAccessor):
        def can_read(self, server: str, share: str, path: str) -> bool:
            return True

        def read(self, server: str, share: str, path: str):
            return b"data"

        def copy_to_local(self, server, share, path, dest_root):
            pass

    accessor = DummyAccessor()

    assert accessor.can_read("srv", "share", "/f.txt") is True
    assert accessor.read("srv", "share", "/f.txt") == b"data"
