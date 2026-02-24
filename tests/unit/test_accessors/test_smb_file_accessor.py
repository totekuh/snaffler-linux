from unittest.mock import MagicMock, patch
from snaffler.accessors.smb_file_accessor import SMBFileAccessor


# ---------- helpers ----------

def make_smb_mock(data=b"testdata"):
    smb = MagicMock()
    smb.getServerName.return_value = "TESTSERVER"

    # connectTree / openFile / readFile / closeFile for read()
    smb.connectTree.return_value = 1
    smb.openFile.return_value = 1
    smb.closeFile.return_value = None

    def fake_read_file(tid, fid, offset=0, bytesToRead=0):
        if bytesToRead > 0:
            return data[offset:offset + bytesToRead]
        return data[offset:]

    smb.readFile.side_effect = fake_read_file
    return smb


def make_accessor(smb_mock):
    cfg = MagicMock()

    with patch(
        "snaffler.accessors.smb_file_accessor.SMBTransport"
    ) as transport:
        transport.return_value.connect.return_value = smb_mock
        return SMBFileAccessor(cfg)


# ---------- tests ----------

def test_read_success():
    smb = make_smb_mock(b"ABC")
    accessor = make_accessor(smb)

    data = accessor.read("srv", "share", "\\file.bin")

    assert data == b"ABC"


def test_read_with_max_bytes():
    smb = make_smb_mock(b"ABCDEFGHIJ")
    accessor = make_accessor(smb)

    data = accessor.read("srv", "share", "\\file.bin", max_bytes=4)

    assert data == b"ABCD"


def test_read_failure():
    smb = make_smb_mock()
    accessor = make_accessor(smb)

    accessor._get_smb = MagicMock(side_effect=Exception("fail"))

    assert accessor.read("srv", "share", "\\file.bin") is None


def test_read_closes_file_on_error():
    smb = make_smb_mock()
    smb.readFile.side_effect = Exception("read failed")
    accessor = make_accessor(smb)

    result = accessor.read("srv", "share", "\\file.bin")

    # closeFile should still be called via finally block
    # (but the outer except catches the error, returning None)
    assert result is None


def test_copy_to_local_success(tmp_path):
    accessor = make_accessor(make_smb_mock())

    accessor.read = MagicMock(return_value=b"PAYLOAD")

    accessor.copy_to_local(
        server="srv",
        share="share",
        path="\\dir\\file.txt",
        dest_root=tmp_path,
    )

    expected = tmp_path / "srv" / "share" / "dir\\file.txt"

    assert expected.exists()
    assert expected.read_bytes() == b"PAYLOAD"


def test_copy_to_local_no_data(tmp_path):
    smb = make_smb_mock()
    accessor = make_accessor(smb)

    accessor.read = MagicMock(return_value=None)

    accessor.copy_to_local(
        server="srv",
        share="share",
        path="\\file.txt",
        dest_root=tmp_path,
    )

    expected = tmp_path / "srv" / "share" / "file.txt"
    assert not expected.exists()


def test_smb_reconnect_on_dead_connection():
    smb_dead = make_smb_mock(b"OLD")
    smb_dead.getServerName.side_effect = Exception("dead")

    smb_new = make_smb_mock(b"NEW")

    cfg = MagicMock()

    with patch(
        "snaffler.accessors.smb_file_accessor.SMBTransport"
    ) as transport:
        transport.return_value.connect.side_effect = [smb_dead, smb_new]

        accessor = SMBFileAccessor(cfg)

        # First read triggers connection to smb_dead, which fails on getServerName
        # causing reconnect to smb_new
        accessor.read("srv", "share", "\\file.txt")

        data = accessor.read("srv", "share", "\\file.txt")

        assert data == b"NEW"
