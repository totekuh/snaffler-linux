from unittest.mock import MagicMock, patch
from snaffler.accessors.smb_file_accessor import SMBFileAccessor


# ---------- helpers ----------

def make_smb_mock(data=b"testdata"):
    smb = MagicMock()
    smb.getServerName.return_value = "TESTSERVER"

    def fake_get_file(share, path, callback, offset=0, length=None):
        if length is not None:
            callback(data[offset:offset + length])
        else:
            callback(data)

    smb.getFile.side_effect = fake_get_file
    return smb


def make_accessor(smb_mock):
    cfg = MagicMock()

    with patch(
        "snaffler.accessors.smb_file_accessor.SMBTransport"
    ) as transport:
        transport.return_value.connect.return_value = smb_mock
        return SMBFileAccessor(cfg)


# ---------- tests ----------

def test_can_read_success():
    smb = make_smb_mock()
    accessor = make_accessor(smb)

    assert accessor.can_read("srv", "share", "\\test.txt") is True


def test_can_read_failure():
    smb = make_smb_mock()
    accessor = make_accessor(smb)

    accessor._get_smb = MagicMock(side_effect=Exception("fail"))

    assert accessor.can_read("srv", "share", "\\test.txt") is False


def test_read_success():
    smb = make_smb_mock(b"ABC")
    accessor = make_accessor(smb)

    data = accessor.read("srv", "share", "\\file.bin")

    assert data == b"ABC"


def test_read_failure():
    smb = make_smb_mock()
    accessor = make_accessor(smb)

    accessor._get_smb = MagicMock(side_effect=Exception("fail"))

    assert accessor.read("srv", "share", "\\file.bin") is None


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

        accessor.can_read("srv", "share", "\\file.txt")

        data = accessor.read("srv", "share", "\\file.txt")

        assert data == b"NEW"
