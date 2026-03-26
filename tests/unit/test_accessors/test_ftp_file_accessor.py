from unittest.mock import MagicMock, patch

from snaffler.accessors.ftp_file_accessor import FTPFileAccessor


# ---------- helpers ----------

def make_ftp_mock():
    ftp = MagicMock()
    ftp.voidcmd.return_value = "200 OK"
    return ftp


def make_accessor(ftp_mock=None, max_file_bytes=10485760):
    cfg = MagicMock()
    cfg.scanning.max_file_bytes = max_file_bytes
    cfg.auth.username = "user"
    cfg.auth.password = "pass"
    cfg.auth.smb_timeout = 5
    cfg.targets.ftp_tls = False

    with patch("snaffler.accessors.ftp_file_accessor.FTPTransport") as transport:
        if ftp_mock:
            transport.return_value.connect.return_value = ftp_mock
        return FTPFileAccessor(cfg)


# ---------- tests ----------

def test_read_success():
    ftp = make_ftp_mock()

    def fake_retrbinary(cmd, callback):
        callback(b"HELLO")

    ftp.retrbinary.side_effect = fake_retrbinary
    accessor = make_accessor(ftp)

    data = accessor.read("ftp://10.0.0.5/file.txt")
    assert data == b"HELLO"


def test_read_with_max_bytes():
    ftp = make_ftp_mock()

    def fake_retrbinary(cmd, callback):
        callback(b"ABCDEFGHIJ")

    ftp.retrbinary.side_effect = fake_retrbinary
    accessor = make_accessor(ftp)

    data = accessor.read("ftp://10.0.0.5/file.txt", max_bytes=4)
    assert data == b"ABCD"


def test_read_multiple_chunks():
    ftp = make_ftp_mock()

    def fake_retrbinary(cmd, callback):
        callback(b"AAA")
        callback(b"BBB")
        callback(b"CCC")

    ftp.retrbinary.side_effect = fake_retrbinary
    accessor = make_accessor(ftp)

    data = accessor.read("ftp://10.0.0.5/file.txt")
    assert data == b"AAABBBCCC"


def test_read_max_bytes_across_chunks():
    ftp = make_ftp_mock()

    def fake_retrbinary(cmd, callback):
        callback(b"AAAA")
        callback(b"BBBB")
        callback(b"CCCC")

    ftp.retrbinary.side_effect = fake_retrbinary
    accessor = make_accessor(ftp)

    data = accessor.read("ftp://10.0.0.5/file.txt", max_bytes=6)
    assert data == b"AAAABB"


def test_read_invalid_path():
    accessor = make_accessor(make_ftp_mock())
    assert accessor.read("INVALID") is None


def test_read_failure_returns_none():
    ftp = make_ftp_mock()
    ftp.retrbinary.side_effect = Exception("transfer failed")
    accessor = make_accessor(ftp)

    assert accessor.read("ftp://10.0.0.5/file.txt") is None


def test_read_failure_invalidates_connection():
    ftp = make_ftp_mock()
    ftp.retrbinary.side_effect = Exception("transfer failed")
    accessor = make_accessor(ftp)

    accessor.read("ftp://10.0.0.5/file.txt")

    ftp.quit.assert_called_once()


def test_copy_to_local_success(tmp_path):
    ftp = make_ftp_mock()

    def fake_retrbinary(cmd, callback):
        callback(b"PAYLOAD")

    ftp.retrbinary.side_effect = fake_retrbinary
    accessor = make_accessor(ftp)

    accessor.copy_to_local("ftp://10.0.0.5/dir/file.txt", tmp_path)

    expected = tmp_path / "10.0.0.5" / "dir" / "file.txt"
    assert expected.exists()
    assert expected.read_bytes() == b"PAYLOAD"


def test_copy_to_local_no_data(tmp_path):
    ftp = make_ftp_mock()
    ftp.retrbinary.side_effect = Exception("file not found")
    accessor = make_accessor(ftp)

    accessor.copy_to_local("ftp://10.0.0.5/file.txt", tmp_path)

    expected = tmp_path / "10.0.0.5" / "file.txt"
    assert not expected.exists()


def test_copy_to_local_invalid_path(tmp_path):
    accessor = make_accessor(make_ftp_mock())
    # Should not raise
    accessor.copy_to_local("INVALID", tmp_path)


def test_copy_to_local_path_traversal_blocked(tmp_path):
    ftp = make_ftp_mock()

    def fake_retrbinary(cmd, callback):
        callback(b"EVIL")

    ftp.retrbinary.side_effect = fake_retrbinary
    accessor = make_accessor(ftp)

    accessor.copy_to_local("ftp://10.0.0.5/../../etc/passwd", tmp_path)

    # Should NOT write outside dest_root
    assert not (tmp_path / "etc" / "passwd").exists()


def test_connection_reuse():
    ftp = make_ftp_mock()

    def fake_retrbinary(cmd, callback):
        callback(b"DATA")

    ftp.retrbinary.side_effect = fake_retrbinary

    cfg = MagicMock()
    cfg.scanning.max_file_bytes = 10485760
    cfg.auth.username = "user"
    cfg.auth.password = "pass"
    cfg.auth.smb_timeout = 5
    cfg.targets.ftp_tls = False

    with patch("snaffler.accessors.ftp_file_accessor.FTPTransport") as transport:
        transport.return_value.connect.return_value = ftp
        accessor = FTPFileAccessor(cfg)

        accessor.read("ftp://10.0.0.5/file1.txt")
        accessor.read("ftp://10.0.0.5/file2.txt")

    transport.return_value.connect.assert_called_once_with("10.0.0.5", 21)


# ---------- early transfer abort tests ----------

def test_read_max_bytes_aborts_transfer():
    """When max_bytes is reached, the callback raises to abort the data
    transfer rather than downloading the entire file."""
    ftp = make_ftp_mock()
    chunks_sent = []

    def fake_retrbinary(cmd, callback):
        # Simulates a server sending many chunks — only the first few
        # should be consumed before the callback aborts.
        for i in range(100):
            chunks_sent.append(i)
            callback(b"X" * 1024)  # 1KB per chunk

    ftp.retrbinary.side_effect = fake_retrbinary
    accessor = make_accessor(ftp, max_file_bytes=10485760)

    data = accessor.read("ftp://10.0.0.5/big.bin", max_bytes=2048)

    # Should have exactly 2048 bytes (2 full chunks)
    assert data == b"X" * 2048
    # The transfer should have been aborted after 3 chunks
    # (2 consumed + 1 that triggers the abort)
    assert len(chunks_sent) == 3


def test_read_max_bytes_invalidates_after_abort():
    """After aborting a transfer, the FTP connection is invalidated
    because the control channel may be in a bad state."""
    ftp = make_ftp_mock()

    def fake_retrbinary(cmd, callback):
        callback(b"A" * 100)
        callback(b"B" * 100)  # this triggers abort when max_bytes=100

    ftp.retrbinary.side_effect = fake_retrbinary
    accessor = make_accessor(ftp, max_file_bytes=10485760)

    data = accessor.read("ftp://10.0.0.5/file.bin", max_bytes=100)
    assert data == b"A" * 100

    # Connection should have been invalidated (quit called)
    ftp.quit.assert_called_once()


# ---------- reconnection tests ----------

def test_reconnect_on_dead_connection():
    dead_ftp = make_ftp_mock()
    dead_ftp.voidcmd.side_effect = Exception("dead")

    fresh_ftp = make_ftp_mock()

    def fake_retrbinary(cmd, callback):
        callback(b"FRESH")

    fresh_ftp.retrbinary.side_effect = fake_retrbinary

    cfg = MagicMock()
    cfg.scanning.max_file_bytes = 10485760
    cfg.auth.username = "user"
    cfg.auth.password = "pass"
    cfg.auth.smb_timeout = 5
    cfg.targets.ftp_tls = False

    with patch("snaffler.accessors.ftp_file_accessor.FTPTransport") as transport:
        transport.return_value.connect.side_effect = [dead_ftp, fresh_ftp]
        accessor = FTPFileAccessor(cfg)

        # First read: dead_ftp fails NOOP → reconnects → but dead_ftp retrbinary
        # actually raises from the invalidate path. Second call gets fresh_ftp.
        accessor.read("ftp://10.0.0.5/file.txt")
        data = accessor.read("ftp://10.0.0.5/file.txt")

    assert data == b"FRESH"
