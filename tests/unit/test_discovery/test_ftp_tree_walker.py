import threading
from unittest.mock import MagicMock, patch

import pytest

from snaffler.discovery.ftp_tree_walker import (
    FTPTreeWalker,
    parse_ftp_url,
    build_ftp_url,
    extract_ftp_root,
)


# ---------- URL parsing tests ----------

def test_parse_ftp_url_full():
    assert parse_ftp_url("ftp://10.0.0.5:2121/data") == ("10.0.0.5", 2121, "/data")


def test_parse_ftp_url_default_port():
    assert parse_ftp_url("ftp://10.0.0.5/docs") == ("10.0.0.5", 21, "/docs")


def test_parse_ftp_url_root():
    assert parse_ftp_url("ftp://10.0.0.5") == ("10.0.0.5", 21, "/")


def test_parse_ftp_url_no_path():
    result = parse_ftp_url("ftp://server.local")
    assert result == ("server.local", 21, "/")


def test_parse_ftp_url_invalid():
    assert parse_ftp_url("//server/share") is None
    assert parse_ftp_url("/local/path") is None
    assert parse_ftp_url("http://example.com") is None


def test_build_ftp_url_default_port():
    assert build_ftp_url("10.0.0.5", 21, "/data/file.txt") == "ftp://10.0.0.5/data/file.txt"


def test_build_ftp_url_custom_port():
    assert build_ftp_url("10.0.0.5", 2121, "/file.txt") == "ftp://10.0.0.5:2121/file.txt"


def test_extract_ftp_root_default_port():
    assert extract_ftp_root("ftp://10.0.0.5/data/file.txt") == "ftp://10.0.0.5"


def test_extract_ftp_root_custom_port():
    assert extract_ftp_root("ftp://10.0.0.5:2121/data/file.txt") == "ftp://10.0.0.5:2121"


def test_extract_ftp_root_invalid():
    assert extract_ftp_root("/local/path") == "/local/path"


# ---------- helpers ----------

def make_cfg():
    cfg = MagicMock()
    cfg.rules.directory = []
    cfg.targets.exclude_unc = []
    cfg.targets.ftp_tls = False
    cfg.auth.username = "user"
    cfg.auth.password = "pass"
    cfg.auth.smb_timeout = 5
    return cfg


def collect_callback():
    collected = []
    def on_file(path, size, mtime):
        collected.append((path, size, mtime))
    return on_file, collected


def collect_dir_callback():
    collected = []
    def on_dir(path):
        collected.append(path)
    return on_dir, collected


# ---------- MLSD walk tests ----------

def test_walk_directory_mlsd_files_and_dirs():
    cfg = make_cfg()
    walker = FTPTreeWalker(cfg)

    ftp = MagicMock()
    ftp.voidcmd.return_value = "200 OK"
    ftp.mlsd.return_value = [
        (".", {"type": "cdir"}),
        ("..", {"type": "pdir"}),
        ("subdir", {"type": "dir"}),
        ("file.txt", {"type": "file", "size": "1234", "modify": "20240101120000"}),
    ]

    with patch.object(walker.ftp_transport, "connect", return_value=ftp):
        on_file, files = collect_callback()
        on_dir, dirs = collect_dir_callback()
        subdirs = walker.walk_directory("ftp://10.0.0.5/data", on_file, on_dir)

    assert subdirs == ["ftp://10.0.0.5/data/subdir"]
    assert dirs == ["ftp://10.0.0.5/data/subdir"]
    assert len(files) == 1
    assert files[0][0] == "ftp://10.0.0.5/data/file.txt"
    assert files[0][1] == 1234


def test_walk_directory_mlsd_custom_port():
    cfg = make_cfg()
    walker = FTPTreeWalker(cfg)

    ftp = MagicMock()
    ftp.voidcmd.return_value = "200 OK"
    ftp.mlsd.return_value = [
        ("readme.md", {"type": "file", "size": "42", "modify": "20240601000000"}),
    ]

    with patch.object(walker.ftp_transport, "connect", return_value=ftp):
        on_file, files = collect_callback()
        subdirs = walker.walk_directory("ftp://10.0.0.5:2121/docs", on_file)

    assert subdirs == []
    assert files[0][0] == "ftp://10.0.0.5:2121/docs/readme.md"


def test_walk_directory_cancel():
    from concurrent.futures import CancelledError

    cfg = make_cfg()
    walker = FTPTreeWalker(cfg)

    cancel = threading.Event()
    cancel.set()

    with pytest.raises(CancelledError):
        walker.walk_directory("ftp://10.0.0.5/data", cancel=cancel)


def test_walk_directory_invalid_url():
    cfg = make_cfg()
    walker = FTPTreeWalker(cfg)

    subdirs = walker.walk_directory("INVALID")
    assert subdirs == []


# ---------- NLST fallback tests ----------

def test_walk_directory_nlst_fallback():
    cfg = make_cfg()
    walker = FTPTreeWalker(cfg)

    ftp = MagicMock()
    ftp.voidcmd.return_value = "200 OK"
    ftp.mlsd.side_effect = Exception("500 MLSD not supported")
    ftp.nlst.return_value = ["/data/file.txt", "/data/subdir"]
    ftp.size.side_effect = [100, Exception("550 not a file")]
    ftp.sendcmd.return_value = "213 20240101120000"

    with patch.object(walker.ftp_transport, "connect", return_value=ftp):
        on_file, files = collect_callback()
        on_dir, dirs = collect_dir_callback()
        subdirs = walker.walk_directory("ftp://10.0.0.5/data", on_file, on_dir)

    assert len(files) == 1
    assert files[0][0] == "ftp://10.0.0.5/data/file.txt"
    assert files[0][1] == 100
    assert len(subdirs) == 1
    assert subdirs[0] == "ftp://10.0.0.5/data/subdir"


# ---------- connection caching tests ----------

def test_connection_reuse():
    cfg = make_cfg()
    walker = FTPTreeWalker(cfg)

    ftp = MagicMock()
    ftp.voidcmd.return_value = "200 OK"
    ftp.mlsd.return_value = [("f.txt", {"type": "file", "size": "10", "modify": "20240101000000"})]

    with patch.object(walker.ftp_transport, "connect", return_value=ftp) as mock_connect:
        walker.walk_directory("ftp://10.0.0.5/dir1")
        walker.walk_directory("ftp://10.0.0.5/dir2")

    mock_connect.assert_called_once_with("10.0.0.5", 21)


def test_stale_connection_reconnects():
    """If the cached connection goes stale, _get_ftp evicts it and reconnects."""
    cfg = make_cfg()
    walker = FTPTreeWalker(cfg)

    stale_ftp = MagicMock()
    # First _get_ftp: not cached yet → connect creates stale_ftp (no NOOP check).
    # Second _get_ftp: cached → NOOP succeeds (still alive).
    # Third _get_ftp: cached → NOOP fails → evict → reconnect.
    stale_ftp.voidcmd.side_effect = ["200 OK", Exception("dead")]
    stale_ftp.mlsd.return_value = [("a.txt", {"type": "file", "size": "1", "modify": "20240101000000"})]

    fresh_ftp = MagicMock()
    fresh_ftp.voidcmd.return_value = "200 OK"
    fresh_ftp.mlsd.return_value = [("b.txt", {"type": "file", "size": "2", "modify": "20240101000000"})]

    call_count = [0]
    def connect_side(host, port):
        call_count[0] += 1
        return stale_ftp if call_count[0] == 1 else fresh_ftp

    with patch.object(walker.ftp_transport, "connect", side_effect=connect_side) as mock_connect:
        on_file, files = collect_callback()
        walker.walk_directory("ftp://10.0.0.5/dir1", on_file)  # creates stale_ftp
        walker.walk_directory("ftp://10.0.0.5/dir2", on_file)  # NOOP ok, reuses
        walker.walk_directory("ftp://10.0.0.5/dir3", on_file)  # NOOP fails → reconnect

    assert mock_connect.call_count == 2
    assert len(files) == 3


def test_connection_error_invalidates():
    cfg = make_cfg()
    walker = FTPTreeWalker(cfg)

    ftp = MagicMock()
    ftp.voidcmd.return_value = "200 OK"
    ftp.mlsd.side_effect = OSError("connection reset")
    ftp.nlst.side_effect = OSError("connection reset")

    with patch.object(walker.ftp_transport, "connect", return_value=ftp):
        with pytest.raises(OSError):
            walker.walk_directory("ftp://10.0.0.5/data")

    ftp.quit.assert_called_once()


# ---------- exclude-unc tests ----------

def test_exclude_unc_filters_ftp_dirs():
    cfg = make_cfg()
    cfg.targets.exclude_unc = ["*/node_modules*"]

    walker = FTPTreeWalker(cfg)

    ftp = MagicMock()
    ftp.voidcmd.return_value = "200 OK"
    ftp.mlsd.return_value = [
        ("node_modules", {"type": "dir"}),
        ("src", {"type": "dir"}),
    ]

    with patch.object(walker.ftp_transport, "connect", return_value=ftp):
        subdirs = walker.walk_directory("ftp://10.0.0.5/project")

    assert len(subdirs) == 1
    assert "src" in subdirs[0]


# ---------- _parse_mlsd_modify ----------

def test_parse_mlsd_modify_valid():
    ts = FTPTreeWalker._parse_mlsd_modify("20240101120000")
    assert ts > 0


def test_parse_mlsd_modify_empty():
    assert FTPTreeWalker._parse_mlsd_modify("") == 0.0


def test_parse_mlsd_modify_short():
    assert FTPTreeWalker._parse_mlsd_modify("2024") == 0.0
