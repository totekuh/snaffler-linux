"""
Integration test: full pipeline with mocked SMB transport.

Real rules, real evaluator, real scanner, real tree walker — only the
SMB connection is faked.  The existing tests/data/ directory (used by
unit tests for rule-level assertions) is served as a fake SMB share.

This validates that the pipeline wiring works end-to-end: files go in,
findings come out, progress counters update.  Detection correctness
is already covered by unit tests — these tests prove the plumbing.
"""

import logging
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from snaffler.classifiers.loader import RuleLoader
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.engine.file_pipeline import FilePipeline
from snaffler.engine.share_pipeline import SharePipeline
from snaffler.utils.progress import ProgressState

# ---------------------------------------------------------------------------
# The fake share root is the existing test data directory.
# Unit tests already prove each file triggers the right rule — here we
# just verify the pipeline feeds them through and produces output.
# ---------------------------------------------------------------------------

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def cfg():
    """Minimal real configuration with real rules loaded."""
    c = SnafflerConfiguration()
    c.auth.username = "test"
    c.auth.password = "test"
    c.scanning.max_read_bytes = 2 * 1024 * 1024
    c.scanning.max_file_bytes = 10 * 1024 * 1024
    c.scanning.match_context_bytes = 200
    c.scanning.min_interest = 0
    c.advanced.share_threads = 2
    c.advanced.tree_threads = 2
    c.advanced.file_threads = 2
    RuleLoader.load(c)
    return c


# ---------------------------------------------------------------------------
# SMB mock helpers
# ---------------------------------------------------------------------------

class FakeSharedFile:
    """Mimics impacket SharedFile for directory listings."""

    def __init__(self, name: str, is_dir: bool, size: int = 0):
        self._name = name
        self._is_dir = is_dir
        self._size = size

    def get_longname(self):
        return self._name

    def is_directory(self):
        return self._is_dir

    def get_filesize(self):
        return self._size

    def get_mtime_epoch(self):
        return datetime(2026, 1, 15, 12, 0, 0).timestamp()


def _build_list_path(share_root: Path):
    """Return a listPath callable that reads from the local filesystem."""

    def _list_path(share_name, pattern):
        # pattern looks like "/subdir/*" or "/*"
        rel = pattern.rstrip("*").replace("\\", "/").strip("/")
        local_dir = share_root / rel if rel else share_root

        entries = [
            FakeSharedFile(".", True),
            FakeSharedFile("..", True),
        ]

        if not local_dir.is_dir():
            from impacket.smbconnection import SessionError
            from impacket.nt_errors import STATUS_ACCESS_DENIED
            raise SessionError(STATUS_ACCESS_DENIED)

        for child in sorted(local_dir.iterdir()):
            size = child.stat().st_size if child.is_file() else 0
            entries.append(FakeSharedFile(child.name, child.is_dir(), size))

        return entries

    return _list_path


def _build_get_file(share_root: Path):
    """Return a getFile callable that reads from the local filesystem."""

    def _get_file(share_name, path, callback, offset=0, max_bytes=None):
        rel = path.replace("\\", "/").lstrip("/")
        local = share_root / rel
        data = local.read_bytes()
        if max_bytes is not None:
            data = data[offset:offset + max_bytes]
        else:
            data = data[offset:]
        callback(data)

    return _get_file


def _make_smb_mock(share_root: Path):
    """Create a mock SMBConnection backed by the local filesystem."""
    smb = MagicMock()
    smb.getServerName.return_value = "FAKEHOST"

    # listShares → one disk share
    smb.listShares.return_value = [
        {
            "shi1_netname": "TestShare\x00",
            "shi1_type": 0,  # STYPE_DISKTREE
            "shi1_remark": "Test share\x00",
        },
    ]

    smb.listPath.side_effect = _build_list_path(share_root)

    # connectTree / openFile / closeFile for can_read()
    smb.connectTree.return_value = 1
    smb.openFile.return_value = 1
    smb.closeFile.return_value = None

    # getFile for file content reads
    smb.getFile.side_effect = _build_get_file(share_root)

    return smb


def _patch_transports(share_root):
    """Context manager that patches all three SMBTransport import sites."""
    smb = _make_smb_mock(share_root)
    return (
        smb,
        patch("snaffler.discovery.shares.SMBTransport",
              return_value=MagicMock(connect=MagicMock(return_value=smb))),
        patch("snaffler.discovery.tree.SMBTransport",
              return_value=MagicMock(connect=MagicMock(return_value=smb))),
        patch("snaffler.accessors.smb_file_accessor.SMBTransport",
              return_value=MagicMock(connect=MagicMock(return_value=smb))),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSharePipeline:
    """Share discovery produces UNC paths."""

    def test_discovers_readable_share(self, cfg):
        smb = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.discovery.shares.SMBTransport") as t:
            t.return_value.connect.return_value = smb

            paths = SharePipeline(cfg=cfg).run(["10.0.0.1"])

        assert paths == ["//10.0.0.1/TestShare"]

    def test_updates_progress_counters(self, cfg):
        smb = _make_smb_mock(_DATA_DIR)
        progress = ProgressState()

        with patch("snaffler.discovery.shares.SMBTransport") as t:
            t.return_value.connect.return_value = smb

            SharePipeline(cfg=cfg, progress=progress).run(["10.0.0.1"])

        assert progress.computers_done == 1
        assert progress.shares_found == 1


class TestFilePipeline:
    """File pipeline walks, scans, and classifies."""

    def test_finds_matches(self, cfg):
        """Pipeline produces findings from the test data directory."""
        smb = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.discovery.tree.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            progress = ProgressState()
            matched = FilePipeline(cfg=cfg, progress=progress).run(
                ["//10.0.0.1/TestShare"]
            )

        # tests/data has 217 files; the pipeline should walk all of them
        assert progress.files_scanned > 0
        # many of those files are designed to trigger rules
        assert matched > 0
        assert progress.files_matched == matched

    def test_scans_more_files_than_matches(self, cfg):
        """Pipeline scans files that don't match (images, benign txt)."""
        smb = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.discovery.tree.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            progress = ProgressState()
            FilePipeline(cfg=cfg, progress=progress).run(
                ["//10.0.0.1/TestShare"]
            )

        # Not every file should match — some are benign or discarded
        assert progress.files_scanned > progress.files_matched


class TestEndToEnd:
    """Full chain: SharePipeline -> FilePipeline."""

    def test_share_discovery_through_file_scan(self, cfg):
        """Complete flow from computer IP to findings."""
        smb = _make_smb_mock(_DATA_DIR)
        progress = ProgressState()

        with patch("snaffler.discovery.shares.SMBTransport") as st, \
                patch("snaffler.discovery.tree.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            st.return_value.connect.return_value = smb
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            paths = SharePipeline(cfg=cfg, progress=progress).run(["10.0.0.1"])
            matched = FilePipeline(cfg=cfg, progress=progress).run(paths)

        # Share discovery worked
        assert progress.computers_done == 1
        assert progress.shares_found == 1

        # File scanning worked
        assert progress.files_scanned > 0
        assert matched > 0

    def test_findings_appear_in_log_output(self, cfg, caplog):
        """Findings are emitted as log records (the output the user sees)."""
        smb = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.discovery.tree.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at, \
                caplog.at_level(logging.WARNING, logger="snaffler"):
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            FilePipeline(cfg=cfg).run(["//10.0.0.1/TestShare"])

        # The pipeline should have emitted WARNING-level log records
        # (findings are logged at WARNING or above)
        assert len(caplog.records) > 0
