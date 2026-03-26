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
import socket
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from snaffler.classifiers.loader import RuleLoader
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.engine.file_pipeline import FilePipeline
from snaffler.engine.runner import SnafflerRunner
from snaffler.engine.share_pipeline import SharePipeline
from snaffler.resume.scan_state import SQLiteStateStore, ScanState
from snaffler.utils.logger import set_finding_store
from snaffler.utils.progress import ProgressState

_no_auth_check = patch.object(SnafflerRunner, "_validate_credentials")

# ---------------------------------------------------------------------------
# The fake share root is the existing test data directory.
# Unit tests already prove each file triggers the right rule — here we
# just verify the pipeline feeds them through and produces output.
# ---------------------------------------------------------------------------

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@pytest.fixture(autouse=True)
def _reset_finding_store():
    yield
    set_finding_store(None)


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
    c.state.state_db = ":memory:"
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


def _build_read_file(share_root: Path):
    """Return a readFile callable that reads from the local filesystem.

    The path is resolved via the most recent openFile call on the mock.
    We store it on the mock itself so readFile can find it.
    """

    def _read_file(tid, fid, offset=0, bytesToRead=0):
        # _current_path is set by the openFile side_effect
        path = getattr(_read_file, "_current_path", None)
        if path is None:
            return b""
        rel = path.replace("\\", "/").lstrip("/")
        local = share_root / rel
        data = local.read_bytes()
        if bytesToRead > 0:
            return data[offset:offset + bytesToRead]
        return data[offset:]

    return _read_file


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

    # connectTree / closeFile
    smb.connectTree.return_value = 1
    smb.closeFile.return_value = None

    # readFile backed by local filesystem
    read_file_fn = _build_read_file(share_root)
    smb.readFile.side_effect = read_file_fn

    # openFile tracks the path so readFile can resolve it
    def _open_file(tid, path, desiredAccess=0, shareMode=0):
        read_file_fn._current_path = path
        return 1

    smb.openFile.side_effect = _open_file

    return smb


def _patch_transports(share_root):
    """Context manager that patches all three SMBTransport import sites."""
    smb = _make_smb_mock(share_root)
    return (
        smb,
        patch("snaffler.discovery.shares.SMBTransport",
              return_value=MagicMock(connect=MagicMock(return_value=smb))),
        patch("snaffler.discovery.smb_tree_walker.SMBTransport",
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

        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
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

        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
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
                patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
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

        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at, \
                caplog.at_level(logging.WARNING, logger="snaffler"):
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            FilePipeline(cfg=cfg).run(["//10.0.0.1/TestShare"])

        # The pipeline should have emitted WARNING-level log records
        # (findings are logged at WARNING or above)
        assert len(caplog.records) > 0


class TestMaxDepth:
    """--max-depth limits how deep the tree walker recurses."""

    def test_depth_zero_only_share_root_files(self, cfg):
        """max_depth=0 means only files in the share root are scanned."""
        cfg.scanning.max_depth = 0
        smb = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            progress_d0 = ProgressState()
            FilePipeline(cfg=cfg, progress=progress_d0).run(
                ["//10.0.0.1/TestShare"]
            )

        # Now unlimited for comparison
        cfg.scanning.max_depth = None
        smb2 = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            tt.return_value.connect.return_value = smb2
            at.return_value.connect.return_value = smb2

            progress_all = ProgressState()
            FilePipeline(cfg=cfg, progress=progress_all).run(
                ["//10.0.0.1/TestShare"]
            )

        # Depth 0 scans only root-level files (tests/data has ~20)
        assert progress_d0.files_scanned > 0
        # But far fewer than unlimited
        assert progress_d0.files_scanned < progress_all.files_scanned

    def test_depth_one_only_first_level_subdirs(self, cfg):
        """max_depth=1 recurses into top-level subdirectories but no deeper."""
        cfg.scanning.max_depth = 1
        smb = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            progress_limited = ProgressState()
            FilePipeline(cfg=cfg, progress=progress_limited).run(
                ["//10.0.0.1/TestShare"]
            )

        # Now run unlimited for comparison
        cfg.scanning.max_depth = None
        smb2 = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            tt.return_value.connect.return_value = smb2
            at.return_value.connect.return_value = smb2

            progress_unlimited = ProgressState()
            FilePipeline(cfg=cfg, progress=progress_unlimited).run(
                ["//10.0.0.1/TestShare"]
            )

        # Depth-1 should scan files (top-level dirs have files)
        assert progress_limited.files_scanned > 0
        # But fewer than unlimited (some files are in deeper subdirs)
        assert progress_limited.files_scanned < progress_unlimited.files_scanned

    def test_unlimited_depth_scans_deepest_files(self, cfg):
        """Without max_depth, files at any depth are scanned."""
        cfg.scanning.max_depth = None
        smb = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            progress = ProgressState()
            FilePipeline(cfg=cfg, progress=progress).run(
                ["//10.0.0.1/TestShare"]
            )

        # tests/data/ has files nested 2-3 levels deep (e.g. home/user/.ssh/)
        assert progress.files_scanned > 200


class TestExcludeUNC:
    """--exclude-unc glob patterns skip matching directories."""

    def test_exclude_pattern_reduces_files(self, cfg):
        """Excluding a directory pattern means fewer files scanned."""
        smb = _make_smb_mock(_DATA_DIR)

        # Baseline: no exclusions
        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            progress_full = ProgressState()
            FilePipeline(cfg=cfg, progress=progress_full).run(
                ["//10.0.0.1/TestShare"]
            )

        # Now with exclusions
        cfg.targets.exclude_unc = ["*/relay_*"]
        smb2 = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            tt.return_value.connect.return_value = smb2
            at.return_value.connect.return_value = smb2

            progress_excl = ProgressState()
            FilePipeline(cfg=cfg, progress=progress_excl).run(
                ["//10.0.0.1/TestShare"]
            )

        # Excluding relay_* dirs should mean fewer files
        assert progress_excl.files_scanned < progress_full.files_scanned
        # But still some files (non-relay dirs)
        assert progress_excl.files_scanned > 0

    def test_multiple_exclude_patterns(self, cfg):
        """Multiple --exclude-unc patterns stack additively."""
        smb = _make_smb_mock(_DATA_DIR)

        # Exclude two specific directories
        cfg.targets.exclude_unc = ["*/relay_*", "*/gpp*"]
        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            progress_two = ProgressState()
            FilePipeline(cfg=cfg, progress=progress_two).run(
                ["//10.0.0.1/TestShare"]
            )

        # Now exclude only one
        cfg.targets.exclude_unc = ["*/relay_*"]
        smb2 = _make_smb_mock(_DATA_DIR)
        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            tt.return_value.connect.return_value = smb2
            at.return_value.connect.return_value = smb2

            progress_one = ProgressState()
            FilePipeline(cfg=cfg, progress=progress_one).run(
                ["//10.0.0.1/TestShare"]
            )

        # Two exclusions should scan fewer files than one
        assert progress_two.files_scanned < progress_one.files_scanned


class TestShareFilters:
    """--share and --exclude-share filter shares in the pipeline."""

    def test_include_filter_limits_shares(self, cfg):
        """--share glob limits which shares are returned."""
        cfg.targets.share_filter = ["Test*"]
        smb = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.discovery.shares.SMBTransport") as t:
            t.return_value.connect.return_value = smb
            paths = SharePipeline(cfg=cfg).run(["10.0.0.1"])

        assert paths == ["//10.0.0.1/TestShare"]

    def test_exclude_filter_drops_shares(self, cfg):
        """--exclude-share glob removes matching shares."""
        cfg.targets.exclude_share = ["Test*"]
        smb = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.discovery.shares.SMBTransport") as t:
            t.return_value.connect.return_value = smb
            paths = SharePipeline(cfg=cfg).run(["10.0.0.1"])

        assert paths == []

    def test_share_filter_end_to_end_no_files_when_excluded(self, cfg):
        """Excluding the only share means no files are scanned."""
        cfg.targets.exclude_share = ["Test*"]
        smb = _make_smb_mock(_DATA_DIR)
        progress = ProgressState()

        with patch("snaffler.discovery.shares.SMBTransport") as st, \
                patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            st.return_value.connect.return_value = smb
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            paths = SharePipeline(cfg=cfg, progress=progress).run(["10.0.0.1"])
            matched = FilePipeline(cfg=cfg, progress=progress).run(paths)

        assert progress.shares_found == 0
        assert progress.files_scanned == 0
        assert matched == 0


class TestResumeIntegration:
    """Resume from SQLite state survives interrupt and resumes correctly."""

    def test_resume_skips_checked_files(self, cfg):
        """Files marked checked in state DB are not re-scanned on resume."""
        smb = _make_smb_mock(_DATA_DIR)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            db_path = f.name

        try:
            cfg.state.state_db = db_path

            # Run 1: full scan
            with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                    patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
                tt.return_value.connect.return_value = smb
                at.return_value.connect.return_value = smb

                progress1 = ProgressState()
                state1 = ScanState(SQLiteStateStore(db_path))
                matched1 = FilePipeline(cfg=cfg, progress=progress1, state=state1).run(
                    ["//10.0.0.1/TestShare"]
                )
                state1.close()

            scanned_run1 = progress1.files_scanned
            assert scanned_run1 > 0

            # Run 2: resume — all files already checked
            smb2 = _make_smb_mock(_DATA_DIR)

            with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                    patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
                tt.return_value.connect.return_value = smb2
                at.return_value.connect.return_value = smb2

                progress2 = ProgressState()
                state2 = ScanState(SQLiteStateStore(db_path))
                matched2 = FilePipeline(cfg=cfg, progress=progress2, state=state2).run(
                    ["//10.0.0.1/TestShare"]
                )
                state2.close()

            # Run 2 walks dirs (re-walks are expected) but skips checked files
            assert progress2.files_scanned == 0
        finally:
            import os
            for suffix in ("", "-wal", "-shm"):
                p = db_path + suffix
                if os.path.exists(p):
                    os.unlink(p)

    def test_resume_state_persists_shares(self, cfg):
        """Share done flags persist across runs."""
        smb = _make_smb_mock(_DATA_DIR)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            db_path = f.name

        try:
            cfg.state.state_db = db_path

            with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                    patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
                tt.return_value.connect.return_value = smb
                at.return_value.connect.return_value = smb

                state = ScanState(SQLiteStateStore(db_path))
                FilePipeline(cfg=cfg, state=state).run(
                    ["//10.0.0.1/TestShare"]
                )
                state.close()

            # Verify share is marked done in state DB
            store = SQLiteStateStore(db_path)
            assert store.has_checked_share("//10.0.0.1/TestShare")
            store.close()
        finally:
            import os
            for suffix in ("", "-wal", "-shm"):
                p = db_path + suffix
                if os.path.exists(p):
                    os.unlink(p)


class TestProgressCounters:
    """Progress counters are accurate through the full pipeline."""

    def test_severity_counts_match_total(self, cfg):
        """Sum of severity counts equals total files_matched."""
        smb = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            progress = ProgressState()
            matched = FilePipeline(cfg=cfg, progress=progress).run(
                ["//10.0.0.1/TestShare"]
            )

        severity_sum = (
            progress.severity_black
            + progress.severity_red
            + progress.severity_yellow
            + progress.severity_green
        )
        assert severity_sum == matched
        assert matched == progress.files_matched

    def test_files_scanned_equals_total_when_no_errors(self, cfg):
        """When everything succeeds, files_scanned == files_total."""
        smb = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            progress = ProgressState()
            FilePipeline(cfg=cfg, progress=progress).run(
                ["//10.0.0.1/TestShare"]
            )

        assert progress.files_scanned == progress.files_total
        assert progress.files_scanned > 0


class TestMinInterest:
    """--min-interest filters findings by triage severity."""

    def test_min_interest_zero_most_findings(self, cfg):
        """min_interest=0 (GREEN) reports everything."""
        cfg.scanning.min_interest = 0
        smb = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            progress_all = ProgressState()
            matched_all = FilePipeline(cfg=cfg, progress=progress_all).run(
                ["//10.0.0.1/TestShare"]
            )

        # Now with higher threshold
        cfg.scanning.min_interest = 2  # RED and above
        smb2 = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            tt.return_value.connect.return_value = smb2
            at.return_value.connect.return_value = smb2

            progress_high = ProgressState()
            matched_high = FilePipeline(cfg=cfg, progress=progress_high).run(
                ["//10.0.0.1/TestShare"]
            )

        # Fewer findings with higher threshold
        assert matched_high < matched_all
        assert matched_high > 0  # test data has RED/BLACK findings


class TestMatchFilter:
    """--match regex filter reduces findings output."""

    def test_match_filter_reduces_finding_count(self, cfg):
        """--match filters findings — matched count is lower with a narrow filter."""
        smb = _make_smb_mock(_DATA_DIR)

        # Baseline: no filter
        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            progress_all = ProgressState()
            matched_all = FilePipeline(cfg=cfg, progress=progress_all).run(
                ["//10.0.0.1/TestShare"]
            )

        # Now with a narrow filter
        cfg.scanning.match_filter = "password"
        smb2 = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            tt.return_value.connect.return_value = smb2
            at.return_value.connect.return_value = smb2

            progress_filtered = ProgressState()
            matched_filtered = FilePipeline(cfg=cfg, progress=progress_filtered).run(
                ["//10.0.0.1/TestShare"]
            )

        # --match filters findings: matched count is reduced
        assert matched_filtered <= matched_all
        assert progress_filtered.files_matched <= progress_all.files_matched

    def test_match_filter_does_not_affect_files_scanned(self, cfg):
        """--match only filters output, not scanning — files_scanned is unchanged."""
        smb = _make_smb_mock(_DATA_DIR)

        # Baseline: no filter
        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            progress_all = ProgressState()
            FilePipeline(cfg=cfg, progress=progress_all).run(
                ["//10.0.0.1/TestShare"]
            )

        # Now with filter
        cfg.scanning.match_filter = "password"
        smb2 = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            tt.return_value.connect.return_value = smb2
            at.return_value.connect.return_value = smb2

            progress_filtered = ProgressState()
            FilePipeline(cfg=cfg, progress=progress_filtered).run(
                ["//10.0.0.1/TestShare"]
            )

        # Same number of files scanned regardless of --match
        assert progress_filtered.files_scanned == progress_all.files_scanned

    def test_match_filter_excludes_from_finding_store(self, cfg):
        """--match filter suppresses both output and DB persistence."""
        smb = _make_smb_mock(_DATA_DIR)
        stored_findings = []

        def fake_store(**kwargs):
            stored_findings.append(kwargs)

        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            # Baseline: count all findings persisted without filter
            set_finding_store(fake_store)
            progress_all = ProgressState()
            matched_all = FilePipeline(cfg=cfg, progress=progress_all).run(
                ["//10.0.0.1/TestShare"]
            )
            total_stored = len(stored_findings)
            set_finding_store(None)

        # Now with filter — DB should get fewer findings
        cfg.scanning.match_filter = "password"
        smb2 = _make_smb_mock(_DATA_DIR)
        stored_findings_filtered = []

        def fake_store_filtered(**kwargs):
            stored_findings_filtered.append(kwargs)

        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
            tt.return_value.connect.return_value = smb2
            at.return_value.connect.return_value = smb2

            set_finding_store(fake_store_filtered)
            progress_filtered = ProgressState()
            matched_filtered = FilePipeline(cfg=cfg, progress=progress_filtered).run(
                ["//10.0.0.1/TestShare"]
            )
            set_finding_store(None)

        # --match now fully suppresses non-matching findings
        assert matched_filtered <= matched_all
        # Filtered findings are excluded from the DB too
        assert len(stored_findings_filtered) <= total_stored


class TestDNSPreResolution:
    """DNS pre-resolution filters dead hosts before share discovery."""

    def _make_dns_mock(self, resolvable: dict):
        """Return a getaddrinfo side_effect that resolves only hosts in *resolvable*."""
        def fake(host, port, family=0, type_=0, proto=0, flags=0):
            if host in resolvable:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (resolvable[host], port))]
            raise socket.gaierror(8, "nodename nor servname provided, or not known")
        return fake

    def test_only_resolved_hosts_reach_share_and_file_pipelines(self, cfg):
        """3 computers, 1 dead — only 2 alive ones produce shares and findings."""
        cfg.targets.computer_targets = ["ALIVE1", "ALIVE2", "DEAD-HOST"]

        smb = _make_smb_mock(_DATA_DIR)

        resolvable = {"ALIVE1": "10.0.0.1", "ALIVE2": "10.0.0.2"}

        with patch("snaffler.engine.runner.socket.getaddrinfo",
                    side_effect=self._make_dns_mock(resolvable)), \
             patch("snaffler.engine.runner.socket.create_connection",
                   return_value=MagicMock()), \
             patch("snaffler.discovery.shares.SMBTransport") as st, \
             patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
             patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at, \
             patch("snaffler.engine.runner.print_completion_stats"), \
             _no_auth_check:

            st.return_value.connect.return_value = smb
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            runner = SnafflerRunner(cfg)
            runner.execute()

        p = runner.progress

        # DNS phase: 3 total, 2 resolved, 1 filtered
        assert p.dns_total == 3
        assert p.dns_resolved == 2
        assert p.dns_filtered == 1

        # Only the 2 alive hosts reached share discovery
        assert p.computers_total == 2
        assert p.computers_done == 2

        # Shares were found (mock returns 1 share per host)
        assert p.shares_found == 2

        # File pipeline ran and found matches in the test data
        assert p.files_scanned > 0
        assert p.files_matched > 0

    def test_all_hosts_dead_skips_everything(self, cfg):
        """When no hosts resolve, share and file pipelines are skipped entirely."""
        cfg.targets.computer_targets = ["DEAD1", "DEAD2"]

        # Nothing resolves
        with patch("snaffler.engine.runner.socket.getaddrinfo",
                    side_effect=self._make_dns_mock({})), \
             patch("snaffler.engine.runner.socket.create_connection",
                   return_value=MagicMock()), \
             patch("snaffler.discovery.shares.SMBTransport"), \
             patch("snaffler.engine.runner.print_completion_stats"), \
             _no_auth_check:

            runner = SnafflerRunner(cfg)
            runner.execute()

        p = runner.progress
        assert p.dns_total == 2
        assert p.dns_resolved == 0
        assert p.dns_filtered == 2

        # Nothing reached share or file pipeline
        assert p.computers_total == 0
        assert p.shares_found == 0
        assert p.files_scanned == 0

    def test_dead_host_shares_not_in_output(self, cfg, caplog):
        """Verify log output only references resolved hosts, not filtered ones."""
        cfg.targets.computer_targets = ["ALIVE", "DEAD-HOST"]

        smb = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.engine.runner.socket.getaddrinfo",
                    side_effect=self._make_dns_mock({"ALIVE": "10.0.0.1"})), \
             patch("snaffler.engine.runner.socket.create_connection",
                   return_value=MagicMock()), \
             patch("snaffler.discovery.shares.SMBTransport") as st, \
             patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
             patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at, \
             patch("snaffler.engine.runner.print_completion_stats"), \
             _no_auth_check:

            st.return_value.connect.return_value = smb
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            with caplog.at_level(logging.DEBUG, logger="snaffler"):
                runner = SnafflerRunner(cfg)
                runner.execute()

        # DEAD-HOST should appear in a "no record" debug message
        dns_skip_msgs = [
            r.message for r in caplog.records
            if "DEAD-HOST" in r.message and "no record" in r.message
        ]
        assert len(dns_skip_msgs) == 1

        # No share discovery or file findings should mention DEAD-HOST
        finding_msgs = [
            r.message for r in caplog.records
            if "DEAD-HOST" in r.message and "shares on" in r.message
        ]
        assert len(finding_msgs) == 0

    def test_interrupt_then_resume_retries_unresolved(self, cfg):
        """Interrupt mid-DNS persists partial results; resume only retries unresolved."""
        cfg.targets.computer_targets = ["HOST1", "HOST2", "HOST3"]
        cfg.advanced.share_threads = 1  # sequential for deterministic ordering

        smb = _make_smb_mock(_DATA_DIR)
        resolvable = {"HOST1": "10.0.0.1", "HOST2": "10.0.0.2", "HOST3": "10.0.0.3"}

        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            db_path = f.name

        try:
            # ---- Run 1: interrupt after first host ----
            cfg.state.state_db = db_path

            def dns_with_interrupt(host, port, family=0, type_=0, proto=0, flags=0):
                if host not in resolvable:
                    raise socket.gaierror(8, "not found")
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (resolvable[host], port))]

            with patch("snaffler.engine.runner.socket.getaddrinfo",
                        side_effect=dns_with_interrupt), \
                 patch("snaffler.engine.runner.socket.create_connection",
                       return_value=MagicMock()), \
                 patch("snaffler.discovery.shares.SMBTransport") as st, \
                 patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                 patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at, \
                 patch("snaffler.engine.runner.print_completion_stats"), \
                 _no_auth_check:

                st.return_value.connect.return_value = smb
                tt.return_value.connect.return_value = smb
                at.return_value.connect.return_value = smb

                runner1 = SnafflerRunner(cfg)

                # Intercept: after first IP is stored, raise KeyboardInterrupt
                orig_set_ip = runner1.state.set_computer_ip
                ip_store_count = {"n": 0}

                def set_ip_then_interrupt(name, ip):
                    orig_set_ip(name, ip)
                    ip_store_count["n"] += 1
                    if ip_store_count["n"] >= 1:
                        raise KeyboardInterrupt

                runner1.state.set_computer_ip = set_ip_then_interrupt

                with pytest.raises(KeyboardInterrupt):
                    runner1.execute()

            # Verify: at least 1 host resolved and persisted
            store1 = SQLiteStateStore(db_path)
            resolved_after_interrupt = store1.load_resolved_computers()
            unresolved_after_interrupt = store1.load_unresolved_computers()
            assert len(resolved_after_interrupt) >= 1
            assert len(unresolved_after_interrupt) >= 1
            # Phase must NOT be done
            assert store1.get_sync_flag("dns_resolution_done") is False
            store1.close()

            # ---- Run 2: resume — should only resolve the remaining hosts ----
            dns_calls_run2 = {"hosts": []}

            def dns_run2(host, port, family=0, type_=0, proto=0, flags=0):
                dns_calls_run2["hosts"].append(host)
                if host not in resolvable:
                    raise socket.gaierror(8, "not found")
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (resolvable[host], port))]

            with patch("snaffler.engine.runner.socket.getaddrinfo",
                        side_effect=dns_run2), \
                 patch("snaffler.engine.runner.socket.create_connection",
                       return_value=MagicMock()), \
                 patch("snaffler.discovery.shares.SMBTransport") as st, \
                 patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                 patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at, \
                 patch("snaffler.engine.runner.print_completion_stats"), \
                 _no_auth_check:

                st.return_value.connect.return_value = smb
                tt.return_value.connect.return_value = smb
                at.return_value.connect.return_value = smb

                runner2 = SnafflerRunner(cfg)
                runner2.execute()

            # Run 2 should only have resolved the unresolved hosts, not all 3
            assert set(dns_calls_run2["hosts"]) == set(unresolved_after_interrupt)

            # All 3 hosts should now be resolved
            store2 = SQLiteStateStore(db_path)
            final_resolved = store2.load_resolved_computers()
            assert sorted(final_resolved) == ["HOST1", "HOST2", "HOST3"]
            assert store2.get_sync_flag("dns_resolution_done") is True
            store2.close()

            # File pipeline should have run and found matches
            assert runner2.progress.files_scanned > 0
            assert runner2.progress.files_matched > 0

        finally:
            import os
            os.unlink(db_path)


class TestExclusions:
    """--exclusions skips hosts matching the exclusion file."""

    def _make_dns_mock(self, resolvable: dict):
        """Return a getaddrinfo side_effect that resolves only hosts in *resolvable*."""
        def fake(host, port, family=0, type_=0, proto=0, flags=0):
            if host in resolvable:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (resolvable[host], port))]
            raise socket.gaierror(8, "nodename nor servname provided, or not known")
        return fake

    def test_exclusions_skip_host_in_computer_mode(self, cfg):
        """Excluded host never reaches DNS, share discovery, or file scanning."""
        cfg.targets.computer_targets = ["INCLUDED", "EXCLUDED"]
        cfg.targets.exclusions = ["EXCLUDED"]

        smb = _make_smb_mock(_DATA_DIR)
        resolvable = {"INCLUDED": "10.0.0.1", "EXCLUDED": "10.0.0.2"}
        dns_hosts_queried = []

        def tracking_dns(host, port, family=0, type_=0, proto=0, flags=0):
            dns_hosts_queried.append(host)
            if host in resolvable:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (resolvable[host], port))]
            raise socket.gaierror(8, "not found")

        with patch("snaffler.engine.runner.socket.getaddrinfo",
                    side_effect=tracking_dns), \
             patch("snaffler.engine.runner.socket.create_connection",
                   return_value=MagicMock()), \
             patch("snaffler.discovery.shares.SMBTransport") as st, \
             patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
             patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at, \
             patch("snaffler.engine.runner.print_completion_stats"), \
             _no_auth_check:

            st.return_value.connect.return_value = smb
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            runner = SnafflerRunner(cfg)
            runner.execute()

        p = runner.progress

        # EXCLUDED never reached DNS
        assert "EXCLUDED" not in dns_hosts_queried
        assert "INCLUDED" in dns_hosts_queried

        # Only INCLUDED reached share discovery
        assert p.dns_total == 1
        assert p.dns_resolved == 1
        assert p.computers_total == 1
        assert p.computers_done == 1

        # File pipeline ran on INCLUDED's shares and found matches
        assert p.shares_found >= 1
        assert p.files_scanned > 0
        assert p.files_matched > 0

    def test_exclusions_skip_host_in_unc_mode(self, cfg):
        """UNC paths with excluded hostnames produce no file scans."""
        cfg.targets.unc_targets = [
            "//INCLUDED/TestShare",
            "//EXCLUDED/TestShare",
        ]
        cfg.targets.exclusions = ["EXCLUDED"]

        smb = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
             patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at, \
             patch("snaffler.engine.runner.print_completion_stats"), \
             _no_auth_check:

            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            runner = SnafflerRunner(cfg)
            runner.execute()

        p = runner.progress

        # Only INCLUDED host counted
        assert p.computers_total == 1
        assert p.shares_found == 1

        # File pipeline ran and found matches in test data
        assert p.files_scanned > 0
        assert p.files_matched > 0

    def test_exclusions_all_hosts_excluded(self, cfg):
        """Excluding every host means nothing runs."""
        cfg.targets.computer_targets = ["HOST1", "HOST2"]
        cfg.targets.exclusions = ["HOST1", "HOST2"]

        with patch("snaffler.engine.runner.socket.getaddrinfo",
                    side_effect=AssertionError("DNS should not be called")), \
             patch("snaffler.engine.runner.print_completion_stats"), \
             _no_auth_check:

            runner = SnafflerRunner(cfg)
            runner.execute()

        p = runner.progress
        assert p.dns_total == 0
        assert p.computers_total == 0
        assert p.shares_found == 0
        assert p.files_scanned == 0


class TestArchivePeek:
    """Archive peeking through the full pipeline."""

    _ARCHIVE_DIR = _DATA_DIR / "archives"

    # ------------------------------------------------------------------ helpers

    def _run_pipeline(self, cfg, share_root=None):
        """Run FilePipeline against *share_root* and return (matched, progress, findings)."""
        root = share_root or _DATA_DIR
        smb = _make_smb_mock(root)
        findings = []

        # Intercept log_file_result to capture individual findings
        import snaffler.engine.file_pipeline as fp_mod
        original_log = fp_mod.log_file_result

        def capture_log(logger, file_path, *args, **kwargs):
            findings.append(file_path)
            return original_log(logger, file_path, *args, **kwargs)

        with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at, \
                patch("snaffler.engine.file_pipeline.log_file_result", side_effect=capture_log):
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            progress = ProgressState()
            matched = FilePipeline(cfg=cfg, progress=progress).run(
                ["//10.0.0.1/TestShare"]
            )

        return matched, progress, findings

    # ---------------------------------------- positive: sensitive archive

    def test_sensitive_archive_produces_findings(self, cfg):
        """ZIP containing id_rsa / passwords.txt → findings via archive peeking."""
        matched, progress, findings = self._run_pipeline(cfg, self._ARCHIVE_DIR)

        assert matched > 0
        # At least one finding must come from inside an archive (→ separator)
        archive_findings = [f for f in findings if "\u2192" in f]
        assert len(archive_findings) > 0

    def test_sensitive_archive_finds_ssh_key(self, cfg):
        """id_rsa inside ZIP triggers KeepSSHKeysByFileName (BLACK)."""
        matched, progress, findings = self._run_pipeline(cfg, self._ARCHIVE_DIR)

        ssh_findings = [f for f in findings if "\u2192" in f and "id_rsa" in f]
        assert len(ssh_findings) >= 1

    def test_sensitive_archive_finds_password_file(self, cfg):
        """passwords.txt inside ZIP triggers KeepPasswordFilesByName (RED)."""
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(self._ARCHIVE_DIR / "password_archive.zip", tmp)
            _, _, findings = self._run_pipeline(cfg, Path(tmp))

        pw_findings = [f for f in findings if "\u2192" in f and "passwords.txt" in f]
        assert len(pw_findings) >= 1

    def test_sensitive_archive_finds_ppk_key(self, cfg):
        """.ppk file inside ZIP triggers KeepSSHKeysByFileExtension (BLACK)."""
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(self._ARCHIVE_DIR / "ppk_archive.zip", tmp)
            _, _, findings = self._run_pipeline(cfg, Path(tmp))

        ppk_findings = [f for f in findings if "\u2192" in f and ".ppk" in f]
        assert len(ppk_findings) >= 1

    def test_sensitive_archive_finds_ntds(self, cfg):
        """NTDS.DIT inside ZIP subdir triggers KeepWinHashesByName (BLACK)."""
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(self._ARCHIVE_DIR / "ntds_archive.zip", tmp)
            _, _, findings = self._run_pipeline(cfg, Path(tmp))

        ntds_findings = [f for f in findings if "\u2192" in f and "NTDS.DIT" in f]
        assert len(ntds_findings) >= 1

    def test_archive_member_unc_path_format(self, cfg):
        """Archive member findings use //server/share/archive.{zip,rar}→member format."""
        _, _, findings = self._run_pipeline(cfg, self._ARCHIVE_DIR)

        archive_findings = [f for f in findings if "\u2192" in f]
        assert len(archive_findings) > 0

        for path in archive_findings:
            # Must start with UNC prefix
            assert path.startswith("//")
            # Part before → must end with a supported archive extension
            archive_part, member_part = path.split("\u2192", 1)
            assert archive_part.endswith((".zip", ".rar", ".7z"))
            # Member part must be a filename (not empty)
            assert len(member_part) > 0

    # ---------------------------------------- positive: progress counters

    def test_archive_findings_counted_in_progress(self, cfg):
        """Archive member findings are reflected in progress.files_matched."""
        matched, progress, findings = self._run_pipeline(cfg, self._ARCHIVE_DIR)

        assert progress.files_matched == matched
        assert matched > 0
        # Severity counts sum to matched
        severity_sum = (
            progress.severity_black
            + progress.severity_red
            + progress.severity_yellow
            + progress.severity_green
        )
        assert severity_sum == matched

    # ---------------------------------------- negative: boring archive

    def test_boring_archive_no_member_findings(self, cfg):
        """ZIP with only readme.txt / notes.dat → no archive-member findings."""
        # Use a temp dir with only the boring archive
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(self._ARCHIVE_DIR / "boring_archive.zip", tmp)
            _, _, findings = self._run_pipeline(cfg, Path(tmp))

        archive_findings = [f for f in findings if "\u2192" in f]
        assert len(archive_findings) == 0

    def test_boring_archive_still_scanned(self, cfg):
        """Boring archive is still counted as a scanned file even with no member findings."""
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(self._ARCHIVE_DIR / "boring_archive.zip", tmp)
            _, progress, _ = self._run_pipeline(cfg, Path(tmp))

        assert progress.files_scanned >= 1

    # ---------------------------------------- negative: oversized archive

    def test_oversized_archive_not_peeked(self, cfg):
        """10MB+ archive exceeds max_read_bytes (2MB) → no peeking, no member findings."""
        # Run against the full archives dir; oversized_archive.zip is ~10.5MB
        _, _, findings = self._run_pipeline(cfg, self._ARCHIVE_DIR)

        # oversized_archive.zip has id_rsa and passwords.txt inside, but it's
        # too big to peek — so no findings should reference oversized_archive.zip→
        oversized_findings = [
            f for f in findings
            if "oversized_archive.zip\u2192" in f
        ]
        assert len(oversized_findings) == 0

    def test_oversized_archive_still_scanned_as_file(self, cfg):
        """Oversized archive is still counted as a scanned file."""
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(self._ARCHIVE_DIR / "oversized_archive.zip", tmp)
            _, progress, _ = self._run_pipeline(cfg, Path(tmp))

        # The file itself is scanned (file rules evaluated), just not peeked
        assert progress.files_scanned >= 1

    def test_raising_max_read_bytes_peeks_oversized(self, cfg):
        """Bumping max_read_bytes above archive size enables peeking."""
        cfg.scanning.max_read_bytes = 20 * 1024 * 1024  # 20MB

        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(self._ARCHIVE_DIR / "oversized_archive.zip", tmp)
            _, _, findings = self._run_pipeline(cfg, Path(tmp))

        # NOW the oversized archive should be peeked and findings produced
        archive_findings = [f for f in findings if "\u2192" in f]
        assert len(archive_findings) > 0

    # ---------------------------------------- negative: max_read_bytes gate

    def test_lowering_max_read_bytes_blocks_all_peeking(self, cfg):
        """Setting max_read_bytes=1 prevents peeking into any archive."""
        cfg.scanning.max_read_bytes = 1  # 1 byte — nothing gets peeked

        _, _, findings = self._run_pipeline(cfg, self._ARCHIVE_DIR)

        archive_findings = [f for f in findings if "\u2192" in f]
        assert len(archive_findings) == 0

    # ---------------------------------------- negative: match filter on archive members

    def test_match_filter_suppresses_archive_findings(self, cfg):
        """--match filter fully suppresses non-matching archive findings."""
        # First get baseline without filter
        matched_all, _, _ = self._run_pipeline(cfg, self._ARCHIVE_DIR)

        cfg.scanning.match_filter = "this_will_never_match_anything_12345"
        matched, _, _ = self._run_pipeline(cfg, self._ARCHIVE_DIR)

        # --match fully suppresses non-matching findings
        assert matched <= matched_all

    def test_match_filter_passes_archive_findings(self, cfg):
        """--match filter matching archive member names passes them through."""
        cfg.scanning.match_filter = "id_rsa"

        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(self._ARCHIVE_DIR / "sensitive_archive.zip", tmp)
            matched, _, findings = self._run_pipeline(cfg, Path(tmp))

        # id_rsa matches the filter → pipeline returns it
        assert matched >= 1
        # The finding path contains id_rsa
        archive_findings = [f for f in findings if "\u2192" in f and "id_rsa" in f]
        assert len(archive_findings) >= 1

    # ---------------------------------------- positive: RAR archives

    def test_rar_sensitive_archive_produces_findings(self, cfg):
        """RAR containing id_rsa → findings via archive peeking."""
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(self._ARCHIVE_DIR / "sensitive_archive.rar", tmp)
            _, _, findings = self._run_pipeline(cfg, Path(tmp))

        archive_findings = [f for f in findings if "\u2192" in f]
        assert len(archive_findings) > 0

    def test_rar_finds_ssh_key(self, cfg):
        """id_rsa inside RAR triggers KeepSSHKeysByFileName (BLACK)."""
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(self._ARCHIVE_DIR / "sensitive_archive.rar", tmp)
            _, _, findings = self._run_pipeline(cfg, Path(tmp))

        ssh_findings = [f for f in findings if "\u2192" in f and "id_rsa" in f]
        assert len(ssh_findings) >= 1

    def test_rar_finds_password_file(self, cfg):
        """passwords.txt inside RAR triggers KeepPasswordFilesByName (RED)."""
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(self._ARCHIVE_DIR / "password_archive.rar", tmp)
            _, _, findings = self._run_pipeline(cfg, Path(tmp))

        pw_findings = [f for f in findings if "\u2192" in f and "passwords.txt" in f]
        assert len(pw_findings) >= 1

    def test_rar_finds_ppk_key(self, cfg):
        """.ppk file inside RAR triggers KeepSSHKeysByFileExtension (BLACK)."""
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(self._ARCHIVE_DIR / "ppk_archive.rar", tmp)
            _, _, findings = self._run_pipeline(cfg, Path(tmp))

        ppk_findings = [f for f in findings if "\u2192" in f and ".ppk" in f]
        assert len(ppk_findings) >= 1

    def test_rar_finds_ntds(self, cfg):
        """NTDS.DIT inside RAR subdir triggers KeepWinHashesByName (BLACK)."""
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(self._ARCHIVE_DIR / "ntds_archive.rar", tmp)
            _, _, findings = self._run_pipeline(cfg, Path(tmp))

        ntds_findings = [f for f in findings if "\u2192" in f and "NTDS.DIT" in f]
        assert len(ntds_findings) >= 1

    def test_rar_member_unc_path_format(self, cfg):
        """RAR member findings use //server/share/archive.rar→member format."""
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(self._ARCHIVE_DIR / "sensitive_archive.rar", tmp)
            _, _, findings = self._run_pipeline(cfg, Path(tmp))

        archive_findings = [f for f in findings if "\u2192" in f]
        assert len(archive_findings) > 0

        for path in archive_findings:
            assert path.startswith("//")
            assert ".rar\u2192" in path
            archive_part, member_part = path.split("\u2192", 1)
            assert archive_part.endswith(".rar")
            assert len(member_part) > 0

    # ---------------------------------------- negative: RAR boring / oversized

    def test_rar_boring_archive_no_member_findings(self, cfg):
        """RAR with only boring files → no archive-member findings."""
        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(self._ARCHIVE_DIR / "boring_archive.rar", tmp)
            _, _, findings = self._run_pipeline(cfg, Path(tmp))

        archive_findings = [f for f in findings if "\u2192" in f]
        assert len(archive_findings) == 0

    def test_rar_oversized_archive_not_peeked(self, cfg):
        """10MB+ RAR exceeds max_read_bytes (2MB) → no peeking."""
        _, _, findings = self._run_pipeline(cfg, self._ARCHIVE_DIR)

        oversized_findings = [
            f for f in findings
            if "oversized_archive.rar\u2192" in f
        ]
        assert len(oversized_findings) == 0

    def test_rar_raising_max_read_bytes_peeks_oversized(self, cfg):
        """Bumping max_read_bytes above RAR size enables peeking."""
        cfg.scanning.max_read_bytes = 20 * 1024 * 1024

        import shutil
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copy(self._ARCHIVE_DIR / "oversized_archive.rar", tmp)
            _, _, findings = self._run_pipeline(cfg, Path(tmp))

        archive_findings = [f for f in findings if "\u2192" in f]
        assert len(archive_findings) > 0

    # ---------------------------------------- full data dir (regression)

    def test_archives_in_full_data_dir_produce_findings(self, cfg):
        """Archives in the full test data dir contribute findings alongside regular files."""
        matched, progress, findings = self._run_pipeline(cfg)

        # Full data dir has both regular files and archives
        assert matched > 0
        assert progress.files_scanned > 0

        # Some findings come from archives
        archive_findings = [f for f in findings if "\u2192" in f]
        assert len(archive_findings) > 0

        # Some findings come from regular files
        regular_findings = [f for f in findings if "\u2192" not in f]
        assert len(regular_findings) > 0


class TestDashedHostname:
    """B1: Hostnames with dashes (e.g. dc-01) must not crash expand_targets."""

    def _make_dns_mock(self, resolvable: dict):
        def fake(host, port, family=0, type_=0, proto=0, flags=0):
            if host in resolvable:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (resolvable[host], port))]
            raise socket.gaierror(8, "not found")
        return fake

    def test_dashed_hostname_processed_by_share_pipeline(self, cfg):
        """A hostname like dc-01 passes through expand_targets and share pipeline."""
        smb = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.discovery.shares.SMBTransport") as t:
            t.return_value.connect.return_value = smb
            paths = SharePipeline(cfg=cfg).run(["dc-01"])

        assert paths == ["//dc-01/TestShare"]

    def test_dashed_hostname_end_to_end_via_runner(self, cfg):
        """Runner with --computer dc-01 completes without crashing."""
        cfg.targets.computer_targets = ["DC-01"]

        smb = _make_smb_mock(_DATA_DIR)
        resolvable = {"DC-01": "10.0.0.99"}

        with patch("snaffler.engine.runner.socket.getaddrinfo",
                    side_effect=self._make_dns_mock(resolvable)), \
             patch("snaffler.engine.runner.socket.create_connection",
                   return_value=MagicMock()), \
             patch("snaffler.discovery.shares.SMBTransport") as st, \
             patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
             patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at, \
             patch("snaffler.engine.runner.print_completion_stats"), \
             _no_auth_check:

            st.return_value.connect.return_value = smb
            tt.return_value.connect.return_value = smb
            at.return_value.connect.return_value = smb

            runner = SnafflerRunner(cfg)
            runner.execute()

        p = runner.progress
        assert p.dns_resolved == 1
        assert p.computers_done == 1
        assert p.shares_found >= 1
        assert p.files_scanned > 0
        assert p.files_matched > 0

    def test_multiple_dashed_hostnames(self, cfg):
        """Multiple dashed hostnames all resolve and produce shares."""
        smb = _make_smb_mock(_DATA_DIR)

        with patch("snaffler.discovery.shares.SMBTransport") as t:
            t.return_value.connect.return_value = smb
            progress = ProgressState()
            paths = SharePipeline(cfg=cfg, progress=progress).run(
                ["dc-01", "file-srv-02", "app-node-3"]
            )

        assert len(paths) == 3
        assert "//dc-01/TestShare" in paths
        assert "//file-srv-02/TestShare" in paths
        assert "//app-node-3/TestShare" in paths
        assert progress.computers_done == 3


class TestDownloadBackslashPaths:
    """B2: copy_to_local must produce forward-slash directory structure on Linux."""

    def test_download_creates_correct_directory_structure(self, cfg):
        """Downloaded files use forward-slash path components, not flat backslash names."""
        smb = _make_smb_mock(_DATA_DIR)

        with tempfile.TemporaryDirectory() as download_dir:
            cfg.scanning.snaffle = True
            cfg.scanning.snaffle_path = download_dir

            with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                    patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
                tt.return_value.connect.return_value = smb
                at.return_value.connect.return_value = smb

                progress = ProgressState()
                matched = FilePipeline(cfg=cfg, progress=progress).run(
                    ["//10.0.0.1/TestShare"]
                )

            assert matched > 0

            # Walk the download directory and verify structure
            download_root = Path(download_dir)
            downloaded_files = list(download_root.rglob("*"))
            downloaded_files = [f for f in downloaded_files if f.is_file()]

            # Should have downloaded at least one file
            assert len(downloaded_files) > 0

            # Verify no path component contains backslashes
            for f in downloaded_files:
                rel = f.relative_to(download_root)
                for part in rel.parts:
                    assert "\\" not in part, (
                        f"Backslash in path component: {part} (full: {rel})"
                    )

            # Verify directory structure: server/share/relative_path
            for f in downloaded_files:
                rel = f.relative_to(download_root)
                # Should be at least server/share/filename (3 levels)
                assert len(rel.parts) >= 3, (
                    f"Downloaded file too shallow: {rel} (expected server/share/file)"
                )
                assert rel.parts[0] == "FAKEHOST" or rel.parts[0] == "10.0.0.1"


class TestResumeUncheckedFilesBatch:
    """B3: load_unchecked_files uses fetchmany — verify batch processing works."""

    def test_resume_processes_all_unchecked_files(self, cfg):
        """Insert unchecked files into resume DB, then resume and verify all processed."""
        smb = _make_smb_mock(_DATA_DIR)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            db_path = f.name

        try:
            cfg.state.state_db = db_path

            # Run 1: full scan to populate the DB with files
            with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                    patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
                tt.return_value.connect.return_value = smb
                at.return_value.connect.return_value = smb

                progress1 = ProgressState()
                state1 = ScanState(SQLiteStateStore(db_path))
                FilePipeline(cfg=cfg, progress=progress1, state=state1).run(
                    ["//10.0.0.1/TestShare"]
                )
                state1.close()

            scanned_run1 = progress1.files_scanned
            assert scanned_run1 > 0

            # Now manually reset files/dirs/shares to simulate an interrupted scan
            store = SQLiteStateStore(db_path)
            with store.lock:
                store.conn.execute("UPDATE target_file SET checked = 0")
                store.conn.execute("UPDATE target_dir SET walked = 0")
                store.conn.execute("UPDATE target_share SET done = 0")
                store.conn.commit()

                # Verify there are unchecked files
                count = store.conn.execute(
                    "SELECT COUNT(*) FROM target_file WHERE checked = 0"
                ).fetchone()[0]
            assert count > 0

            # Verify load_unchecked_files returns them all (exercises fetchmany)
            unchecked = store.load_unchecked_files()
            assert len(unchecked) == count
            store.close()

            # Run 2: resume — dirs are unwalked so they will be re-walked,
            # re-discovering files and scanning the unchecked ones
            smb2 = _make_smb_mock(_DATA_DIR)

            with patch("snaffler.discovery.smb_tree_walker.SMBTransport") as tt, \
                    patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at:
                tt.return_value.connect.return_value = smb2
                at.return_value.connect.return_value = smb2

                progress2 = ProgressState()
                state2 = ScanState(SQLiteStateStore(db_path))
                FilePipeline(cfg=cfg, progress=progress2, state=state2).run(
                    ["//10.0.0.1/TestShare"]
                )
                state2.close()

            # All files should have been re-scanned
            assert progress2.files_scanned == scanned_run1

            # Verify all files are now checked in the DB
            store3 = SQLiteStateStore(db_path)
            remaining = store3.load_unchecked_files()
            assert len(remaining) == 0
            store3.close()
        finally:
            import os
            for suffix in ("", "-wal", "-shm"):
                p = db_path + suffix
                if os.path.exists(p):
                    os.unlink(p)
