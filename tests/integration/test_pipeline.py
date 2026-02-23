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
             patch("snaffler.discovery.tree.SMBTransport") as tt, \
             patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at, \
             patch("snaffler.engine.runner.print_completion_stats"):

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
             patch("snaffler.engine.runner.print_completion_stats"):

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
             patch("snaffler.discovery.tree.SMBTransport") as tt, \
             patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at, \
             patch("snaffler.engine.runner.print_completion_stats"):

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
            cfg.resume.enabled = True
            cfg.resume.state_db = db_path

            calls = {"n": 0}

            def dns_with_interrupt(host, port, family=0, type_=0, proto=0, flags=0):
                calls["n"] += 1
                if host not in resolvable:
                    raise socket.gaierror(8, "not found")
                # Let first host resolve, interrupt on second
                if calls["n"] >= 2:
                    # Return the result but the processing loop will be interrupted
                    # via the store side-effect below
                    pass
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (resolvable[host], port))]

            with patch("snaffler.engine.runner.socket.getaddrinfo",
                        side_effect=dns_with_interrupt), \
                 patch("snaffler.engine.runner.socket.create_connection",
                       return_value=MagicMock()), \
                 patch("snaffler.discovery.shares.SMBTransport") as st, \
                 patch("snaffler.discovery.tree.SMBTransport") as tt, \
                 patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at, \
                 patch("snaffler.engine.runner.print_completion_stats"):

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
                 patch("snaffler.discovery.tree.SMBTransport") as tt, \
                 patch("snaffler.accessors.smb_file_accessor.SMBTransport") as at, \
                 patch("snaffler.engine.runner.print_completion_stats"):

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
