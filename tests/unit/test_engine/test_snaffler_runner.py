import socket
import threading
from contextlib import contextmanager
from unittest.mock import MagicMock, call, patch

import pytest

from snaffler.engine.runner import SnafflerRunner, _deduplicate_paths
from snaffler.utils.logger import set_finding_store


@pytest.fixture(autouse=True)
def _reset_finding_store():
    """Ensure the module-level finding store is cleared between tests."""
    yield
    set_finding_store(None)


def _patch_finding_store():
    """Suppress set_finding_store calls in runner init/cleanup."""
    return patch("snaffler.engine.runner.set_finding_store")


# ---------- helpers ----------

def make_cfg():
    cfg = MagicMock()

    # ---------- state ----------
    cfg.state.state_db = ":memory:"

    # ---------- targets ----------
    cfg.targets.unc_targets = []
    cfg.targets.computer_targets = []
    cfg.targets.local_targets = []
    cfg.targets.ftp_targets = []
    cfg.targets.shares_only = False
    cfg.targets.rescan_unreadable = False
    cfg.targets.share_filter = []
    cfg.targets.exclude_share = []
    cfg.targets.exclude_unc = []
    cfg.targets.exclusions = []

    # ---------- auth ----------
    cfg.auth.domain = None

    # ---------- advanced ----------
    cfg.advanced.share_threads = 2
    cfg.advanced.tree_threads = 2
    cfg.advanced.file_threads = 2
    cfg.advanced.dns_threads = 4

    # ---------- web ----------
    cfg.web.enabled = False

    return cfg


@contextmanager
def _resolve_all_hosts():
    """Patch context: getaddrinfo resolves every hostname to 127.0.0.1, port 445 open."""
    def fake(host, port, family=0, type_=0, proto=0, flags=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
    with patch("snaffler.engine.runner.socket.getaddrinfo", side_effect=fake), \
         _port_always_open():
        yield


def _port_always_open():
    """Patch context: create_connection always succeeds (port 445 reachable)."""
    return patch("snaffler.engine.runner.socket.create_connection", return_value=MagicMock())


def _make_runner_with_state(cfg):
    """Create a runner and inject a mock ScanState."""
    with _patch_finding_store():
        runner = SnafflerRunner(cfg)
    state = MagicMock()
    # count methods default to 0 for progress sync
    state.count_checked_computers.return_value = 0
    state.count_checked_shares.return_value = 0
    state.count_checked_files.return_value = 0
    state.count_findings_by_triage.return_value = {}
    runner.state = state
    runner.share_pipeline.state = state
    runner.file_pipeline.state = state
    return runner, state


# ---------- local mode ----------

def test_runner_local_targets():
    """--local-fs paths are passed directly to file_pipeline.run()."""
    cfg = make_cfg()
    cfg.targets.local_targets = ["/tmp/data"]

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    runner.file_pipeline.run.assert_called_once_with(["/tmp/data"])
    assert runner.progress.shares_found == 1


def test_runner_local_injects_local_transport():
    """Local mode injects LocalTreeWalker and LocalFileAccessor."""
    from snaffler.accessors.local_file_accessor import LocalFileAccessor
    from snaffler.discovery.local_tree_walker import LocalTreeWalker

    cfg = make_cfg()
    cfg.targets.local_targets = ["/tmp"]

    runner = SnafflerRunner(cfg)

    assert isinstance(runner.file_pipeline.tree_walker, LocalTreeWalker)
    assert isinstance(runner.file_pipeline.file_scanner.file_accessor, LocalFileAccessor)


def test_runner_local_warns_shares_only(caplog):
    """--shares-only with --local-fs emits a warning."""
    import logging

    cfg = make_cfg()
    cfg.targets.local_targets = ["/tmp"]
    cfg.targets.shares_only = True

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"), \
            caplog.at_level(logging.WARNING, logger="snaffler"):
        runner.execute()

    assert any("--shares-only has no effect" in r.message for r in caplog.records)
    # Still runs the pipeline (--shares-only is ignored, not blocking)
    runner.file_pipeline.run.assert_called_once()


def test_runner_local_warns_exclusions(caplog):
    """--exclusions with --local-fs emits a warning."""
    import logging

    cfg = make_cfg()
    cfg.targets.local_targets = ["/tmp"]
    cfg.targets.exclusions = ["SOMEHOST"]

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"), \
            caplog.at_level(logging.WARNING, logger="snaffler"):
        runner.execute()

    assert any("--exclusions has no effect" in r.message for r in caplog.records)


def test_runner_local_does_not_use_smb():
    """Local mode does NOT instantiate SMBTreeWalker."""
    cfg = make_cfg()
    cfg.targets.local_targets = ["/tmp"]

    runner = SnafflerRunner(cfg)

    from snaffler.discovery.smb_tree_walker import SMBTreeWalker
    assert not isinstance(runner.file_pipeline.tree_walker, SMBTreeWalker)


# ---------- SMB mode ----------

def test_runner_unc_targets():
    cfg = make_cfg()
    cfg.targets.unc_targets = ["//HOST/SHARE"]

    runner = SnafflerRunner(cfg)

    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    runner.file_pipeline.run.assert_called_once_with(
        ["//HOST/SHARE"]
    )


def test_runner_computer_targets():
    cfg = make_cfg()
    cfg.targets.computer_targets = ["HOST1"]

    runner = SnafflerRunner(cfg)

    runner.share_pipeline.run = MagicMock(return_value=["//HOST1/SHARE"])
    runner.file_pipeline.run = MagicMock()

    with _resolve_all_hosts(), patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    runner.share_pipeline.run.assert_called_once_with(["HOST1"])
    runner.file_pipeline.run.assert_called_once_with(
        ["//HOST1/SHARE"]
    )


def test_runner_domain_discovery():
    cfg = make_cfg()
    cfg.auth.domain = "example.com"

    runner = SnafflerRunner(cfg)

    with patch(
        "snaffler.engine.runner.DomainPipeline"
    ) as domain_cls, _resolve_all_hosts(), patch(
        "snaffler.engine.runner.print_completion_stats"
    ):
        domain = domain_cls.return_value
        domain.run.return_value = ["HOST1"]
        domain.get_dfs_shares.return_value = []

        runner.share_pipeline.run = MagicMock(return_value=["//HOST1/SHARE"])
        runner.file_pipeline.run = MagicMock()

        runner.execute()

    domain.run.assert_called_once()
    runner.share_pipeline.run.assert_called_once_with(["HOST1"])
    runner.file_pipeline.run.assert_called_once_with(
        ["//HOST1/SHARE"]
    )


def test_runner_no_targets():
    cfg = make_cfg()

    runner = SnafflerRunner(cfg)

    runner.file_pipeline.run = MagicMock()

    runner.execute()

    runner.file_pipeline.run.assert_not_called()


# ---------- _deduplicate_paths ----------

def test_deduplicate_paths_merges():
    share = ["//HOST1/SHARE"]
    dfs = ["//nas01/data"]
    result = _deduplicate_paths(share, dfs)
    assert result == ["//HOST1/SHARE", "//nas01/data"]


def test_deduplicate_paths_removes_dupes():
    share = ["//HOST1/SHARE", "//nas01/data"]
    dfs = ["//NAS01/DATA"]  # same path, different case
    result = _deduplicate_paths(share, dfs)
    assert result == ["//HOST1/SHARE", "//nas01/data"]


def test_deduplicate_paths_empty_dfs():
    share = ["//HOST1/SHARE"]
    result = _deduplicate_paths(share, [])
    assert result == ["//HOST1/SHARE"]


def test_deduplicate_paths_empty_shares():
    result = _deduplicate_paths([], ["//nas01/data"])
    assert result == ["//nas01/data"]


# ---------- domain discovery with DFS ----------

def test_runner_domain_discovery_with_dfs():
    cfg = make_cfg()
    cfg.auth.domain = "example.com"

    runner = SnafflerRunner(cfg)

    with patch(
        "snaffler.engine.runner.DomainPipeline"
    ) as domain_cls, _resolve_all_hosts(), patch(
        "snaffler.engine.runner.print_completion_stats"
    ):
        domain = domain_cls.return_value
        domain.run.return_value = ["HOST1"]
        domain.get_dfs_shares.return_value = [
            "//nas01/data",
            "//HOST1/SHARE",  # overlaps with share pipeline
        ]

        runner.share_pipeline.run = MagicMock(return_value=["//HOST1/SHARE"])
        runner.file_pipeline.run = MagicMock()

        runner.execute()

    domain.run.assert_called_once()
    domain.get_dfs_shares.assert_called_once()
    runner.share_pipeline.run.assert_called_once_with(["HOST1"])
    # Should have merged: //HOST1/SHARE + //nas01/data (deduped)
    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert "//HOST1/SHARE" in paths
    assert "//nas01/data" in paths
    assert len(paths) == 2


def test_runner_domain_discovery_dfs_only():
    """DFS adds paths even when share pipeline finds nothing."""
    cfg = make_cfg()
    cfg.auth.domain = "example.com"

    runner = SnafflerRunner(cfg)

    with patch(
        "snaffler.engine.runner.DomainPipeline"
    ) as domain_cls, patch(
        "snaffler.engine.runner.print_completion_stats"
    ):
        domain = domain_cls.return_value
        domain.run.return_value = []  # no computers
        domain.get_dfs_shares.return_value = ["//nas01/data"]

        runner.share_pipeline.run = MagicMock()
        runner.file_pipeline.run = MagicMock()

        runner.execute()

    # share_pipeline.run should NOT be called (no computers)
    runner.share_pipeline.run.assert_not_called()
    # But file_pipeline should still run with DFS paths
    runner.file_pipeline.run.assert_called_once_with(["//nas01/data"])


def test_runner_domain_discovery_no_dfs():
    """No DFS results — behaves same as before."""
    cfg = make_cfg()
    cfg.auth.domain = "example.com"

    runner = SnafflerRunner(cfg)

    with patch(
        "snaffler.engine.runner.DomainPipeline"
    ) as domain_cls, _resolve_all_hosts(), patch(
        "snaffler.engine.runner.print_completion_stats"
    ):
        domain = domain_cls.return_value
        domain.run.return_value = ["HOST1"]
        domain.get_dfs_shares.return_value = []

        runner.share_pipeline.run = MagicMock(return_value=["//HOST1/SHARE"])
        runner.file_pipeline.run = MagicMock()

        runner.execute()

    runner.file_pipeline.run.assert_called_once_with(["//HOST1/SHARE"])


# ---------- status thread ----------

def test_runner_status_thread_starts_and_stops():
    cfg = make_cfg()
    cfg.targets.unc_targets = ["//HOST/SHARE"]

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    # After execute(), the status thread should have been stopped
    assert runner._status_thread is not None
    assert not runner._status_thread.is_alive()


def test_runner_status_thread_stops_on_error():
    cfg = make_cfg()
    cfg.targets.unc_targets = ["//HOST/SHARE"]

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock(side_effect=RuntimeError("boom"))

    try:
        runner.execute()
    except RuntimeError:
        pass

    assert not runner._status_thread.is_alive()


def test_runner_progress_passed_to_pipelines():
    cfg = make_cfg()
    runner = SnafflerRunner(cfg)

    assert runner.share_pipeline.progress is runner.progress
    assert runner.file_pipeline.progress is runner.progress


def test_runner_unc_seeds_progress_counters():
    """UNC branch should seed computer/share counters from paths."""
    cfg = make_cfg()
    cfg.targets.unc_targets = [
        "//10.0.0.1/Share1",
        "//10.0.0.1/Share2",
        "//10.0.0.2/Data",
    ]

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    assert runner.progress.computers_total == 2
    assert runner.progress.computers_done == 2
    assert runner.progress.shares_found == 3


# ---------- resume: domain discovery ----------

def test_runner_domain_resume_skips_ldap():
    """When computer_discovery_done is set, load from state instead of LDAP."""
    cfg = make_cfg()
    cfg.auth.domain = "example.com"

    runner, state = _make_runner_with_state(cfg)
    state.is_phase_done.side_effect = lambda phase: phase == "computer_discovery_done"
    state.load_computers.return_value = ["HOST1", "HOST2"]
    state.load_resolved_computers.return_value = []
    state.load_unresolved_computers.return_value = ["HOST1", "HOST2"]
    state.should_skip_computer.return_value = False
    state.load_shares.return_value = ["//HOST1/SHARE", "//HOST2/DATA"]

    runner.share_pipeline.run = MagicMock(return_value=[])
    runner.file_pipeline.run = MagicMock()

    with patch(
        "snaffler.engine.runner.DomainPipeline"
    ) as domain_cls, _resolve_all_hosts(), patch(
        "snaffler.engine.runner.print_completion_stats"
    ):
        domain = domain_cls.return_value
        domain.get_dfs_shares.return_value = []

        runner.execute()

    # LDAP should NOT have been called
    domain.run.assert_not_called()
    # But computers should have been loaded from state
    state.load_computers.assert_called()
    # file_pipeline should have been called with the shares from state
    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert sorted(paths) == ["//HOST1/SHARE", "//HOST2/DATA"]


def test_runner_domain_resume_skips_shares():
    """When share_discovery_done is set, load shares from state."""
    cfg = make_cfg()
    cfg.auth.domain = "example.com"

    runner, state = _make_runner_with_state(cfg)
    state.is_phase_done.return_value = True  # all phases done
    state.load_computers.return_value = ["HOST1"]
    state.load_resolved_computers.return_value = ["HOST1"]
    state.load_shares.return_value = ["//HOST1/SHARE"]

    runner.share_pipeline.run = MagicMock()
    runner.file_pipeline.run = MagicMock()

    with patch(
        "snaffler.engine.runner.DomainPipeline"
    ) as domain_cls, patch(
        "snaffler.engine.runner.print_completion_stats"
    ):
        domain = domain_cls.return_value
        domain.get_dfs_shares.return_value = []

        runner.execute()

    # SharePipeline should NOT have run
    runner.share_pipeline.run.assert_not_called()
    # file_pipeline should have been called with loaded shares
    runner.file_pipeline.run.assert_called_once_with(["//HOST1/SHARE"])


def test_runner_domain_resume_partial_shares():
    """Some computers already enumerated — only remaining should be scanned."""
    cfg = make_cfg()
    cfg.auth.domain = "example.com"

    runner, state = _make_runner_with_state(cfg)

    # computer discovery done, DNS done, share discovery NOT done
    state.is_phase_done.side_effect = lambda phase: phase in (
        "computer_discovery_done", "dns_resolution_done",
    )
    state.load_computers.return_value = ["HOST1", "HOST2", "HOST3"]
    state.load_resolved_computers.return_value = ["HOST1", "HOST2", "HOST3"]

    # HOST1 already checked
    state.should_skip_computer.side_effect = lambda name: name == "HOST1"
    # SharePipeline finds shares on HOST2/HOST3
    runner.share_pipeline.run = MagicMock(
        return_value=["//HOST2/SHARE", "//HOST3/SHARE"]
    )
    # After storing, load_shares returns old + new
    state.load_shares.return_value = [
        "//HOST1/SHARE", "//HOST2/SHARE", "//HOST3/SHARE"
    ]

    runner.file_pipeline.run = MagicMock()

    with patch(
        "snaffler.engine.runner.DomainPipeline"
    ) as domain_cls, patch(
        "snaffler.engine.runner.print_completion_stats"
    ):
        domain = domain_cls.return_value
        domain.get_dfs_shares.return_value = []

        runner.execute()

    # SharePipeline should only get HOST2 and HOST3
    runner.share_pipeline.run.assert_called_once_with(["HOST2", "HOST3"])
    # file_pipeline gets ALL shares (old + new)
    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert sorted(paths) == ["//HOST1/SHARE", "//HOST2/SHARE", "//HOST3/SHARE"]


def test_runner_computer_resume_skips_shares():
    """--computer mode with resume: share_discovery_done skips SharePipeline."""
    cfg = make_cfg()
    cfg.targets.computer_targets = ["HOST1"]

    runner, state = _make_runner_with_state(cfg)
    state.is_phase_done.return_value = True  # all phases done (incl. DNS)
    state.load_resolved_computers.return_value = ["HOST1"]
    state.load_shares.return_value = ["//HOST1/SHARE"]

    runner.share_pipeline.run = MagicMock()
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    runner.share_pipeline.run.assert_not_called()
    runner.file_pipeline.run.assert_called_once_with(["//HOST1/SHARE"])


def test_runner_unc_resume_unchanged():
    """UNC mode doesn't use resume helpers (no share/computer discovery)."""
    cfg = make_cfg()
    cfg.targets.unc_targets = ["//HOST/SHARE"]

    runner, state = _make_runner_with_state(cfg)
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    # No phase checks for UNC mode
    state.is_phase_done.assert_not_called()
    runner.file_pipeline.run.assert_called_once_with(["//HOST/SHARE"])


def test_runner_domain_resume_no_computers_marks_phase_done():
    """Even with zero computers, phase flag must be set to avoid infinite LDAP retries."""
    cfg = make_cfg()
    cfg.auth.domain = "example.com"

    runner, state = _make_runner_with_state(cfg)
    state.is_phase_done.return_value = False
    state.load_shares.return_value = []

    runner.share_pipeline.run = MagicMock(return_value=[])
    runner.file_pipeline.run = MagicMock()

    with patch(
        "snaffler.engine.runner.DomainPipeline"
    ) as domain_cls, patch(
        "snaffler.engine.runner.print_completion_stats"
    ):
        domain = domain_cls.return_value
        domain.run.return_value = []  # zero computers
        domain.get_dfs_shares.return_value = []

        runner.execute()

    state.mark_phase_done.assert_any_call("computer_discovery_done")


def test_runner_shares_only_resume_skips_file_scan():
    """--shares-only with state must NOT trigger file scanning."""
    cfg = make_cfg()
    cfg.auth.domain = "example.com"
    cfg.targets.shares_only = True

    runner, state = _make_runner_with_state(cfg)
    state.is_phase_done.return_value = True  # all phases done
    state.load_computers.return_value = ["HOST1"]
    state.load_resolved_computers.return_value = ["HOST1"]
    state.load_shares.return_value = ["//HOST1/SHARE"]

    runner.share_pipeline.run = MagicMock()
    runner.file_pipeline.run = MagicMock()

    with patch(
        "snaffler.engine.runner.DomainPipeline"
    ) as domain_cls, patch(
        "snaffler.engine.runner.print_completion_stats"
    ):
        domain = domain_cls.return_value
        domain.get_dfs_shares.return_value = []

        runner.execute()

    # file_pipeline.run should NOT have been called
    runner.file_pipeline.run.assert_not_called()


def test_runner_shares_only_first_run_with_state():
    """--shares-only on first run: SharePipeline stores shares but returns []."""
    cfg = make_cfg()
    cfg.targets.computer_targets = ["HOST1"]
    cfg.targets.shares_only = True

    runner, state = _make_runner_with_state(cfg)
    state.is_phase_done.return_value = False
    state.load_resolved_computers.return_value = []
    state.load_unresolved_computers.return_value = ["HOST1"]
    state.should_skip_computer.return_value = False
    state.load_shares.return_value = ["//HOST1/SHARE"]

    runner.share_pipeline.run = MagicMock(return_value=[])
    runner.file_pipeline.run = MagicMock()

    with _resolve_all_hosts(), patch(
        "snaffler.engine.runner.print_completion_stats"
    ):
        runner.execute()

    # file_pipeline.run should NOT have been called
    runner.file_pipeline.run.assert_not_called()


def test_runner_shares_only_domain_dfs_skips_file_scan():
    """--shares-only with domain discovery: DFS paths must NOT trigger file scanning."""
    cfg = make_cfg()
    cfg.auth.domain = "example.com"
    cfg.targets.shares_only = True

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock()

    with patch(
        "snaffler.engine.runner.DomainPipeline"
    ) as domain_cls, patch(
        "snaffler.engine.runner.print_completion_stats"
    ):
        domain = domain_cls.return_value
        domain.run.return_value = []  # no computers
        domain.get_dfs_shares.return_value = ["//nas01/data", "//nas02/backup"]

        runner.execute()

    # DFS paths found, but file_pipeline must NOT be called
    runner.file_pipeline.run.assert_not_called()


def test_runner_sync_progress_from_state():
    """_sync_progress_from_state reads counts from DB."""
    cfg = make_cfg()
    runner, state = _make_runner_with_state(cfg)

    runner.progress.computers_total = 100
    runner.progress.computers_done = 5  # in-memory counter

    # DB has more (from previous run)
    state.count_checked_computers.return_value = 80
    state.count_checked_shares.return_value = 30
    state.count_checked_files.return_value = 500

    runner._sync_progress_from_state()

    assert runner.progress.computers_done == 80
    assert runner.progress.shares_walked == 30
    assert runner.progress.files_scanned == 500


def test_runner_sync_progress_no_state():
    """No crash when state is None."""
    cfg = make_cfg()
    runner = SnafflerRunner(cfg)
    runner._sync_progress_from_state()  # should be a no-op


def test_runner_stores_computers_on_discovery():
    """First domain run stores computers in state."""
    cfg = make_cfg()
    cfg.auth.domain = "example.com"

    runner, state = _make_runner_with_state(cfg)
    state.is_phase_done.return_value = False
    state.load_resolved_computers.return_value = []
    state.load_unresolved_computers.return_value = ["HOST1", "HOST2"]
    state.should_skip_computer.return_value = False
    state.load_shares.return_value = []

    runner.share_pipeline.run = MagicMock(return_value=[])
    runner.file_pipeline.run = MagicMock()

    with patch(
        "snaffler.engine.runner.DomainPipeline"
    ) as domain_cls, _resolve_all_hosts(), patch(
        "snaffler.engine.runner.print_completion_stats"
    ):
        domain = domain_cls.return_value
        domain.run.return_value = ["HOST1", "HOST2"]
        domain.get_dfs_shares.return_value = []

        runner.execute()

    # store_computers is called in _resume_computer_discovery and again
    # (idempotently) in _resolve_computers to ensure rows exist for --computer mode
    state.store_computers.assert_any_call(["HOST1", "HOST2"])
    state.mark_phase_done.assert_any_call("computer_discovery_done")


def test_runner_stores_shares_on_discovery():
    """First share discovery marks phase done; per-computer marking is in SharePipeline."""
    cfg = make_cfg()
    cfg.auth.domain = "example.com"

    runner, state = _make_runner_with_state(cfg)
    state.is_phase_done.return_value = False
    state.load_resolved_computers.return_value = []
    state.load_unresolved_computers.return_value = ["HOST1"]
    state.should_skip_computer.return_value = False
    state.load_shares.return_value = ["//HOST1/SHARE"]

    runner.share_pipeline.run = MagicMock(return_value=["//HOST1/SHARE"])
    runner.file_pipeline.run = MagicMock()

    with patch(
        "snaffler.engine.runner.DomainPipeline"
    ) as domain_cls, _resolve_all_hosts(), patch(
        "snaffler.engine.runner.print_completion_stats"
    ):
        domain = domain_cls.return_value
        domain.run.return_value = ["HOST1"]
        domain.get_dfs_shares.return_value = []

        runner.execute()

    # Per-computer marking now happens inside SharePipeline, not runner.
    # Runner only sets the phase flag and loads all shares.
    state.mark_phase_done.assert_any_call("share_discovery_done")
    state.load_shares.assert_called()


# ---------- DNS pre-resolution ----------


def _mock_getaddrinfo(resolvable):
    """Return a getaddrinfo mock that resolves only hosts in *resolvable* dict."""
    def fake_getaddrinfo(host, port, family=0, type_=0, proto=0, flags=0):
        if host in resolvable:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (resolvable[host], port))]
        raise socket.gaierror(8, "nodename nor servname provided, or not known")
    return fake_getaddrinfo


def test_runner_dns_resolution_filters_dead_hosts():
    """3 hosts, 1 fails DNS → only 2 go to share discovery."""
    cfg = make_cfg()
    cfg.targets.computer_targets = ["HOST1", "HOST2", "DEAD"]

    runner = SnafflerRunner(cfg)
    runner.share_pipeline.run = MagicMock(return_value=["//HOST1/SHARE"])
    runner.file_pipeline.run = MagicMock()

    resolvable = {"HOST1": "10.0.0.1", "HOST2": "10.0.0.2"}

    with patch(
        "snaffler.engine.runner.socket.getaddrinfo",
        side_effect=_mock_getaddrinfo(resolvable),
    ), _port_always_open(), patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    # SharePipeline should only get resolved hosts
    called_hosts = runner.share_pipeline.run.call_args[0][0]
    assert sorted(called_hosts) == ["HOST1", "HOST2"]

    # Progress counters
    assert runner.progress.dns_total == 3
    assert runner.progress.dns_resolved == 2
    assert runner.progress.dns_filtered == 1


def test_runner_dns_resolution_resume_skips():
    """_PHASE_DNS set → loads resolved from state, no getaddrinfo calls."""
    cfg = make_cfg()
    cfg.targets.computer_targets = ["HOST1", "HOST2"]

    runner, state = _make_runner_with_state(cfg)
    state.is_phase_done.side_effect = lambda p: p == "dns_resolution_done"
    state.load_resolved_computers.return_value = ["HOST1"]
    state.load_shares.return_value = ["//HOST1/SHARE"]
    state.should_skip_computer.return_value = False

    runner.share_pipeline.run = MagicMock(return_value=[])
    runner.file_pipeline.run = MagicMock()

    with patch(
        "snaffler.engine.runner.socket.getaddrinfo",
        side_effect=AssertionError("should not be called"),
    ) as mock_gai, patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    state.load_resolved_computers.assert_called()
    # getaddrinfo must NOT have been called — DNS phase was already done
    mock_gai.assert_not_called()
    # SharePipeline should get only the resolved host
    runner.share_pipeline.run.assert_called_once_with(["HOST1"])


def test_runner_dns_resolution_partial_resume():
    """Some already resolved, only unresolved get DNS lookups."""
    cfg = make_cfg()
    cfg.targets.computer_targets = ["HOST1", "HOST2", "HOST3"]

    runner, state = _make_runner_with_state(cfg)

    # DNS phase NOT done, shares phase NOT done
    state.is_phase_done.return_value = False
    # HOST1 already resolved in state, HOST2/HOST3 unresolved
    state.load_resolved_computers.return_value = ["HOST1"]
    state.load_unresolved_computers.return_value = ["HOST2", "HOST3"]
    state.should_skip_computer.return_value = False
    state.load_shares.return_value = []

    runner.share_pipeline.run = MagicMock(return_value=[])
    runner.file_pipeline.run = MagicMock()

    # Only HOST2 resolves; HOST3 is dead
    resolvable = {"HOST2": "10.0.0.2"}

    with patch(
        "snaffler.engine.runner.socket.getaddrinfo",
        side_effect=_mock_getaddrinfo(resolvable),
    ), _port_always_open(), patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    # HOST2 resolved → set_computer_ip called
    state.set_computer_ip.assert_called_once_with("HOST2", "10.0.0.2")
    # SharePipeline gets HOST1 (already resolved) + HOST2 (just resolved)
    called_hosts = runner.share_pipeline.run.call_args[0][0]
    assert sorted(called_hosts) == ["HOST1", "HOST2"]
    state.mark_phase_done.assert_any_call("dns_resolution_done")


def test_runner_dns_resolution_computer_mode():
    """--computer mode also runs DNS pre-resolution."""
    cfg = make_cfg()
    cfg.targets.computer_targets = ["ALIVE", "DEAD"]

    runner = SnafflerRunner(cfg)
    runner.share_pipeline.run = MagicMock(return_value=["//ALIVE/SHARE"])
    runner.file_pipeline.run = MagicMock()

    resolvable = {"ALIVE": "10.0.0.1"}

    with patch(
        "snaffler.engine.runner.socket.getaddrinfo",
        side_effect=_mock_getaddrinfo(resolvable),
    ), _port_always_open(), patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    # Only ALIVE should reach share pipeline
    runner.share_pipeline.run.assert_called_once_with(["ALIVE"])
    runner.file_pipeline.run.assert_called_once_with(["//ALIVE/SHARE"])


def test_runner_dns_resolution_stores_ips():
    """Verifies state.set_computer_ip() called for each resolved host."""
    cfg = make_cfg()
    cfg.targets.computer_targets = ["HOST1", "HOST2"]

    runner, state = _make_runner_with_state(cfg)
    state.is_phase_done.return_value = False
    state.load_resolved_computers.return_value = []
    state.load_unresolved_computers.return_value = ["HOST1", "HOST2"]
    state.should_skip_computer.return_value = False
    state.load_shares.return_value = []

    runner.share_pipeline.run = MagicMock(return_value=[])
    runner.file_pipeline.run = MagicMock()

    resolvable = {"HOST1": "10.0.0.1", "HOST2": "10.0.0.2"}

    with patch(
        "snaffler.engine.runner.socket.getaddrinfo",
        side_effect=_mock_getaddrinfo(resolvable),
    ), _port_always_open(), patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    # Both should have had IPs stored
    ip_calls = state.set_computer_ip.call_args_list
    stored = {c[0][0]: c[0][1] for c in ip_calls}
    assert stored == {"HOST1": "10.0.0.1", "HOST2": "10.0.0.2"}
    state.mark_phase_done.assert_any_call("dns_resolution_done")


def test_runner_dns_resolution_interrupt_persists_partial():
    """Ctrl+C mid-DNS: already-resolved IPs saved, phase NOT marked done, re-raises."""
    cfg = make_cfg()
    cfg.targets.computer_targets = ["HOST1", "HOST2"]
    # Force sequential so we control ordering
    cfg.advanced.share_threads = 1

    runner, state = _make_runner_with_state(cfg)
    state.is_phase_done.return_value = False
    state.load_resolved_computers.return_value = []
    state.load_unresolved_computers.return_value = ["HOST1", "HOST2"]

    # HOST1 resolves, HOST2 triggers interrupt in the result-processing loop
    call_count = {"n": 0}

    def fake_getaddrinfo(host, port, family=0, type_=0, proto=0, flags=0):
        call_count["n"] += 1
        if host == "HOST1":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", port))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.2", port))]

    # Intercept set_computer_ip: after first successful store, raise KeyboardInterrupt
    original_set_ip = state.set_computer_ip

    def set_ip_then_interrupt(name, ip):
        original_set_ip(name, ip)
        if state.set_computer_ip.call_count >= 1:
            raise KeyboardInterrupt

    state.set_computer_ip = MagicMock(side_effect=set_ip_then_interrupt)

    with patch(
        "snaffler.engine.runner.socket.getaddrinfo",
        side_effect=fake_getaddrinfo,
    ), _port_always_open():
        with pytest.raises(KeyboardInterrupt):
            runner._resolve_computers(["HOST1", "HOST2"])

    # At least one IP was persisted before the interrupt.
    # Verify via the *original* mock (the inner call target) that a real
    # hostname→IP pair from getaddrinfo was forwarded to the backing store.
    assert original_set_ip.call_count >= 1
    persisted = {c[0][0]: c[0][1] for c in original_set_ip.call_args_list}
    # Every persisted entry must match what getaddrinfo would have returned
    expected_ips = {"HOST1": "10.0.0.1", "HOST2": "10.0.0.2"}
    for hostname, ip in persisted.items():
        assert hostname in expected_ips, f"Unexpected host persisted: {hostname}"
        assert ip == expected_ips[hostname], (
            f"Wrong IP for {hostname}: got {ip}, expected {expected_ips[hostname]}"
        )

    # Phase must NOT be marked done — unresolved hosts need retry on resume
    phase_calls = [
        c for c in state.mark_phase_done.call_args_list
        if c[0][0] == "dns_resolution_done"
    ]
    assert len(phase_calls) == 0


# ---------- TCP port reachability check ----------


def test_runner_dns_filters_port_closed():
    """Host resolves in DNS but port 445 is unreachable → filtered out."""
    cfg = make_cfg()
    cfg.targets.computer_targets = ["ALIVE", "FIREWALLED", "DEAD"]

    runner = SnafflerRunner(cfg)
    runner.share_pipeline.run = MagicMock(return_value=["//ALIVE/SHARE"])
    runner.file_pipeline.run = MagicMock()

    # All three resolve in DNS; DEAD does not
    resolvable = {"ALIVE": "10.0.0.1", "FIREWALLED": "10.0.0.2"}

    # Port 445 open only on ALIVE (10.0.0.1)
    def fake_create_connection(address, timeout=None):
        ip, port = address
        if ip == "10.0.0.1":
            return MagicMock()
        raise OSError("Connection refused")

    with patch(
        "snaffler.engine.runner.socket.getaddrinfo",
        side_effect=_mock_getaddrinfo(resolvable),
    ), patch(
        "snaffler.engine.runner.socket.create_connection",
        side_effect=fake_create_connection,
    ), patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    # Only ALIVE should reach share pipeline
    runner.share_pipeline.run.assert_called_once_with(["ALIVE"])

    # 3 total, 1 resolved (DNS+port), 2 filtered (1 DNS + 1 port)
    assert runner.progress.dns_total == 3
    assert runner.progress.dns_resolved == 1
    assert runner.progress.dns_filtered == 2


def test_runner_dns_port_closed_log_message(caplog):
    """Port-closed host logs 'port 445 unreachable', not 'no record'."""
    import logging

    cfg = make_cfg()
    cfg.targets.computer_targets = ["FIREWALLED"]

    runner = SnafflerRunner(cfg)
    runner.share_pipeline.run = MagicMock(return_value=[])
    runner.file_pipeline.run = MagicMock()

    # DNS resolves, but port 445 is closed
    resolvable = {"FIREWALLED": "10.0.0.2"}

    def fake_create_connection(address, timeout=None):
        raise OSError("Connection refused")

    with patch(
        "snaffler.engine.runner.socket.getaddrinfo",
        side_effect=_mock_getaddrinfo(resolvable),
    ), patch(
        "snaffler.engine.runner.socket.create_connection",
        side_effect=fake_create_connection,
    ), patch("snaffler.engine.runner.print_completion_stats"), \
         caplog.at_level(logging.DEBUG, logger="snaffler"):
        runner.execute()

    # Should log the accurate "port 445 unreachable" message
    port_msgs = [
        r.message for r in caplog.records
        if "FIREWALLED" in r.message and "port 445 unreachable" in r.message
    ]
    assert len(port_msgs) == 1
    assert "10.0.0.2" in port_msgs[0]

    # Must NOT log "no record" — the host did resolve in DNS
    wrong_msgs = [
        r.message for r in caplog.records
        if "FIREWALLED" in r.message and "no record" in r.message
    ]
    assert len(wrong_msgs) == 0


def test_runner_dns_all_lookups_fail():
    """All hosts fail DNS resolution — share/file pipelines not called, no crash."""
    cfg = make_cfg()
    cfg.targets.computer_targets = ["DEAD1", "DEAD2", "DEAD3"]

    runner = SnafflerRunner(cfg)
    runner.share_pipeline.run = MagicMock(return_value=[])
    runner.file_pipeline.run = MagicMock()

    # Nothing resolves
    with patch(
        "snaffler.engine.runner.socket.getaddrinfo",
        side_effect=_mock_getaddrinfo({}),
    ), _port_always_open(), patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    # SharePipeline should NOT have been called (no resolved hosts)
    runner.share_pipeline.run.assert_not_called()
    # FilePipeline should NOT have been called
    runner.file_pipeline.run.assert_not_called()

    # All hosts filtered
    assert runner.progress.dns_total == 3
    assert runner.progress.dns_resolved == 0
    assert runner.progress.dns_filtered == 3


# ---------- share filtering (--share / --exclude-share) ----------


def test_runner_unc_share_filter_include():
    """--share filter on UNC paths: only matching shares scanned."""
    cfg = make_cfg()
    cfg.targets.unc_targets = ["//HOST/IT_Data", "//HOST/HR_Data", "//HOST/Finance"]
    cfg.targets.share_filter = ["IT*"]

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert paths == ["//HOST/IT_Data"]


def test_runner_unc_share_filter_exclude():
    """--exclude-share on UNC paths: matching shares skipped."""
    cfg = make_cfg()
    cfg.targets.unc_targets = ["//HOST/DATA", "//HOST/IPC$", "//HOST/print$"]
    cfg.targets.exclude_share = ["IPC$", "print$"]

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert paths == ["//HOST/DATA"]


def test_runner_unc_share_filter_include_and_exclude():
    """Both --share and --exclude-share: include first, then exclude."""
    cfg = make_cfg()
    cfg.targets.unc_targets = [
        "//HOST/HR_Data",
        "//HOST/HR_Archive",
        "//HOST/Finance",
    ]
    cfg.targets.share_filter = ["HR*"]
    cfg.targets.exclude_share = ["HR_Archive*"]

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert paths == ["//HOST/HR_Data"]


def test_runner_unc_share_filter_all_excluded():
    """All UNC paths filtered out: file_pipeline not called."""
    cfg = make_cfg()
    cfg.targets.unc_targets = ["//HOST/IPC$"]
    cfg.targets.exclude_share = ["IPC$"]

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    runner.file_pipeline.run.assert_not_called()


def test_runner_unc_no_filter_passes_all():
    """No share filters: all UNC paths pass through."""
    cfg = make_cfg()
    cfg.targets.unc_targets = ["//HOST/A", "//HOST/B", "//HOST/C"]

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert paths == ["//HOST/A", "//HOST/B", "//HOST/C"]


def test_runner_unc_share_filter_case_insensitive():
    """Share filter is case-insensitive on UNC paths."""
    cfg = make_cfg()
    cfg.targets.unc_targets = ["//HOST/DATA", "//HOST/data", "//HOST/Other"]
    cfg.targets.share_filter = ["data"]

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert sorted(paths) == ["//HOST/DATA", "//HOST/data"]


def test_runner_dfs_share_filter():
    """DFS paths are filtered by --exclude-share before merge."""
    cfg = make_cfg()
    cfg.auth.domain = "example.com"
    cfg.targets.exclude_share = ["backup*"]

    runner = SnafflerRunner(cfg)

    with patch(
        "snaffler.engine.runner.DomainPipeline"
    ) as domain_cls, _resolve_all_hosts(), patch(
        "snaffler.engine.runner.print_completion_stats"
    ):
        domain = domain_cls.return_value
        domain.run.return_value = ["HOST1"]
        domain.get_dfs_shares.return_value = [
            "//nas01/data",
            "//nas01/backup_daily",
        ]

        runner.share_pipeline.run = MagicMock(return_value=["//HOST1/SHARE"])
        runner.file_pipeline.run = MagicMock()

        runner.execute()

    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    # backup_daily should be filtered out
    assert "//nas01/data" in paths
    assert "//nas01/backup_daily" not in paths
    assert "//HOST1/SHARE" in paths


def test_runner_unc_share_filter_with_subpath():
    """UNC paths with subdirectories: share name correctly extracted."""
    cfg = make_cfg()
    cfg.targets.unc_targets = [
        "//HOST/IT_Data/subfolder/file.txt",
        "//HOST/HR_Data/deep/path",
    ]
    cfg.targets.share_filter = ["IT*"]

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert paths == ["//HOST/IT_Data/subfolder/file.txt"]


# ---------- share filtering on resume ----------


def test_runner_resume_share_filter_exclude():
    """Resume with share_discovery_done + --exclude-share: excluded shares NOT passed to file_pipeline."""
    cfg = make_cfg()
    cfg.targets.computer_targets = ["HOST1"]
    cfg.targets.exclude_share = ["JUNK$"]

    runner, state = _make_runner_with_state(cfg)
    # All phases done (DNS + shares)
    state.is_phase_done.return_value = True
    state.load_resolved_computers.return_value = ["HOST1"]
    state.load_shares.return_value = [
        "//HOST1/DATA",
        "//HOST1/JUNK$",
        "//HOST1/IT_Share",
    ]

    runner.share_pipeline.run = MagicMock()
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    # SharePipeline should NOT have run (phase already done)
    runner.share_pipeline.run.assert_not_called()
    # file_pipeline should get shares WITHOUT the excluded JUNK$
    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert "//HOST1/DATA" in paths
    assert "//HOST1/IT_Share" in paths
    assert "//HOST1/JUNK$" not in paths
    # Progress should reflect filtered count
    assert runner.progress.shares_found == 2


def test_runner_resume_share_filter_include():
    """Resume with share_discovery_done + --share include: only matching shares passed to file_pipeline."""
    cfg = make_cfg()
    cfg.targets.computer_targets = ["HOST1"]
    cfg.targets.share_filter = ["IT*"]

    runner, state = _make_runner_with_state(cfg)
    # All phases done (DNS + shares)
    state.is_phase_done.return_value = True
    state.load_resolved_computers.return_value = ["HOST1"]
    state.load_shares.return_value = [
        "//HOST1/IT_Share",
        "//HOST1/HR_Data",
        "//HOST1/Finance",
    ]

    runner.share_pipeline.run = MagicMock()
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    # SharePipeline should NOT have run (phase already done)
    runner.share_pipeline.run.assert_not_called()
    # file_pipeline should only get the IT_Share
    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert paths == ["//HOST1/IT_Share"]
    # Progress should reflect filtered count
    assert runner.progress.shares_found == 1


def test_runner_resume_share_filter_after_pipeline_run():
    """After share_pipeline.run() completes, loaded shares are filtered before returning."""
    cfg = make_cfg()
    cfg.auth.domain = "example.com"
    cfg.targets.exclude_share = ["ADMIN$", "IPC$"]

    runner, state = _make_runner_with_state(cfg)

    # computer + DNS done, share discovery NOT done
    state.is_phase_done.side_effect = lambda phase: phase in (
        "computer_discovery_done", "dns_resolution_done",
    )
    state.load_computers.return_value = ["HOST1"]
    state.load_resolved_computers.return_value = ["HOST1"]
    state.should_skip_computer.return_value = False
    # After pipeline run, load_shares returns all discovered shares
    state.load_shares.return_value = [
        "//HOST1/DATA",
        "//HOST1/ADMIN$",
        "//HOST1/IPC$",
        "//HOST1/Users",
    ]

    runner.share_pipeline.run = MagicMock(return_value=[])
    runner.file_pipeline.run = MagicMock()

    with patch(
        "snaffler.engine.runner.DomainPipeline"
    ) as domain_cls, patch(
        "snaffler.engine.runner.print_completion_stats"
    ):
        domain = domain_cls.return_value
        domain.get_dfs_shares.return_value = []

        runner.execute()

    # file_pipeline should get shares WITHOUT ADMIN$ and IPC$
    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert "//HOST1/DATA" in paths
    assert "//HOST1/Users" in paths
    assert "//HOST1/ADMIN$" not in paths
    assert "//HOST1/IPC$" not in paths


# ---------- --exclusions computer/UNC filtering ----------


def test_exclusions_filter_computer_targets():
    """--exclusions removes matching computers before DNS resolution."""
    cfg = make_cfg()
    cfg.targets.computer_targets = ["HOST1", "HOST2", "HOST3"]
    cfg.targets.exclusions = ["HOST2"]

    runner = SnafflerRunner(cfg)
    runner.share_pipeline.run = MagicMock(return_value=["//HOST1/SHARE", "//HOST3/SHARE"])
    runner.file_pipeline.run = MagicMock()

    resolvable = {"HOST1": "10.0.0.1", "HOST3": "10.0.0.3"}

    with patch(
        "snaffler.engine.runner.socket.getaddrinfo",
        side_effect=_mock_getaddrinfo(resolvable),
    ), _port_always_open(), patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    # Only HOST1 and HOST3 should reach share pipeline (HOST2 excluded)
    runner.share_pipeline.run.assert_called_once()
    called_hosts = runner.share_pipeline.run.call_args[0][0]
    assert sorted(called_hosts) == ["HOST1", "HOST3"]


def test_exclusions_filter_unc_targets():
    """--exclusions drops UNC paths whose hostname matches the exclusion list."""
    cfg = make_cfg()
    cfg.targets.unc_targets = [
        "//HOST1/Share1",
        "//HOST2/Share2",
        "//HOST3/Share3",
    ]
    cfg.targets.exclusions = ["HOST2"]

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert "//HOST1/Share1" in paths
    assert "//HOST3/Share3" in paths
    assert "//HOST2/Share2" not in paths


def test_exclusions_case_insensitive():
    """Exclusion matching is case-insensitive."""
    cfg = make_cfg()
    cfg.targets.computer_targets = ["Server1", "SERVER2", "server3"]
    cfg.targets.exclusions = ["server1", "Server3"]

    runner = SnafflerRunner(cfg)
    runner.share_pipeline.run = MagicMock(return_value=[])
    runner.file_pipeline.run = MagicMock()

    resolvable = {"SERVER2": "10.0.0.2"}

    with patch(
        "snaffler.engine.runner.socket.getaddrinfo",
        side_effect=_mock_getaddrinfo(resolvable),
    ), _port_always_open(), patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    # Only SERVER2 should pass through (Server1 and server3 excluded)
    runner.share_pipeline.run.assert_called_once()
    called_hosts = runner.share_pipeline.run.call_args[0][0]
    assert called_hosts == ["SERVER2"]


def test_exclusions_empty_no_effect():
    """Empty exclusions list doesn't filter anything."""
    cfg = make_cfg()
    cfg.targets.unc_targets = ["//HOST1/A", "//HOST2/B"]
    cfg.targets.exclusions = []

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert paths == ["//HOST1/A", "//HOST2/B"]


# ---------- BUG-M: DNS resolution must not leak global timeout ----------


def test_dns_resolution_does_not_leak_global_timeout():
    """BUG-M: _resolve_computers must not alter socket.getdefaulttimeout()."""
    cfg = make_cfg()
    cfg.targets.computer_targets = ["HOST1", "HOST2"]
    cfg.auth.smb_timeout = 5

    runner, state = _make_runner_with_state(cfg)
    state.is_phase_done.return_value = False
    state.load_unresolved_computers.return_value = ["HOST1", "HOST2"]
    state.load_resolved_computers.return_value = []

    original_timeout = socket.getdefaulttimeout()

    with _resolve_all_hosts():
        runner._resolve_computers(["HOST1", "HOST2"])

    assert socket.getdefaulttimeout() == original_timeout


# ---------- BUG-X1: DNS setdefaulttimeout race ----------

def test_dns_resolve_does_not_call_setdefaulttimeout():
    """BUG-X1: _resolve_computers must not call socket.setdefaulttimeout() —
    it is process-global and races across 100 concurrent DNS threads."""
    cfg = make_cfg()
    cfg.targets.computer_targets = ["HOST1"]
    cfg.auth.smb_timeout = 5

    runner, state = _make_runner_with_state(cfg)
    state.is_phase_done.return_value = False
    state.load_unresolved_computers.return_value = ["HOST1"]
    state.load_resolved_computers.return_value = []

    with _resolve_all_hosts(), \
         patch("snaffler.engine.runner.socket.setdefaulttimeout") as mock_sdt:
        runner._resolve_computers(["HOST1"])

    mock_sdt.assert_not_called()


# ---------- BUG-X6: status thread exception resilience ----------

def test_status_loop_survives_format_status_exception():
    """BUG-X6: If format_status() raises, the status thread must not die."""
    cfg = make_cfg()
    with _patch_finding_store():
        runner = SnafflerRunner(cfg)

    # Make format_status raise on the first call
    call_count = [0]
    original_format = runner.progress.format_status

    def exploding_format():
        call_count[0] += 1
        if call_count[0] == 1:
            raise RuntimeError("kaboom")
        return original_format()

    runner.progress.format_status = exploding_format

    # Run the status loop briefly
    import time
    with patch("snaffler.engine.runner._STATUS_INTERVAL", 0.05):
        runner._start_status_thread()
        time.sleep(0.25)
        runner._stop_status_thread()

    # The loop should have survived the first exception and called again
    assert call_count[0] >= 2, (
        f"Status loop should have continued after exception, "
        f"but format_status was only called {call_count[0]} time(s)"
    )


# ---------- BUG-X7: _sync_progress_from_state logs debug ----------

def test_sync_progress_from_state_logs_on_error(caplog):
    """BUG-X7: _sync_progress_from_state should log at DEBUG, not silently pass."""
    import logging

    cfg = make_cfg()
    with _patch_finding_store():
        runner = SnafflerRunner(cfg)

    # Inject a state that raises on count_checked_computers
    state = MagicMock()
    state.count_checked_computers.side_effect = RuntimeError("DB corrupted")
    runner.state = state

    with caplog.at_level(logging.DEBUG, logger="snaffler"):
        runner._sync_progress_from_state()

    assert any("Failed to sync progress from state DB" in r.message for r in caplog.records)


# ---------- BUG-Z4: PySocks exceptions crash DNS resolution loop ----------

def test_dns_resolution_survives_non_oserror_exception():
    """BUG-Z4: PySocks or other non-OSError exceptions in DNS futures must not
    crash the entire as_completed loop — remaining futures should still be processed."""
    from concurrent.futures import ThreadPoolExecutor as RealTPE

    cfg = make_cfg()

    runner, state = _make_runner_with_state(cfg)
    state.is_phase_done.return_value = False
    state.load_unresolved_computers.return_value = ["HOST1", "HOST2", "HOST3"]
    state.load_resolved_computers.return_value = []

    def resolve_one_with_pysocks_error(hostname):
        """HOST2 raises a non-OSError exception (simulating PySocks)."""
        if hostname == "HOST2":
            raise RuntimeError("PySocks: General SOCKS server failure")
        return "127.0.0.1"

    class PatchedExecutor:
        def __init__(self, **kwargs):
            self._pool = RealTPE(**kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self._pool.__exit__(*args)

        def submit(self, fn, hostname):
            return self._pool.submit(resolve_one_with_pysocks_error, hostname)

        def shutdown(self, *args, **kwargs):
            return self._pool.shutdown(*args, **kwargs)

    with patch("snaffler.engine.runner.ThreadPoolExecutor", PatchedExecutor):
        resolved = runner._resolve_computers(["HOST1", "HOST2", "HOST3"])

    # HOST1 and HOST3 should resolve, HOST2 should fail gracefully
    assert "HOST1" in resolved
    assert "HOST3" in resolved
    assert "HOST2" not in resolved
    assert len(resolved) == 2


# ---------- finding count restore on resume ----------

def test_sync_progress_restores_finding_counts():
    """_sync_progress_from_state restores files_matched and severity counters from DB."""
    cfg = make_cfg()
    cfg.auth.domain = "CORP.LOCAL"
    runner, state = _make_runner_with_state(cfg)

    state.count_findings_by_triage.return_value = {
        "Black": 2,
        "Red": 10,
        "Yellow": 5,
        "Green": 3,
    }

    runner._sync_progress_from_state()

    assert runner.progress.files_matched == 20
    assert runner.progress.severity_black == 2
    assert runner.progress.severity_red == 10
    assert runner.progress.severity_yellow == 5
    assert runner.progress.severity_green == 3


def test_sync_progress_uses_max_for_finding_counts():
    """Finding counts use max() so live scan counts are not overwritten by stale DB values."""
    cfg = make_cfg()
    cfg.auth.domain = "CORP.LOCAL"
    runner, state = _make_runner_with_state(cfg)

    # Simulate live scan already found more than DB has
    runner.progress.severity_red = 50
    runner.progress.files_matched = 100

    state.count_findings_by_triage.return_value = {
        "Red": 10,
        "Yellow": 5,
    }

    runner._sync_progress_from_state()

    # Live counts should NOT be reduced
    assert runner.progress.severity_red == 50
    assert runner.progress.files_matched == 100
    # But new categories from DB should be picked up
    assert runner.progress.severity_yellow == 5


def test_sync_progress_empty_findings():
    """No findings in DB → counters stay at zero."""
    cfg = make_cfg()
    cfg.auth.domain = "CORP.LOCAL"
    runner, state = _make_runner_with_state(cfg)

    state.count_findings_by_triage.return_value = {}

    runner._sync_progress_from_state()

    assert runner.progress.files_matched == 0
    assert runner.progress.severity_black == 0


# ---------- --rescan-unreadable ----------


def test_runner_normal_scan_only_walks_readable_shares():
    """Normal scan: even though unreadable shares are stored, only readable
    shares reach file_pipeline.run()."""
    cfg = make_cfg()
    cfg.targets.computer_targets = ["HOST1"]

    runner, state = _make_runner_with_state(cfg)
    # DNS done, share discovery NOT done (triggers SharePipeline.run)
    state.is_phase_done.side_effect = lambda phase: phase == "dns_resolution_done"
    state.load_resolved_computers.return_value = ["HOST1"]
    state.should_skip_computer.return_value = False
    # After share pipeline stores all, load_shares returns only readable
    state.load_shares.return_value = ["//HOST1/PUBLIC", "//HOST1/OPEN"]

    # SharePipeline returns only readable shares
    runner.share_pipeline.run = MagicMock(
        return_value=["//HOST1/PUBLIC", "//HOST1/OPEN"]
    )
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    # File pipeline must only get readable shares
    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert sorted(paths) == ["//HOST1/OPEN", "//HOST1/PUBLIC"]


def test_runner_resume_only_walks_readable_shares():
    """On resume (share phase done), load_shares only returns readable shares,
    so unreadable shares from a previous scan never reach file_pipeline."""
    cfg = make_cfg()
    cfg.targets.computer_targets = ["HOST1"]

    runner, state = _make_runner_with_state(cfg)
    # All phases done
    state.is_phase_done.return_value = True
    state.load_resolved_computers.return_value = ["HOST1"]
    # load_shares filters out unreadable (readable=0)
    state.load_shares.return_value = ["//HOST1/PUBLIC"]

    runner.share_pipeline.run = MagicMock()
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    # SharePipeline should NOT have run (phase already done)
    runner.share_pipeline.run.assert_not_called()
    # File pipeline should only get the readable share
    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert paths == ["//HOST1/PUBLIC"]


def test_rescan_unreadable_finds_newly_readable():
    """--rescan-unreadable re-tests denied shares and scans newly readable ones."""
    cfg = make_cfg()
    cfg.targets.rescan_unreadable = True

    runner, state = _make_runner_with_state(cfg)
    state.load_unreadable_shares.return_value = [
        "//HOST1/SECRET",
        "//HOST1/FINANCE",
        "//HOST1/STILL_DENIED",
    ]

    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.discovery.shares.ShareFinder") as finder_cls, \
         patch("snaffler.engine.runner.print_completion_stats"):
        finder = finder_cls.return_value
        # SECRET and FINANCE now readable, STILL_DENIED still denied
        finder.is_share_readable.side_effect = lambda c, s: s != "STILL_DENIED"

        runner.execute()

    # File pipeline should get the 2 newly readable shares
    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert sorted(paths) == ["//HOST1/FINANCE", "//HOST1/SECRET"]

    # DB should be updated for newly readable shares
    assert state.update_share_readable.call_count == 2
    state.update_share_readable.assert_any_call("//HOST1/SECRET")
    state.update_share_readable.assert_any_call("//HOST1/FINANCE")

    # Progress should reflect newly readable count
    assert runner.progress.shares_found == 2


def test_rescan_unreadable_none_become_readable():
    """--rescan-unreadable with all shares still denied: file pipeline not called."""
    cfg = make_cfg()
    cfg.targets.rescan_unreadable = True

    runner, state = _make_runner_with_state(cfg)
    state.load_unreadable_shares.return_value = [
        "//HOST1/SECRET",
        "//HOST1/FINANCE",
    ]

    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.discovery.shares.ShareFinder") as finder_cls, \
         patch("snaffler.engine.runner.print_completion_stats"):
        finder = finder_cls.return_value
        finder.is_share_readable.return_value = False

        runner.execute()

    runner.file_pipeline.run.assert_not_called()
    state.update_share_readable.assert_not_called()


def test_rescan_unreadable_empty_db():
    """--rescan-unreadable with no unreadable shares in DB: nothing happens."""
    cfg = make_cfg()
    cfg.targets.rescan_unreadable = True

    runner, state = _make_runner_with_state(cfg)
    state.load_unreadable_shares.return_value = []

    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    runner.file_pipeline.run.assert_not_called()


def test_rescan_unreadable_extracts_host_and_share():
    """--rescan-unreadable correctly parses //host/share from UNC paths."""
    cfg = make_cfg()
    cfg.targets.rescan_unreadable = True

    runner, state = _make_runner_with_state(cfg)
    state.load_unreadable_shares.return_value = ["//dc01/ADMIN$"]

    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.discovery.shares.ShareFinder") as finder_cls, \
         patch("snaffler.engine.runner.print_completion_stats"):
        finder = finder_cls.return_value
        finder.is_share_readable.return_value = True

        runner.execute()

    # Verify correct host/share extraction
    finder.is_share_readable.assert_called_once_with("dc01", "ADMIN$")


def test_rescan_unreadable_skips_other_modes(caplog):
    """--rescan-unreadable takes priority: other targeting modes are not run."""
    import logging
    cfg = make_cfg()
    cfg.targets.rescan_unreadable = True
    cfg.targets.unc_targets = ["//HOST/SHARE"]  # should be ignored

    runner, state = _make_runner_with_state(cfg)
    state.load_unreadable_shares.return_value = ["//OTHER/DENIED"]

    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.discovery.shares.ShareFinder") as finder_cls, \
         patch("snaffler.engine.runner.print_completion_stats"), \
         caplog.at_level(logging.WARNING, logger="snaffler"):
        finder = finder_cls.return_value
        finder.is_share_readable.return_value = True

        runner.execute()

    # Should scan the rescan target, not the UNC target
    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert paths == ["//OTHER/DENIED"]

    # Should warn about ignored targets
    assert any("--rescan-unreadable takes priority" in r.message
               and "--unc" in r.message for r in caplog.records)


def test_rescan_unreadable_malformed_path_skipped():
    """Malformed UNC paths (no share component) are silently skipped."""
    cfg = make_cfg()
    cfg.targets.rescan_unreadable = True

    runner, state = _make_runner_with_state(cfg)
    state.load_unreadable_shares.return_value = [
        "//HOST1/SHARE",
        "badpath",  # no //host/share structure
    ]

    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.discovery.shares.ShareFinder") as finder_cls, \
         patch("snaffler.engine.runner.print_completion_stats"):
        finder = finder_cls.return_value
        finder.is_share_readable.return_value = True

        runner.execute()

    # Only the valid path should be tested
    finder.is_share_readable.assert_called_once_with("HOST1", "SHARE")
    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert paths == ["//HOST1/SHARE"]


def test_rescan_unreadable_exception_continues(caplog):
    """If is_share_readable throws on one share, the loop continues to others."""
    import logging
    cfg = make_cfg()
    cfg.targets.rescan_unreadable = True

    runner, state = _make_runner_with_state(cfg)
    state.load_unreadable_shares.return_value = [
        "//HOST1/EXPLODES",
        "//HOST1/WORKS",
        "//HOST2/ALSO_EXPLODES",
        "//HOST2/FINE",
    ]

    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.discovery.shares.ShareFinder") as finder_cls, \
         patch("snaffler.engine.runner.print_completion_stats"), \
         caplog.at_level(logging.INFO, logger="snaffler"):
        finder = finder_cls.return_value

        def selective_readable(computer, share_name):
            if share_name in ("EXPLODES", "ALSO_EXPLODES"):
                raise ConnectionError("connection reset")
            return True

        finder.is_share_readable.side_effect = selective_readable

        runner.execute()

    # Should still scan the shares that didn't throw
    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert sorted(paths) == ["//HOST1/WORKS", "//HOST2/FINE"]

    # Only non-errored shares should be updated in DB
    assert state.update_share_readable.call_count == 2

    # Log message should report errors separately
    assert any("2 errors" in r.message for r in caplog.records)


# ---------- rescan + share filters ----------


def test_rescan_unreadable_respects_share_filter():
    """--rescan-unreadable + --share only tests matching shares."""
    cfg = make_cfg()
    cfg.targets.rescan_unreadable = True
    cfg.targets.share_filter = ["FINANCE*"]

    runner, state = _make_runner_with_state(cfg)
    state.load_unreadable_shares.return_value = [
        "//HOST1/FINANCE",
        "//HOST1/SECRET",
        "//HOST2/FINANCE_ARCHIVE",
    ]

    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.discovery.shares.ShareFinder") as finder_cls, \
         patch("snaffler.engine.runner.print_completion_stats"):
        finder = finder_cls.return_value
        finder.is_share_readable.return_value = True

        runner.execute()

    # Only FINANCE and FINANCE_ARCHIVE match the glob; SECRET is filtered out
    runner.file_pipeline.run.assert_called_once()
    paths = sorted(runner.file_pipeline.run.call_args[0][0])
    assert paths == ["//HOST1/FINANCE", "//HOST2/FINANCE_ARCHIVE"]


def test_rescan_unreadable_respects_exclude_share():
    """--rescan-unreadable + --exclude-share skips matching shares."""
    cfg = make_cfg()
    cfg.targets.rescan_unreadable = True
    cfg.targets.exclude_share = ["ADMIN$"]

    runner, state = _make_runner_with_state(cfg)
    state.load_unreadable_shares.return_value = [
        "//HOST1/DATA",
        "//HOST1/ADMIN$",
    ]

    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.discovery.shares.ShareFinder") as finder_cls, \
         patch("snaffler.engine.runner.print_completion_stats"):
        finder = finder_cls.return_value
        finder.is_share_readable.return_value = True

        runner.execute()

    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert paths == ["//HOST1/DATA"]


def test_rescan_unreadable_respects_exclusions():
    """--rescan-unreadable + --exclusions skips excluded hosts."""
    cfg = make_cfg()
    cfg.targets.rescan_unreadable = True
    cfg.targets.exclusions = ["DEADHOST"]

    runner, state = _make_runner_with_state(cfg)
    state.load_unreadable_shares.return_value = [
        "//DEADHOST/SHARE",
        "//GOODHOST/DATA",
    ]

    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.discovery.shares.ShareFinder") as finder_cls, \
         patch("snaffler.engine.runner.print_completion_stats"):
        finder = finder_cls.return_value
        finder.is_share_readable.return_value = True

        runner.execute()

    runner.file_pipeline.run.assert_called_once()
    paths = runner.file_pipeline.run.call_args[0][0]
    assert paths == ["//GOODHOST/DATA"]


def test_rescan_unreadable_all_filtered_out():
    """If all unreadable shares are filtered by --share/--exclusions, warn and exit."""
    cfg = make_cfg()
    cfg.targets.rescan_unreadable = True
    cfg.targets.exclusions = ["HOST1", "HOST2"]

    runner, state = _make_runner_with_state(cfg)
    state.load_unreadable_shares.return_value = [
        "//HOST1/SHARE",
        "//HOST2/DATA",
    ]

    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    runner.file_pipeline.run.assert_not_called()


# ---------- rescan + other target warnings ----------


def test_rescan_warns_about_ignored_computer(caplog):
    """--rescan-unreadable + --computer emits a warning."""
    import logging
    cfg = make_cfg()
    cfg.targets.rescan_unreadable = True
    cfg.targets.computer_targets = ["HOST1"]

    runner, state = _make_runner_with_state(cfg)
    state.load_unreadable_shares.return_value = []

    with patch("snaffler.engine.runner.print_completion_stats"), \
         caplog.at_level(logging.WARNING, logger="snaffler"):
        runner.execute()

    assert any("--rescan-unreadable takes priority" in r.message
               and "--computer" in r.message for r in caplog.records)


def test_rescan_warns_about_ignored_domain(caplog):
    """--rescan-unreadable + --domain emits a warning."""
    import logging
    cfg = make_cfg()
    cfg.targets.rescan_unreadable = True
    cfg.auth.domain = "CORP.LOCAL"

    runner, state = _make_runner_with_state(cfg)
    state.load_unreadable_shares.return_value = []

    with patch("snaffler.engine.runner.print_completion_stats"), \
         caplog.at_level(logging.WARNING, logger="snaffler"):
        runner.execute()

    assert any("--rescan-unreadable takes priority" in r.message
               and "--domain" in r.message for r in caplog.records)


def test_rescan_no_warning_when_standalone(caplog):
    """--rescan-unreadable alone does not emit the 'takes priority' warning."""
    import logging
    cfg = make_cfg()
    cfg.targets.rescan_unreadable = True

    runner, state = _make_runner_with_state(cfg)
    state.load_unreadable_shares.return_value = []

    with patch("snaffler.engine.runner.print_completion_stats"), \
         caplog.at_level(logging.WARNING, logger="snaffler"):
        runner.execute()

    assert not any("takes priority" in r.message for r in caplog.records
                    if hasattr(r, "message"))
