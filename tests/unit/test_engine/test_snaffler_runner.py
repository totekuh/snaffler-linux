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
    cfg.targets.shares_only = False
    cfg.targets.share_filter = []
    cfg.targets.exclude_share = []

    # ---------- auth ----------
    cfg.auth.domain = None

    # ---------- advanced ----------
    cfg.advanced.share_threads = 2
    cfg.advanced.tree_threads = 2
    cfg.advanced.file_threads = 2
    cfg.advanced.dns_threads = 4

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
    runner.state = state
    runner.share_pipeline.state = state
    runner.file_pipeline.state = state
    return runner, state


# ---------- tests ----------

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
