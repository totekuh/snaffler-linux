import threading
from unittest.mock import MagicMock, patch

from snaffler.engine.runner import SnafflerRunner, _deduplicate_paths


# ---------- helpers ----------

def make_cfg():
    cfg = MagicMock()

    # ---------- resume ----------
    cfg.resume.enabled = False
    cfg.resume.state_db = None

    # ---------- targets ----------
    cfg.targets.unc_targets = []
    cfg.targets.computer_targets = []
    cfg.targets.shares_only = False

    # ---------- auth ----------
    cfg.auth.domain = None

    # ---------- advanced (ВАЖНО!) ----------
    cfg.advanced.share_threads = 2
    cfg.advanced.tree_threads = 2
    cfg.advanced.file_threads = 2

    return cfg



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

    with patch("snaffler.engine.runner.print_completion_stats"):
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
    ) as domain_cls, patch(
        "snaffler.engine.runner.print_completion_stats"
    ):
        domain = domain_cls.return_value
        domain.run.return_value = ["HOST1"]

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
    ) as domain_cls, patch(
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
    ) as domain_cls, patch(
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
