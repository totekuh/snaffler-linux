"""Tests for graceful shutdown: DB close, stats printing, future cancellation."""

import pytest
from unittest.mock import MagicMock, patch, call

from snaffler.engine.runner import SnafflerRunner
from snaffler.utils.logger import set_finding_store


@pytest.fixture(autouse=True)
def _reset_finding_store():
    yield
    set_finding_store(None)


# ---------- helpers ----------

def make_cfg():
    cfg = MagicMock()
    cfg.state.state_db = ":memory:"
    cfg.targets.unc_targets = []
    cfg.targets.computer_targets = []
    cfg.targets.shares_only = False
    cfg.targets.share_filter = []
    cfg.targets.exclude_share = []
    cfg.auth.domain = None
    cfg.advanced.share_threads = 2
    cfg.advanced.tree_threads = 2
    cfg.advanced.file_threads = 2
    return cfg


# ---------- runner: state close ----------

def test_runner_closes_state_on_success():
    """state.close() is called on normal completion."""
    cfg = make_cfg()
    cfg.targets.unc_targets = ["//HOST/SHARE"]

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock()
    runner.state = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    runner.state.close.assert_called_once()


def test_runner_closes_state_on_interrupt():
    """state.close() is called even when interrupted."""
    cfg = make_cfg()
    cfg.targets.unc_targets = ["//HOST/SHARE"]

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock(side_effect=KeyboardInterrupt)
    runner.state = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        with pytest.raises(KeyboardInterrupt):
            runner.execute()

    runner.state.close.assert_called_once()


def test_runner_closes_state_on_error():
    """state.close() is called even when pipeline throws."""
    cfg = make_cfg()
    cfg.targets.unc_targets = ["//HOST/SHARE"]

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock(side_effect=RuntimeError("boom"))
    runner.state = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        with pytest.raises(RuntimeError):
            runner.execute()

    runner.state.close.assert_called_once()


# ---------- runner: stats printing ----------

def test_runner_prints_stats_on_success():
    """print_completion_stats is called on normal completion."""
    cfg = make_cfg()
    cfg.targets.unc_targets = ["//HOST/SHARE"]

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats") as mock_stats:
        runner.execute()

    mock_stats.assert_called_once()


def test_runner_prints_stats_on_interrupt():
    """print_completion_stats is called even when interrupted."""
    cfg = make_cfg()
    cfg.targets.unc_targets = ["//HOST/SHARE"]

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock(side_effect=KeyboardInterrupt)

    with patch("snaffler.engine.runner.print_completion_stats") as mock_stats:
        with pytest.raises(KeyboardInterrupt):
            runner.execute()

    mock_stats.assert_called_once()


def test_runner_stats_before_state_close():
    """Stats are printed before state DB is closed."""
    cfg = make_cfg()
    cfg.targets.unc_targets = ["//HOST/SHARE"]

    runner = SnafflerRunner(cfg)
    runner.file_pipeline.run = MagicMock(side_effect=KeyboardInterrupt)
    runner.state = MagicMock()

    call_order = []
    with patch("snaffler.engine.runner.print_completion_stats",
               side_effect=lambda **kw: call_order.append("stats")):
        runner.state.close = MagicMock(
            side_effect=lambda: call_order.append("close")
        )
        with pytest.raises(KeyboardInterrupt):
            runner.execute()

    assert call_order == ["stats", "close"]


# ---------- pipeline: future cancellation ----------

def test_file_pipeline_cancels_futures_on_interrupt():
    """File pipeline cancels pending futures on KeyboardInterrupt."""
    from concurrent.futures import ThreadPoolExecutor as RealTPE
    from snaffler.engine.file_pipeline import FilePipeline

    cfg = make_cfg()
    pipeline = FilePipeline(cfg=cfg)

    # Make tree walker raise on first call
    pipeline.tree_walker.walk_directory = MagicMock(side_effect=KeyboardInterrupt)

    # Wrap real ThreadPoolExecutor to spy on shutdown calls
    shutdown_calls = []

    class SpyTPE(RealTPE):
        def shutdown(self, *args, **kwargs):
            shutdown_calls.append(kwargs)
            return super().shutdown(*args, **kwargs)

    with patch("snaffler.engine.file_pipeline.ThreadPoolExecutor", SpyTPE):
        with pytest.raises(KeyboardInterrupt):
            pipeline.run(["//HOST/SHARE"])

    # Verify at least one shutdown had cancel_futures=True
    assert any(c.get("cancel_futures") is True for c in shutdown_calls), (
        f"Expected shutdown(cancel_futures=True), got: {shutdown_calls}"
    )


def test_share_pipeline_cancels_futures_on_interrupt():
    """Share pipeline cancels pending futures on KeyboardInterrupt."""
    from concurrent.futures import ThreadPoolExecutor as RealTPE
    from snaffler.engine.share_pipeline import SharePipeline

    cfg = make_cfg()
    pipeline = SharePipeline(cfg=cfg)

    # Make share finder raise on first call
    pipeline.share_finder.get_computer_shares = MagicMock(
        side_effect=KeyboardInterrupt
    )

    # Wrap real ThreadPoolExecutor to spy on shutdown calls
    shutdown_calls = []

    class SpyTPE(RealTPE):
        def shutdown(self, *args, **kwargs):
            shutdown_calls.append(kwargs)
            return super().shutdown(*args, **kwargs)

    with patch("snaffler.engine.share_pipeline.ThreadPoolExecutor", SpyTPE):
        with pytest.raises(KeyboardInterrupt):
            pipeline.run(["HOST1"])

    # Verify shutdown was called with cancel_futures=True
    assert any(c.get("cancel_futures") is True for c in shutdown_calls), (
        f"Expected shutdown(cancel_futures=True), got: {shutdown_calls}"
    )


# ---------- runner: state always present ----------

def test_runner_state_always_created():
    """State DB is always created, even without explicit --state flag."""
    cfg = make_cfg()
    cfg.targets.unc_targets = ["//HOST/SHARE"]

    runner = SnafflerRunner(cfg)
    assert runner.state is not None
    runner.file_pipeline.run = MagicMock(side_effect=KeyboardInterrupt)

    with patch("snaffler.engine.runner.print_completion_stats"):
        with pytest.raises(KeyboardInterrupt):
            runner.execute()
