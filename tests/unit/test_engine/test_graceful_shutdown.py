"""Tests for graceful shutdown: DB close, stats printing, future cancellation."""

import pytest
from unittest.mock import MagicMock, patch, call

from snaffler.engine.runner import SnafflerRunner


# ---------- helpers ----------

def make_cfg():
    cfg = MagicMock()
    cfg.resume.enabled = False
    cfg.resume.state_db = None
    cfg.targets.unc_targets = []
    cfg.targets.computer_targets = []
    cfg.targets.shares_only = False
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
    from snaffler.engine.file_pipeline import FilePipeline

    cfg = make_cfg()
    pipeline = FilePipeline(cfg=cfg)

    # Make tree walker raise on first call
    pipeline.tree_walker.walk_tree = MagicMock(side_effect=KeyboardInterrupt)

    with pytest.raises(KeyboardInterrupt):
        pipeline.run(["//HOST/SHARE"])


def test_share_pipeline_cancels_futures_on_interrupt():
    """Share pipeline cancels pending futures on KeyboardInterrupt."""
    from snaffler.engine.share_pipeline import SharePipeline

    cfg = make_cfg()
    pipeline = SharePipeline(cfg=cfg)

    # Make share finder raise on first call
    pipeline.share_finder.get_computer_shares = MagicMock(
        side_effect=KeyboardInterrupt
    )

    with pytest.raises(KeyboardInterrupt):
        pipeline.run(["HOST1"])


# ---------- runner: no state (state=None) ----------

def test_runner_no_state_no_crash_on_interrupt():
    """Interrupt without resume enabled doesn't crash on state cleanup."""
    cfg = make_cfg()
    cfg.targets.unc_targets = ["//HOST/SHARE"]

    runner = SnafflerRunner(cfg)
    assert runner.state is None
    runner.file_pipeline.run = MagicMock(side_effect=KeyboardInterrupt)

    with patch("snaffler.engine.runner.print_completion_stats"):
        with pytest.raises(KeyboardInterrupt):
            runner.execute()
