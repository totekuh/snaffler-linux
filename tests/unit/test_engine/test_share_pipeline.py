from unittest.mock import MagicMock

import pytest

from snaffler.engine.share_pipeline import SharePipeline
from snaffler.utils.progress import ProgressState


# ---------- helpers ----------

def make_cfg():
    cfg = MagicMock()

    cfg.advanced.share_threads = 2
    cfg.targets.shares_only = False

    return cfg


# ---------- tests ----------

def test_share_pipeline_no_shares():
    cfg = make_cfg()
    pipeline = SharePipeline(cfg)

    pipeline.share_finder.get_computer_shares = MagicMock(return_value=[])

    result = pipeline.run(["HOST1"])

    assert result == []


def test_share_pipeline_basic():
    cfg = make_cfg()
    pipeline = SharePipeline(cfg)

    pipeline.share_finder.get_computer_shares = MagicMock(
        return_value=[
            ("//HOST1/SHARE1", object()),
            ("//HOST1/SHARE2", object()),
        ]
    )

    result = pipeline.run(["HOST1"])

    assert result == [
        "//HOST1/SHARE1",
        "//HOST1/SHARE2",
    ]


def test_share_pipeline_shares_only():
    cfg = make_cfg()
    cfg.targets.shares_only = True

    pipeline = SharePipeline(cfg)

    pipeline.share_finder.get_computer_shares = MagicMock(
        return_value=[
            ("//HOST1/SHARE", object()),
        ]
    )

    result = pipeline.run(["HOST1"])

    assert result == []


def test_share_pipeline_partial_failure():
    cfg = make_cfg()
    pipeline = SharePipeline(cfg)

    def side_effect(host):
        if host == "BAD":
            raise RuntimeError("boom")
        return [("//GOOD/SHARE", object())]

    pipeline.share_finder.get_computer_shares = MagicMock(
        side_effect=side_effect
    )

    result = pipeline.run(["BAD", "GOOD"])

    assert result == ["//GOOD/SHARE"]


def test_share_pipeline_invalid_threads():
    cfg = make_cfg()
    cfg.advanced.share_threads = 0

    with pytest.raises(ValueError):
        SharePipeline(cfg)


# ---------- progress ----------

def test_share_pipeline_progress_counters():
    cfg = make_cfg()
    progress = ProgressState()
    pipeline = SharePipeline(cfg, progress=progress)

    pipeline.share_finder.get_computer_shares = MagicMock(
        side_effect=[
            [("//H1/S1", object()), ("//H1/S2", object())],
            [("//H2/S1", object())],
        ]
    )

    # Runner sets computers_total before calling SharePipeline.run()
    progress.computers_total = 2
    pipeline.run(["H1", "H2"])

    assert progress.computers_total == 2
    assert progress.computers_done == 2
    assert progress.shares_found == 3


def test_share_pipeline_progress_counts_failures():
    cfg = make_cfg()
    progress = ProgressState()
    pipeline = SharePipeline(cfg, progress=progress)

    def side_effect(host):
        if host == "BAD":
            raise RuntimeError("boom")
        return [("//GOOD/SHARE", object())]

    pipeline.share_finder.get_computer_shares = MagicMock(side_effect=side_effect)

    # Runner sets computers_total before calling SharePipeline.run()
    progress.computers_total = 2
    pipeline.run(["BAD", "GOOD"])

    # Both computers counted as done (even the failed one)
    assert progress.computers_total == 2
    assert progress.computers_done == 2
    assert progress.shares_found == 1


# ---------- resume: per-computer marking ----------

def test_share_pipeline_marks_computers_in_state():
    """SharePipeline marks each computer done in state DB incrementally."""
    cfg = make_cfg()
    state = MagicMock()
    pipeline = SharePipeline(cfg, state=state)

    pipeline.share_finder.get_computer_shares = MagicMock(
        side_effect=[
            [("//H1/S1", object())],
            [("//H2/S1", object()), ("//H2/S2", object())],
        ]
    )

    pipeline.run(["H1", "H2"])

    # Each computer marked done individually
    assert state.mark_computer_done.call_count == 2
    state.mark_computer_done.assert_any_call("H1")
    state.mark_computer_done.assert_any_call("H2")

    # Shares stored incrementally per-computer
    assert state.store_shares.call_count == 2


def test_share_pipeline_marks_failed_computer_in_state():
    """Failed computers are marked done (no DNS, access denied, etc.) — no point retrying."""
    cfg = make_cfg()
    state = MagicMock()
    pipeline = SharePipeline(cfg, state=state)

    def side_effect(host):
        if host == "BAD":
            raise RuntimeError("boom")
        return [("//GOOD/SHARE", object())]

    pipeline.share_finder.get_computer_shares = MagicMock(side_effect=side_effect)

    pipeline.run(["BAD", "GOOD"])

    # Both marked done — errors are permanent, only KeyboardInterrupt skips marking
    assert state.mark_computer_done.call_count == 2
    state.mark_computer_done.assert_any_call("BAD")
    state.mark_computer_done.assert_any_call("GOOD")
