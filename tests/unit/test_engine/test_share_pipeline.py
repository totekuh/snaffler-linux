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

    pipeline.run(["BAD", "GOOD"])

    # Both computers counted as done (even the failed one)
    assert progress.computers_total == 2
    assert progress.computers_done == 2
    assert progress.shares_found == 1
