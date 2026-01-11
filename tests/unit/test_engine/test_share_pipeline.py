from unittest.mock import MagicMock

import pytest

from snaffler.engine.share_pipeline import SharePipeline


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
