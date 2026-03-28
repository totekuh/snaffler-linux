from unittest.mock import MagicMock

import pytest

from snaffler.engine.share_pipeline import SharePipeline
from snaffler.utils.progress import ProgressState


# ---------- helpers ----------

def make_cfg():
    from tests.conftest import make_engine_cfg
    return make_engine_cfg()


def _share(readable=True):
    """Create a mock share with a readable attribute."""
    s = MagicMock()
    s.readable = readable
    return s


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
            ("//HOST1/SHARE1", _share()),
            ("//HOST1/SHARE2", _share()),
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
            ("//HOST1/SHARE", _share()),
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
        return [("//GOOD/SHARE", _share())]

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
            [("//H1/S1", _share()), ("//H1/S2", _share())],
            [("//H2/S1", _share())],
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
        return [("//GOOD/SHARE", _share())]

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
            [("//H1/S1", _share())],
            [("//H2/S1", _share()), ("//H2/S2", _share())],
        ]
    )

    pipeline.run(["H1", "H2"])

    # Each computer marked done individually
    assert state.mark_computer_done.call_count == 2
    state.mark_computer_done.assert_any_call("H1")
    state.mark_computer_done.assert_any_call("H2")

    # Shares stored incrementally per-computer
    assert state.store_shares.call_count == 2


def test_share_pipeline_transport_error_does_not_mark_done():
    """Transport errors should NOT mark the computer done — retry on resume."""
    cfg = make_cfg()
    state = MagicMock()
    pipeline = SharePipeline(cfg, state=state)

    def side_effect(host):
        if host == "BAD":
            raise RuntimeError("boom")
        return [("//GOOD/SHARE", _share())]

    pipeline.share_finder.get_computer_shares = MagicMock(side_effect=side_effect)

    pipeline.run(["BAD", "GOOD"])

    # Only GOOD is marked done — BAD had a transport error
    assert state.mark_computer_done.call_count == 1
    state.mark_computer_done.assert_called_once_with("GOOD")


# ---------- readable / unreadable ----------

def test_share_pipeline_stores_readable_and_unreadable():
    """All shares (readable + unreadable) are stored to state with readable flag."""
    cfg = make_cfg()
    state = MagicMock()
    pipeline = SharePipeline(cfg, state=state)

    pipeline.share_finder.get_computer_shares = MagicMock(
        return_value=[
            ("//H1/PUBLIC", _share(readable=True)),
            ("//H1/SECRET", _share(readable=False)),
        ]
    )

    result = pipeline.run(["H1"])

    # Only readable shares returned for walking
    assert result == ["//H1/PUBLIC"]

    # Both stored to state with readable flag
    state.store_shares.assert_called_once()
    stored = state.store_shares.call_args[0][0]
    assert ("//H1/PUBLIC", True) in stored
    assert ("//H1/SECRET", False) in stored


def test_share_pipeline_only_counts_readable_in_progress():
    """Progress.shares_found only counts readable shares."""
    cfg = make_cfg()
    progress = ProgressState()
    pipeline = SharePipeline(cfg, progress=progress)

    pipeline.share_finder.get_computer_shares = MagicMock(
        return_value=[
            ("//H1/PUBLIC", _share(readable=True)),
            ("//H1/SECRET", _share(readable=False)),
            ("//H1/ALSO_SECRET", _share(readable=False)),
        ]
    )

    pipeline.run(["H1"])

    assert progress.shares_found == 1


def test_share_pipeline_all_unreadable():
    """When all shares are unreadable, returns empty list."""
    cfg = make_cfg()
    pipeline = SharePipeline(cfg)

    pipeline.share_finder.get_computer_shares = MagicMock(
        return_value=[
            ("//H1/SECRET", _share(readable=False)),
        ]
    )

    result = pipeline.run(["H1"])

    assert result == []


def test_share_pipeline_unreadable_not_walked():
    """Normal scan: unreadable shares stored but never returned for walking."""
    cfg = make_cfg()
    state = MagicMock()
    progress = ProgressState()
    pipeline = SharePipeline(cfg, state=state, progress=progress)

    pipeline.share_finder.get_computer_shares = MagicMock(
        side_effect=[
            [
                ("//H1/PUBLIC", _share(readable=True)),
                ("//H1/DENIED1", _share(readable=False)),
                ("//H1/DENIED2", _share(readable=False)),
            ],
            [
                ("//H2/OPEN", _share(readable=True)),
                ("//H2/LOCKED", _share(readable=False)),
            ],
        ]
    )

    result = pipeline.run(["H1", "H2"])

    # Only readable shares in the return list
    assert sorted(result) == ["//H1/PUBLIC", "//H2/OPEN"]

    # All 5 shares stored to DB (readable + unreadable)
    all_stored = []
    for c in state.store_shares.call_args_list:
        all_stored.extend(c[0][0])
    assert len(all_stored) == 5
    stored_readable = [unc for unc, r in all_stored if r]
    stored_unreadable = [unc for unc, r in all_stored if not r]
    assert sorted(stored_readable) == ["//H1/PUBLIC", "//H2/OPEN"]
    assert sorted(stored_unreadable) == ["//H1/DENIED1", "//H1/DENIED2", "//H2/LOCKED"]

    # Progress only counts readable
    assert progress.shares_found == 2


def test_share_pipeline_shares_only_with_unreadable():
    """--shares-only: returns empty list but still stores all shares including unreadable."""
    cfg = make_cfg()
    cfg.targets.shares_only = True
    state = MagicMock()
    pipeline = SharePipeline(cfg, state=state)

    pipeline.share_finder.get_computer_shares = MagicMock(
        return_value=[
            ("//H1/PUBLIC", _share(readable=True)),
            ("//H1/SECRET", _share(readable=False)),
        ]
    )

    result = pipeline.run(["H1"])

    # shares_only returns empty (no walking)
    assert result == []

    # But both shares should be stored in DB for future --rescan-unreadable
    state.store_shares.assert_called_once()
    stored = state.store_shares.call_args[0][0]
    assert len(stored) == 2
