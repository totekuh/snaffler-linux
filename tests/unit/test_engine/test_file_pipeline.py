from unittest.mock import MagicMock

from snaffler.engine.file_pipeline import FilePipeline
from snaffler.utils.progress import ProgressState


# ---------- helpers ----------

def make_cfg():
    cfg = MagicMock()

    cfg.advanced.tree_threads = 2
    cfg.advanced.file_threads = 2

    cfg.rules.file = []
    cfg.rules.content = []
    cfg.rules.postmatch = []

    return cfg


# ---------- tests ----------

def test_file_pipeline_no_files():
    cfg = make_cfg()
    pipeline = FilePipeline(cfg)

    pipeline.tree_walker.walk_tree = MagicMock(return_value=[])

    result = pipeline.run(["//HOST/SHARE"])

    assert result == 0
    pipeline.tree_walker.walk_tree.assert_called_once()


def test_file_pipeline_basic_flow():
    cfg = make_cfg()
    pipeline = FilePipeline(cfg)

    fake_files = [
        ("//HOST/SHARE/a.txt", object()),
        ("//HOST/SHARE/b.txt", object()),
    ]

    pipeline.tree_walker.walk_tree = MagicMock(return_value=fake_files)

    pipeline.file_scanner.scan_file = MagicMock(
        side_effect=[None, object()]  # only one match
    )

    result = pipeline.run(["//HOST/SHARE"])

    assert result == 1
    assert pipeline.file_scanner.scan_file.call_count == 2


def test_file_pipeline_resume_skips_files():
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.side_effect = lambda p: p.endswith("a.txt")

    pipeline = FilePipeline(cfg, state=state)

    fake_files = [
        ("//HOST/SHARE/a.txt", object()),
        ("//HOST/SHARE/b.txt", object()),
    ]

    pipeline.tree_walker.walk_tree = MagicMock(return_value=fake_files)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    result = pipeline.run(["//HOST/SHARE"])

    assert result == 0
    pipeline.file_scanner.scan_file.assert_called_once_with(
        "//HOST/SHARE/b.txt",
        fake_files[1][1],
    )


def test_file_pipeline_marks_files_done():
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False

    pipeline = FilePipeline(cfg, state=state)

    fake_files = [
        ("//HOST/SHARE/a.txt", object()),
    ]

    pipeline.tree_walker.walk_tree = MagicMock(return_value=fake_files)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    state.mark_file_done.assert_called_once_with("//HOST/SHARE/a.txt")


def test_file_pipeline_marks_share_done_after_file_scanning():
    """mark_share_done is called after all files are scanned, not after tree walking."""
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False

    call_order = []
    state.mark_file_done.side_effect = lambda p: call_order.append(("file", p))
    state.mark_share_done.side_effect = lambda p: call_order.append(("share", p))

    pipeline = FilePipeline(cfg, state=state)

    fake_files = [("//HOST/SHARE/a.txt", object())]
    pipeline.tree_walker.walk_tree = MagicMock(return_value=fake_files)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    # Files must be marked before shares
    file_indices = [i for i, (t, _) in enumerate(call_order) if t == "file"]
    share_indices = [i for i, (t, _) in enumerate(call_order) if t == "share"]
    assert file_indices, "mark_file_done should have been called"
    assert share_indices, "mark_share_done should have been called"
    assert max(file_indices) < min(share_indices), \
        "shares should be marked done only after all files are scanned"


def test_file_pipeline_marks_share_done_on_empty_walk():
    """Shares with no files are still marked done (tree walk succeeded)."""
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_share.return_value = False

    pipeline = FilePipeline(cfg, state=state)
    pipeline.tree_walker.walk_tree = MagicMock(return_value=[])

    pipeline.run(["//HOST/SHARE"])

    state.mark_share_done.assert_called_once_with("//HOST/SHARE")


# ---------- progress ----------

def test_file_pipeline_progress_counters():
    cfg = make_cfg()
    progress = ProgressState()
    pipeline = FilePipeline(cfg, progress=progress)

    fake_files = [
        ("//HOST/SHARE/a.txt", object()),
        ("//HOST/SHARE/b.txt", object()),
        ("//HOST/SHARE/c.txt", object()),
    ]

    pipeline.tree_walker.walk_tree = MagicMock(return_value=fake_files)
    pipeline.file_scanner.scan_file = MagicMock(
        side_effect=[None, object(), object()]  # 2 matches
    )

    pipeline.run(["//HOST/SHARE"])

    assert progress.files_total == 3
    assert progress.files_scanned == 3
    assert progress.files_matched == 2


def test_file_pipeline_progress_with_resume():
    cfg = make_cfg()
    progress = ProgressState()

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.side_effect = lambda p: p.endswith("a.txt")

    pipeline = FilePipeline(cfg, state=state, progress=progress)

    fake_files = [
        ("//HOST/SHARE/a.txt", object()),
        ("//HOST/SHARE/b.txt", object()),
    ]

    pipeline.tree_walker.walk_tree = MagicMock(return_value=fake_files)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    # files_total includes previously-scanned files from resume
    assert progress.files_total == 2
    assert progress.files_scanned == 2
    assert progress.files_matched == 0
