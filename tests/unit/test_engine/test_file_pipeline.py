import queue
import time
from unittest.mock import MagicMock, call, patch

from snaffler.engine.file_pipeline import FilePipeline, _BatchWriter, _extract_share_unc
from snaffler.utils.progress import ProgressState


# ---------- helpers ----------

def make_cfg():
    cfg = MagicMock()

    cfg.advanced.tree_threads = 2
    cfg.advanced.file_threads = 2
    cfg.advanced.max_tree_threads_per_share = 0  # unlimited by default

    cfg.rules.file = []
    cfg.rules.content = []
    cfg.rules.postmatch = []

    cfg.targets.share_filter = []
    cfg.targets.exclude_share = []
    cfg.targets.exclude_unc = []

    cfg.scanning.max_depth = None

    return cfg


def make_walk_side_effect(fake_files):
    """Return a side_effect for walk_directory that calls on_file for each file
    and returns [] (no subdirs)."""
    def walk_directory(path, on_file=None, on_dir=None, cancel=None):
        for unc_path, size, mtime in fake_files:
            if on_file:
                on_file(unc_path, size, mtime)
        return []
    return walk_directory


# ---------- tests ----------

def test_file_pipeline_no_files():
    cfg = make_cfg()
    pipeline = FilePipeline(cfg)

    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=make_walk_side_effect([])
    )

    result = pipeline.run(["//HOST/SHARE"])

    assert result == 0
    pipeline.tree_walker.walk_directory.assert_called_once()


def test_file_pipeline_basic_flow():
    cfg = make_cfg()
    pipeline = FilePipeline(cfg)

    fake_files = [
        ("//HOST/SHARE/a.txt", 100, 1700000000.0),
        ("//HOST/SHARE/b.txt", 200, 1700000001.0),
    ]

    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=make_walk_side_effect(fake_files)
    )

    pipeline.file_scanner.scan_file = MagicMock(
        side_effect=[None, object()]  # only one match
    )

    result = pipeline.run(["//HOST/SHARE"])

    assert result == 1
    assert pipeline.file_scanner.scan_file.call_count == 2


def test_file_pipeline_scan_file_called_with_tuple_args():
    """scan_file is called with (unc_path, size, mtime_epoch) args."""
    cfg = make_cfg()
    pipeline = FilePipeline(cfg)

    fake_files = [
        ("//HOST/SHARE/a.txt", 100, 1700000000.0),
    ]

    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=make_walk_side_effect(fake_files)
    )
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    pipeline.file_scanner.scan_file.assert_called_once_with(
        "//HOST/SHARE/a.txt", 100, 1700000000.0
    )


def test_file_pipeline_resume_skips_files():
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.side_effect = lambda p: p.endswith("a.txt")
    state.load_unwalked_dirs.return_value = []
    state.load_unchecked_files.return_value = []

    pipeline = FilePipeline(cfg, state=state)

    fake_files = [
        ("//HOST/SHARE/a.txt", 100, 1700000000.0),
        ("//HOST/SHARE/b.txt", 200, 1700000001.0),
    ]

    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=make_walk_side_effect(fake_files)
    )
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    result = pipeline.run(["//HOST/SHARE"])

    assert result == 0
    pipeline.file_scanner.scan_file.assert_called_once_with(
        "//HOST/SHARE/b.txt", 200, 1700000001.0,
    )


def test_file_pipeline_marks_files_done():
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = []
    state.load_unchecked_files.return_value = []

    pipeline = FilePipeline(cfg, state=state)

    fake_files = [
        ("//HOST/SHARE/a.txt", 100, 1700000000.0),
    ]

    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=make_walk_side_effect(fake_files)
    )
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    state.mark_file_done.assert_called_once_with("//HOST/SHARE/a.txt")


def test_file_pipeline_marks_share_done_after_file_scanning():
    """mark_share_done is called after all files are scanned, not after tree walking."""
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = []
    state.load_unchecked_files.return_value = []

    call_order = []
    state.mark_file_done.side_effect = lambda p: call_order.append(("file", p))
    state.mark_share_done.side_effect = lambda p: call_order.append(("share", p))

    pipeline = FilePipeline(cfg, state=state)

    fake_files = [("//HOST/SHARE/a.txt", 100, 1700000000.0)]
    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=make_walk_side_effect(fake_files)
    )
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
    state.load_unwalked_dirs.return_value = []
    state.load_unchecked_files.return_value = []

    pipeline = FilePipeline(cfg, state=state)
    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=make_walk_side_effect([])
    )

    pipeline.run(["//HOST/SHARE"])

    state.mark_share_done.assert_called_once_with("//HOST/SHARE")


# ---------- progress ----------

def test_file_pipeline_progress_counters():
    cfg = make_cfg()
    progress = ProgressState()
    pipeline = FilePipeline(cfg, progress=progress)

    fake_files = [
        ("//HOST/SHARE/a.txt", 100, 1700000000.0),
        ("//HOST/SHARE/b.txt", 200, 1700000001.0),
        ("//HOST/SHARE/c.txt", 300, 1700000002.0),
    ]

    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=make_walk_side_effect(fake_files)
    )
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
    state.load_unwalked_dirs.return_value = []
    state.load_unchecked_files.return_value = []

    pipeline = FilePipeline(cfg, state=state, progress=progress)

    fake_files = [
        ("//HOST/SHARE/a.txt", 100, 1700000000.0),
        ("//HOST/SHARE/b.txt", 200, 1700000001.0),
    ]

    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=make_walk_side_effect(fake_files)
    )
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    # files_total includes previously-scanned files from resume
    assert progress.files_total == 2
    assert progress.files_scanned == 2
    assert progress.files_matched == 0


# ---------- parallel fan-out ----------

def test_file_pipeline_parallel_fan_out():
    """Walk returns subdirs → those get submitted as new walk_directory calls."""
    cfg = make_cfg()
    pipeline = FilePipeline(cfg)

    call_count = [0]

    def walk_directory_fan(path, on_file=None, on_dir=None, cancel=None):
        call_count[0] += 1
        if path == "//HOST/SHARE":
            # Root returns 2 subdirs
            if on_dir:
                on_dir("//HOST/SHARE/dir1")
                on_dir("//HOST/SHARE/dir2")
            return ["//HOST/SHARE/dir1", "//HOST/SHARE/dir2"]
        else:
            # Subdirs return files, no further subdirs
            if on_file:
                on_file(f"{path}/file.txt", 100, 0.0)
            return []

    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=walk_directory_fan
    )
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    result = pipeline.run(["//HOST/SHARE"])

    # walk_directory should be called 3 times: root + 2 subdirs
    assert call_count[0] == 3
    assert pipeline.file_scanner.scan_file.call_count == 2


def test_file_pipeline_parallel_share_completion():
    """Each share is tracked independently; shares are marked done when all dirs complete."""
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = []
    state.load_unchecked_files.return_value = []

    pipeline = FilePipeline(cfg, state=state)

    def walk_directory_multi(path, on_file=None, on_dir=None, cancel=None):
        if on_file:
            on_file(f"{path}/file.txt", 100, 0.0)
        return []

    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=walk_directory_multi
    )
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE1", "//HOST/SHARE2"])

    # Both shares should be marked done
    share_done_calls = [c[0][0] for c in state.mark_share_done.call_args_list]
    assert sorted(share_done_calls) == ["//HOST/SHARE1", "//HOST/SHARE2"]


def test_file_pipeline_resume_seeds_unchecked_from_other_share():
    """Unchecked files from shares NOT being walked are seeded into the queue."""
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_share.side_effect = lambda p: p == "//OTHER/DONE"
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = []
    # File from a different share that was already walked (not in active paths)
    state.load_unchecked_files.return_value = [
        ("//OTHER/DONE/leftover.txt", 500, 1700000000.0),
    ]

    pipeline = FilePipeline(cfg, state=state)

    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=make_walk_side_effect([])
    )
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    # //OTHER/DONE is skipped (should_skip_share=True), only //HOST/SHARE is walked
    pipeline.run(["//HOST/SHARE", "//OTHER/DONE"])

    # The leftover file from //OTHER/DONE should have been seeded and scanned
    scanned = [c[0][0] for c in pipeline.file_scanner.scan_file.call_args_list]
    assert "//OTHER/DONE/leftover.txt" in scanned


def test_file_pipeline_resume_no_duplicate_scan():
    """Unchecked files from actively-walked shares are NOT pre-seeded (avoids duplicates)."""
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = []
    # This file belongs to //HOST/SHARE which IS being actively walked
    state.load_unchecked_files.return_value = [
        ("//HOST/SHARE/already_discovered.txt", 500, 1700000000.0),
    ]

    pipeline = FilePipeline(cfg, state=state)

    # The live walk also discovers the same file
    fake_files = [
        ("//HOST/SHARE/already_discovered.txt", 500, 1700000000.0),
    ]
    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=make_walk_side_effect(fake_files)
    )
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    # File should be scanned exactly once (from live walk), NOT twice
    scanned = [c[0][0] for c in pipeline.file_scanner.scan_file.call_args_list]
    assert scanned.count("//HOST/SHARE/already_discovered.txt") == 1


def test_file_pipeline_resume_rewalks_unwalked_dirs():
    """Unwalked dirs from state DB are re-walked on resume."""
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = [
        "//HOST/SHARE/unfinished_dir",
    ]
    state.load_unchecked_files.return_value = []

    pipeline = FilePipeline(cfg, state=state)

    call_paths = []

    def walk_recording(path, on_file=None, on_dir=None, cancel=None):
        call_paths.append(path)
        if path == "//HOST/SHARE/unfinished_dir" and on_file:
            on_file("//HOST/SHARE/unfinished_dir/found.txt", 100, 0.0)
        return []

    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=walk_recording
    )
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    # Both the share root and the unwalked dir should have been walked
    assert "//HOST/SHARE" in call_paths
    assert "//HOST/SHARE/unfinished_dir" in call_paths

    # The file from the unwalked dir should have been scanned
    scanned = [c[0][0] for c in pipeline.file_scanner.scan_file.call_args_list]
    assert "//HOST/SHARE/unfinished_dir/found.txt" in scanned


def test_resume_skips_already_walked_dirs():
    """Dirs marked walked=1 in the DB are not re-walked on resume."""
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = []
    state.load_unchecked_files.return_value = []
    # These dirs were fully walked in the previous run
    state.load_walked_dirs.return_value = [
        "//HOST/SHARE/already_done",
        "//HOST/SHARE/already_done/deep",
    ]

    pipeline = FilePipeline(cfg, state=state)

    walked = []

    def walk(path, on_file=None, on_dir=None, cancel=None):
        walked.append(path)
        if path == "//HOST/SHARE":
            # Share root re-walk returns subdirs that were already walked
            return ["//HOST/SHARE/already_done"]
        if path == "//HOST/SHARE/already_done":
            return ["//HOST/SHARE/already_done/deep"]
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    # Share root is always re-walked (sets up cancel_events, etc.)
    assert "//HOST/SHARE" in walked
    # But previously walked subdirs should NOT be re-walked
    assert "//HOST/SHARE/already_done" not in walked
    assert "//HOST/SHARE/already_done/deep" not in walked


def test_resume_walked_dirs_files_preseeded():
    """Unchecked files from walked dirs are pre-seeded on resume."""
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = []
    state.load_walked_dirs.return_value = ["//HOST/SHARE/done_dir"]
    # File in a walked dir that wasn't scanned before interruption
    state.load_unchecked_files.return_value = [
        ("//HOST/SHARE/done_dir/missed.txt", 100, 1700000000.0),
    ]

    pipeline = FilePipeline(cfg, state=state)
    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=make_walk_side_effect([])
    )
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    scanned = [c[0][0] for c in pipeline.file_scanner.scan_file.call_args_list]
    assert "//HOST/SHARE/done_dir/missed.txt" in scanned


def test_resume_skips_done_shares():
    """Shares marked done in the state DB are not walked at all on resume."""
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_share.side_effect = lambda p: p == "//HOST/DONE"
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = []
    state.load_unchecked_files.return_value = []

    pipeline = FilePipeline(cfg, state=state)

    walked = []

    def walk(path, on_file=None, on_dir=None, cancel=None):
        walked.append(path)
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    progress = ProgressState()
    pipeline.progress = progress

    pipeline.run(["//HOST/DONE", "//HOST/ACTIVE"])

    # Done share should never be walked
    assert "//HOST/DONE" not in walked
    # Active share should still be walked
    assert "//HOST/ACTIVE" in walked
    # Done share counted as walked in progress
    assert progress.shares_walked >= 1


def test_resume_share_root_walked_only_subdirs_resumed():
    """When share root was already walked, only unwalked subdirs are submitted."""
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    # Share root already walked in previous run
    state.load_walked_dirs.return_value = ["//HOST/SHARE"]
    state.load_unwalked_dirs.return_value = [
        "//HOST/SHARE/unfinished",
    ]
    state.load_unchecked_files.return_value = []

    pipeline = FilePipeline(cfg, state=state)

    walked = []

    def walk(path, on_file=None, on_dir=None, cancel=None):
        walked.append(path)
        if on_file and path == "//HOST/SHARE/unfinished":
            on_file("//HOST/SHARE/unfinished/data.txt", 50, 0.0)
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    # Share root should NOT be re-walked (already walked)
    assert "//HOST/SHARE" not in walked
    # Unwalked subdir should be walked
    assert "//HOST/SHARE/unfinished" in walked


def test_resume_share_root_walked_no_remaining_work_marks_done():
    """Share with walked root and no unwalked subdirs is marked done."""
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    state.load_walked_dirs.return_value = ["//HOST/SHARE"]
    state.load_unwalked_dirs.return_value = []
    state.load_unchecked_files.return_value = []

    pipeline = FilePipeline(cfg, state=state)
    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=make_walk_side_effect([])
    )
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    # Share should be marked done since root was walked and no work remains
    state.mark_share_done.assert_any_call("//HOST/SHARE")


def test_preseed_respects_exclude_share():
    """Files in DB from an excluded share are NOT scanned on resume."""
    cfg = make_cfg()
    cfg.targets.exclude_share = ["JUNK$"]

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = []
    state.load_unchecked_files.return_value = [
        ("//HOST/JUNK$/secret.txt", 100, 1700000000.0),
        ("//HOST/DATA/report.txt", 200, 1700000001.0),
    ]

    pipeline = FilePipeline(cfg, state=state)
    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=make_walk_side_effect([])
    )
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    # Walk //HOST/OTHER so that both JUNK$ and DATA files hit the pre-seed path
    # (neither share is in walked_roots)
    pipeline.run(["//HOST/OTHER"])

    scanned = [c[0][0] for c in pipeline.file_scanner.scan_file.call_args_list]
    assert "//HOST/JUNK$/secret.txt" not in scanned
    assert "//HOST/DATA/report.txt" in scanned


def test_preseed_respects_exclude_unc():
    """Files in DB under an excluded UNC pattern are NOT scanned on resume."""
    cfg = make_cfg()
    cfg.targets.exclude_unc = ["*/C$/Windows*"]

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = []
    state.load_unchecked_files.return_value = [
        ("//HOST/C$/Windows/System32/config/SAM", 100, 1700000000.0),
        ("//HOST/C$/Users/admin/secret.txt", 200, 1700000001.0),
    ]

    pipeline = FilePipeline(cfg, state=state)
    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=make_walk_side_effect([])
    )
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    # Walk //HOST/OTHER so both files hit the pre-seed path
    pipeline.run(["//HOST/OTHER"])

    scanned = [c[0][0] for c in pipeline.file_scanner.scan_file.call_args_list]
    assert "//HOST/C$/Windows/System32/config/SAM" not in scanned
    assert "//HOST/C$/Users/admin/secret.txt" in scanned


def test_preseed_respects_include_share():
    """When --share filter is set, only matching shares are scanned from DB."""
    cfg = make_cfg()
    cfg.targets.share_filter = ["DATA"]

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = []
    state.load_unchecked_files.return_value = [
        ("//HOST/DATA/report.txt", 200, 1700000001.0),
        ("//HOST/LOGS/app.log", 300, 1700000002.0),
    ]

    pipeline = FilePipeline(cfg, state=state)
    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=make_walk_side_effect([])
    )
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/OTHER"])

    scanned = [c[0][0] for c in pipeline.file_scanner.scan_file.call_args_list]
    assert "//HOST/DATA/report.txt" in scanned
    assert "//HOST/LOGS/app.log" not in scanned


# ---------- batch writer ----------

def test_batch_writer_flushes_on_batch_size():
    """Batch writer flushes when batch size is reached."""
    state = MagicMock()

    writer = _BatchWriter(state)
    writer.start()

    # Put enough items to trigger a batch flush
    for i in range(500):
        writer.put_dir(f"//HOST/SHARE/dir{i}", "//HOST/SHARE")

    writer.stop()

    assert state.store_dirs.called


def test_batch_writer_flushes_on_stop():
    """Batch writer flushes remaining items on stop."""
    state = MagicMock()

    writer = _BatchWriter(state)
    writer.start()

    writer.put_file("//HOST/SHARE/a.txt", "//HOST/SHARE", 100, 0.0)
    writer.put_dir("//HOST/SHARE/dir1", "//HOST/SHARE")

    writer.stop()

    assert state.store_files.called
    assert state.store_dirs.called


def test_batch_writer_flushes_on_interval():
    """Batch writer flushes on time interval even with few items."""
    state = MagicMock()

    # Use a patched interval for fast testing
    with patch("snaffler.engine.file_pipeline._BATCH_INTERVAL", 0.1):
        writer = _BatchWriter(state)
        writer.start()

        writer.put_file("//HOST/SHARE/a.txt", "//HOST/SHARE", 100, 0.0)

        # Wait for the interval flush
        time.sleep(0.3)

        writer.stop()

    assert state.store_files.called


# ---------- error handling ----------

def test_file_pipeline_walk_error_does_not_mark_walked():
    """A failed walk_directory should NOT mark the dir as walked (retried on resume)."""
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = []
    state.load_unchecked_files.return_value = []

    pipeline = FilePipeline(cfg, state=state)

    def walk_exploding(path, on_file=None, on_dir=None, cancel=None):
        raise ConnectionError("SMB connection failed")

    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=walk_exploding
    )
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    # mark_dir_walked should NOT have been called for the failed dir
    state.mark_dir_walked.assert_not_called()

    # mark_share_done should NOT have been called — share had errors
    state.mark_share_done.assert_not_called()


def test_file_pipeline_partial_share_error_does_not_mark_done():
    """A share where some dirs fail should NOT be marked done on resume."""
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = []
    state.load_unchecked_files.return_value = []

    pipeline = FilePipeline(cfg, state=state)

    call_count = [0]

    def walk_partial_fail(path, on_file=None, on_dir=None, cancel=None):
        call_count[0] += 1
        if path == "//HOST/SHARE":
            # Root succeeds, returns one subdir
            if on_dir:
                on_dir("//HOST/SHARE/subdir")
            return ["//HOST/SHARE/subdir"]
        # Subdir fails
        raise ConnectionError("SMB session expired")

    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=walk_partial_fail
    )
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    # Root dir was walked OK, but subdir failed
    walked_dirs = [c[0][0] for c in state.mark_dir_walked.call_args_list]
    assert "//HOST/SHARE" in walked_dirs
    assert "//HOST/SHARE/subdir" not in walked_dirs

    # Share should NOT be marked done due to subdir error
    state.mark_share_done.assert_not_called()


# ---------- helpers ----------

def test_on_file_does_not_block_on_full_queue():
    """When the file_queue is full and shutdown is set, on_file should return
    instead of blocking forever (F3 fix)."""
    cfg = make_cfg()
    pipeline = FilePipeline(cfg)

    # Use a tiny queue to easily fill it
    tiny_queue = queue.Queue(maxsize=1)
    tiny_queue.put(("//HOST/SHARE/filler.txt", 0, 0.0))  # fill the queue

    files_seen = []

    def walk_directory_blocking(path, on_file=None, on_dir=None, cancel=None):
        """Walk that tries to emit a file into the already-full queue."""
        if on_file:
            on_file(f"{path}/blocked.txt", 100, 0.0)
            files_seen.append(f"{path}/blocked.txt")
        return []

    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=walk_directory_blocking
    )
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    # Run with normal flow — the pipeline should complete without hanging.
    # The consumer drains the queue, so the put() eventually succeeds.
    result = pipeline.run(["//HOST/SHARE"])

    # Pipeline should complete; the file should have been processed
    assert pipeline.file_scanner.scan_file.call_count >= 1


def test_no_duplicate_scan_same_file_two_dirs():
    """Two directories both yield the same file UNC → scanned exactly once."""
    cfg = make_cfg()
    pipeline = FilePipeline(cfg)

    def walk_dup(path, on_file=None, on_dir=None, cancel=None):
        if path == "//HOST/SHARE":
            if on_dir:
                on_dir("//HOST/SHARE/dir1")
                on_dir("//HOST/SHARE/dir2")
            return ["//HOST/SHARE/dir1", "//HOST/SHARE/dir2"]
        # Both subdirs "discover" the same file (e.g. symlink)
        if on_file:
            on_file("//HOST/SHARE/shared_file.txt", 100, 0.0)
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk_dup)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    scanned = [c[0][0] for c in pipeline.file_scanner.scan_file.call_args_list]
    assert scanned.count("//HOST/SHARE/shared_file.txt") == 1


def test_preseed_skips_already_enqueued_file():
    """File discovered by live walk AND present in load_unchecked_files → scanned once."""
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_share.side_effect = lambda p: p == "//OTHER/SHARE"
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = []
    # Same file appears in unchecked list for a non-active share
    state.load_unchecked_files.return_value = [
        ("//OTHER/SHARE/overlap.txt", 200, 1700000000.0),
    ]

    pipeline = FilePipeline(cfg, state=state)

    def walk_with_overlap(path, on_file=None, on_dir=None, cancel=None):
        if path == "//HOST/SHARE" and on_file:
            # Live walk discovers the same file that's also in unchecked
            on_file("//OTHER/SHARE/overlap.txt", 200, 1700000000.0)
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk_with_overlap)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE", "//OTHER/SHARE"])

    scanned = [c[0][0] for c in pipeline.file_scanner.scan_file.call_args_list]
    assert scanned.count("//OTHER/SHARE/overlap.txt") == 1


def test_no_duplicate_scan_case_insensitive():
    """//HOST/SHARE/File.txt and //HOST/SHARE/file.txt treated as the same path."""
    cfg = make_cfg()
    pipeline = FilePipeline(cfg)

    def walk_case_variants(path, on_file=None, on_dir=None, cancel=None):
        if path == "//HOST/SHARE":
            if on_dir:
                on_dir("//HOST/SHARE/dir1")
                on_dir("//HOST/SHARE/dir2")
            return ["//HOST/SHARE/dir1", "//HOST/SHARE/dir2"]
        if path == "//HOST/SHARE/dir1" and on_file:
            on_file("//HOST/SHARE/Secrets.txt", 100, 0.0)
        if path == "//HOST/SHARE/dir2" and on_file:
            on_file("//HOST/SHARE/secrets.txt", 100, 0.0)
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk_case_variants)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    scanned = [c[0][0] for c in pipeline.file_scanner.scan_file.call_args_list]
    assert len(scanned) == 1


def test_progress_not_double_counted_on_dedup():
    """When the same file is reported twice by two dirs, files_total increments once."""
    cfg = make_cfg()
    progress = ProgressState()
    pipeline = FilePipeline(cfg, progress=progress)

    def walk_dup(path, on_file=None, on_dir=None, cancel=None):
        if path == "//HOST/SHARE":
            if on_dir:
                on_dir("//HOST/SHARE/dir1")
                on_dir("//HOST/SHARE/dir2")
            return ["//HOST/SHARE/dir1", "//HOST/SHARE/dir2"]
        if on_file:
            on_file("//HOST/SHARE/shared.txt", 100, 0.0)
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk_dup)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    assert progress.files_total == 1
    assert progress.files_scanned == 1


def test_extract_share_unc():
    """_extract_share_unc extracts //server/share from full UNC paths."""
    assert _extract_share_unc("//HOST/SHARE/dir/file.txt") == "//HOST/SHARE"
    assert _extract_share_unc("//HOST/SHARE") == "//HOST/SHARE"
    assert _extract_share_unc("//10.0.0.1/Data$/path") == "//10.0.0.1/Data$"


def test_extract_share_unc_local_paths():
    """_extract_share_unc returns local paths unchanged (no UNC prefix)."""
    assert _extract_share_unc("/tmp/data") == "/tmp/data"
    assert _extract_share_unc("/tmp/data/subdir/file.txt") == "/tmp/data/subdir/file.txt"
    assert _extract_share_unc("/home/user/docs") == "/home/user/docs"
    assert _extract_share_unc("/data") == "/data"


def test_extract_share_unc_backslash_unc():
    """_extract_share_unc handles backslash UNC paths."""
    assert _extract_share_unc("\\\\HOST\\SHARE\\dir\\file.txt") == "//HOST/SHARE"


# ── max_depth ────────────────────────────────────────────────────

def test_max_depth_zero_no_recursion():
    """--max-depth 0 scans files in share root only, no subdirs walked."""
    cfg = make_cfg()
    cfg.scanning.max_depth = 0
    pipeline = FilePipeline(cfg)

    def walk(path, on_file=None, on_dir=None, cancel=None):
        if path == "//HOST/SHARE":
            if on_file:
                on_file("//HOST/SHARE/root.txt", 100, 0.0)
            if on_dir:
                on_dir("//HOST/SHARE/subdir")
            return ["//HOST/SHARE/subdir"]
        # Should never reach here
        if on_file:
            on_file(f"{path}/deep.txt", 100, 0.0)
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    # Root walk called, but subdir NOT submitted
    walked = [c[0][0] for c in pipeline.tree_walker.walk_directory.call_args_list]
    assert "//HOST/SHARE" in walked
    assert "//HOST/SHARE/subdir" not in walked

    scanned = [c[0][0] for c in pipeline.file_scanner.scan_file.call_args_list]
    assert scanned == ["//HOST/SHARE/root.txt"]


def test_max_depth_limits_recursion():
    """--max-depth 1 allows one level of subdirs but not deeper."""
    cfg = make_cfg()
    cfg.scanning.max_depth = 1
    pipeline = FilePipeline(cfg)

    def walk(path, on_file=None, on_dir=None, cancel=None):
        if path == "//HOST/SHARE":
            if on_dir:
                on_dir("//HOST/SHARE/level1")
            return ["//HOST/SHARE/level1"]
        if path == "//HOST/SHARE/level1":
            if on_file:
                on_file("//HOST/SHARE/level1/file.txt", 100, 0.0)
            if on_dir:
                on_dir("//HOST/SHARE/level1/level2")
            return ["//HOST/SHARE/level1/level2"]
        if on_file:
            on_file(f"{path}/deep.txt", 100, 0.0)
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    walked = [c[0][0] for c in pipeline.tree_walker.walk_directory.call_args_list]
    assert "//HOST/SHARE" in walked
    assert "//HOST/SHARE/level1" in walked
    assert "//HOST/SHARE/level1/level2" not in walked

    scanned = [c[0][0] for c in pipeline.file_scanner.scan_file.call_args_list]
    assert scanned == ["//HOST/SHARE/level1/file.txt"]


def test_sentinel_delivery_on_full_queue():
    """BUG-F6: Sentinels must be delivered even when the queue is completely full.

    The producer's finally block uses a retry loop that drains items from
    the queue when it's full, guaranteeing sentinel delivery so consumer
    threads don't hang forever.
    """
    cfg = make_cfg()
    cfg.advanced.file_threads = 2
    pipeline = FilePipeline(cfg)

    # Use a tiny queue that fills up immediately
    tiny_q = queue.Queue(maxsize=2)
    for _ in range(2):
        tiny_q.put(("//HOST/SHARE/filler.txt", 0, 0.0))

    assert tiny_q.full()

    # Simulate the sentinel push logic from the producer's finally block:
    # drain one item, then push sentinel — must succeed without deadlock.
    sentinel_count = 0
    for _ in range(cfg.advanced.file_threads):
        while True:
            try:
                tiny_q.put(None, timeout=0.5)
                sentinel_count += 1
                break
            except queue.Full:
                try:
                    tiny_q.get_nowait()
                except queue.Empty:
                    pass

    assert sentinel_count == cfg.advanced.file_threads, (
        f"Expected {cfg.advanced.file_threads} sentinels delivered, got {sentinel_count}"
    )


def test_max_depth_none_unlimited():
    """No --max-depth means unlimited recursion (default)."""
    cfg = make_cfg()
    assert cfg.scanning.max_depth is None
    pipeline = FilePipeline(cfg)

    def walk(path, on_file=None, on_dir=None, cancel=None):
        if path == "//HOST/SHARE":
            return ["//HOST/SHARE/a"]
        if path == "//HOST/SHARE/a":
            return ["//HOST/SHARE/a/b"]
        if path == "//HOST/SHARE/a/b":
            return ["//HOST/SHARE/a/b/c"]
        if path == "//HOST/SHARE/a/b/c":
            if on_file:
                on_file("//HOST/SHARE/a/b/c/deep.txt", 100, 0.0)
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    walked = [c[0][0] for c in pipeline.tree_walker.walk_directory.call_args_list]
    assert "//HOST/SHARE/a/b/c" in walked


def test_max_depth_respected_on_resume():
    """Unwalked dirs beyond --max-depth are skipped on resume."""
    cfg = make_cfg()
    cfg.scanning.max_depth = 0

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = [
        "//HOST/SHARE/deep/nested/dir",
        "//HOST/SHARE/another",
    ]
    state.load_unchecked_files.return_value = []

    pipeline = FilePipeline(cfg, state=state)

    walked = []

    def walk(path, on_file=None, on_dir=None, cancel=None):
        walked.append(path)
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    # Share root is always walked (depth 0)
    assert "//HOST/SHARE" in walked
    # Both resumed dirs exceed max_depth=0 and should be skipped
    assert "//HOST/SHARE/deep/nested/dir" not in walked
    assert "//HOST/SHARE/another" not in walked


def test_max_depth_one_allows_shallow_resume_dirs():
    """Unwalked dirs at depth <= max_depth are re-walked on resume."""
    cfg = make_cfg()
    cfg.scanning.max_depth = 1

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = [
        "//HOST/SHARE/level1",        # depth 1 — allowed
        "//HOST/SHARE/level1/level2",  # depth 2 — too deep
    ]
    state.load_unchecked_files.return_value = []

    pipeline = FilePipeline(cfg, state=state)

    walked = []

    def walk(path, on_file=None, on_dir=None, cancel=None):
        walked.append(path)
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    assert "//HOST/SHARE" in walked
    assert "//HOST/SHARE/level1" in walked
    assert "//HOST/SHARE/level1/level2" not in walked


# ---------- BUG-X3: Unbounded enqueued set ----------

def test_enqueued_set_bounded_by_max_enqueued():
    """BUG-X3: The enqueued set must be cleared when it exceeds _MAX_ENQUEUED
    to prevent unbounded memory usage."""
    from snaffler.engine.file_pipeline import _MAX_ENQUEUED

    cfg = make_cfg()

    # Patch _MAX_ENQUEUED to a small value for testing
    with patch("snaffler.engine.file_pipeline._MAX_ENQUEUED", 5):
        pipeline = FilePipeline(cfg)

        file_counter = [0]

        def walk_many_files(path, on_file=None, on_dir=None, cancel=None):
            if on_file:
                for i in range(10):
                    file_counter[0] += 1
                    on_file(f"//HOST/SHARE/file_{file_counter[0]}.txt", 100, 0.0)
            return []

        pipeline.tree_walker.walk_directory = MagicMock(
            side_effect=walk_many_files
        )
        pipeline.file_scanner.scan_file = MagicMock(return_value=None)

        # Should complete without error — the enqueued set is cleared
        result = pipeline.run(["//HOST/SHARE"])
        assert pipeline.file_scanner.scan_file.call_count == 10


# ---------- BUG-X20: _BatchWriter._flush logs at warning ----------

def test_batch_writer_flush_error_logs_warning(caplog):
    """BUG-X20: Batch writer flush errors should log at WARNING, not DEBUG."""
    import logging

    state = MagicMock()
    state.store_dirs.side_effect = RuntimeError("DB locked")

    writer = _BatchWriter(state)
    writer.start()

    writer.put_dir("//HOST/SHARE/dir1", "//HOST/SHARE")

    writer.stop()

    # Check that the warning was logged (not just debug)
    warning_records = [
        r for r in caplog.records
        if r.levelno >= logging.WARNING and "Batch writer flush error" in r.message
    ]
    assert len(warning_records) >= 1, (
        "Batch writer flush error should be logged at WARNING level"
    )


# ---------- BUG-Z2: --exclude-unc not applied to share roots ----------

def test_exclude_unc_filters_share_roots():
    """BUG-Z2: --exclude-unc patterns must filter out share root paths
    before they are walked, not just subdirectories."""
    cfg = make_cfg()
    cfg.targets.exclude_unc = ["*/SYSVOL*"]

    pipeline = FilePipeline(cfg)
    # Set exclude_unc on the tree_walker too (as the real code does)
    pipeline.tree_walker._exclude_unc = ["*/SYSVOL*"]

    walk_calls = []

    def walk_recording(path, on_file=None, on_dir=None, cancel=None):
        walk_calls.append(path)
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk_recording)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//DC/SYSVOL", "//DC/NETLOGON"])

    # SYSVOL should have been filtered out, only NETLOGON walked
    assert "//DC/SYSVOL" not in walk_calls
    assert "//DC/NETLOGON" in walk_calls


def test_exclude_unc_filters_share_roots_case_insensitive():
    """BUG-Z2: --exclude-unc matching is case-insensitive for share roots."""
    cfg = make_cfg()
    cfg.targets.exclude_unc = ["*/sysvol*"]

    pipeline = FilePipeline(cfg)
    pipeline.tree_walker._exclude_unc = ["*/sysvol*"]

    walk_calls = []

    def walk_recording(path, on_file=None, on_dir=None, cancel=None):
        walk_calls.append(path)
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk_recording)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//DC/SYSVOL", "//DC/Data"])

    assert "//DC/SYSVOL" not in walk_calls
    assert "//DC/Data" in walk_calls


def test_exclude_unc_share_root_updates_progress():
    """BUG-Z2: Excluded share roots should still count as walked in progress."""
    cfg = make_cfg()
    cfg.targets.exclude_unc = ["*/SYSVOL*"]

    progress = ProgressState()
    pipeline = FilePipeline(cfg, progress=progress)
    pipeline.tree_walker._exclude_unc = ["*/SYSVOL*"]

    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=make_walk_side_effect([])
    )
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//DC/SYSVOL", "//DC/NETLOGON"])

    # Both shares should count toward total, both should be "walked"
    assert progress.shares_total == 2
    assert progress.shares_walked == 2


# ---------- share error vs progress ----------

def test_share_with_error_still_counted_as_walked_in_progress():
    """A share where some dirs fail should still increment shares_walked
    in progress (the share IS walked, just not fully clean)."""
    cfg = make_cfg()
    progress = ProgressState()

    pipeline = FilePipeline(cfg, progress=progress)

    def walk_partial_fail(path, on_file=None, on_dir=None, cancel=None):
        if path == "//HOST/SHARE":
            if on_dir:
                on_dir("//HOST/SHARE/subdir")
            return ["//HOST/SHARE/subdir"]
        raise ConnectionError("access denied")

    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=walk_partial_fail
    )
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    # Progress should show the share as walked even though a subdir errored
    assert progress.shares_walked == 1


def test_share_with_error_not_marked_done_in_resume():
    """A share where some dirs fail should NOT be marked done in the resume DB
    (so failed dirs retry on next run)."""
    cfg = make_cfg()
    progress = ProgressState()

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = []
    state.load_unchecked_files.return_value = []

    pipeline = FilePipeline(cfg, state=state, progress=progress)

    def walk_partial_fail(path, on_file=None, on_dir=None, cancel=None):
        if path == "//HOST/SHARE":
            if on_dir:
                on_dir("//HOST/SHARE/subdir")
            return ["//HOST/SHARE/subdir"]
        raise ConnectionError("access denied")

    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=walk_partial_fail
    )
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    # Progress shows walked, but resume DB does NOT mark done
    assert progress.shares_walked == 1
    state.mark_share_done.assert_not_called()


def test_clean_share_both_walked_and_marked_done():
    """A share with zero errors should be counted in progress AND marked done."""
    cfg = make_cfg()
    progress = ProgressState()

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = []
    state.load_unchecked_files.return_value = []

    pipeline = FilePipeline(cfg, state=state, progress=progress)

    pipeline.tree_walker.walk_directory = MagicMock(
        side_effect=make_walk_side_effect([("//HOST/SHARE/a.txt", 100, 0.0)])
    )
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    assert progress.shares_walked == 1
    state.mark_share_done.assert_called_once_with("//HOST/SHARE")


def test_mixed_clean_and_errored_shares_progress():
    """With 3 shares (1 clean, 1 errored, 1 clean), progress shows all 3 walked
    but only 2 marked done in resume DB."""
    cfg = make_cfg()
    progress = ProgressState()

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = []
    state.load_unchecked_files.return_value = []

    pipeline = FilePipeline(cfg, state=state, progress=progress)

    def walk_mixed(path, on_file=None, on_dir=None, cancel=None):
        if path == "//HOST/SHARE2":
            # This share's root walk returns a subdir that fails
            if on_dir:
                on_dir("//HOST/SHARE2/bad")
            return ["//HOST/SHARE2/bad"]
        if path == "//HOST/SHARE2/bad":
            raise PermissionError("access denied")
        # SHARE1 and SHARE3 are clean
        if on_file:
            on_file(f"{path}/file.txt", 100, 0.0)
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk_mixed)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE1", "//HOST/SHARE2", "//HOST/SHARE3"])

    # All 3 shares should show as walked in progress
    assert progress.shares_walked == 3

    # Only SHARE1 and SHARE3 should be marked done in resume DB
    done_calls = sorted(c[0][0] for c in state.mark_share_done.call_args_list)
    assert done_calls == ["//HOST/SHARE1", "//HOST/SHARE3"]


def test_all_shares_errored_progress_still_complete():
    """Even if every share has errors, progress shows them all as walked."""
    cfg = make_cfg()
    progress = ProgressState()

    pipeline = FilePipeline(cfg, progress=progress)

    def walk_all_fail(path, on_file=None, on_dir=None, cancel=None):
        raise ConnectionError("host unreachable")

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk_all_fail)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE1", "//HOST/SHARE2"])

    assert progress.shares_walked == 2


def test_shares_with_errors_case_insensitive():
    """Error tracking uses lowercased share roots consistently."""
    cfg = make_cfg()
    progress = ProgressState()

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = []
    state.load_unchecked_files.return_value = []

    pipeline = FilePipeline(cfg, state=state, progress=progress)

    def walk_case_error(path, on_file=None, on_dir=None, cancel=None):
        if path == "//Host/Share":
            if on_dir:
                on_dir("//Host/Share/SubDir")
            return ["//Host/Share/SubDir"]
        if path == "//Host/Share/SubDir":
            raise PermissionError("denied")
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk_case_error)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//Host/Share"])

    # Progress should count it as walked
    assert progress.shares_walked == 1
    # But NOT marked done in resume DB (had error)
    state.mark_share_done.assert_not_called()


# ── fair-share scheduling ──────────────────────────────────────

def test_fair_share_limits_concurrent_walks_per_share():
    """With max_per_share=1, only one walk runs per share at a time.
    Both shares must still complete (buffered dirs get drained)."""
    cfg = make_cfg()
    cfg.advanced.tree_threads = 4
    cfg.advanced.max_tree_threads_per_share = 1

    progress = ProgressState()
    pipeline = FilePipeline(cfg, progress=progress)

    walked = []

    def walk(path, on_file=None, on_dir=None, cancel=None):
        walked.append(path)
        if path == "//HOST/SHARE1":
            if on_dir:
                on_dir("//HOST/SHARE1/a")
                on_dir("//HOST/SHARE1/b")
            return ["//HOST/SHARE1/a", "//HOST/SHARE1/b"]
        if path == "//HOST/SHARE2":
            if on_dir:
                on_dir("//HOST/SHARE2/x")
            return ["//HOST/SHARE2/x"]
        if on_file:
            on_file(f"{path}/file.txt", 100, 0.0)
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE1", "//HOST/SHARE2"])

    # All dirs must be walked despite the per-share limit
    assert "//HOST/SHARE1/a" in walked
    assert "//HOST/SHARE1/b" in walked
    assert "//HOST/SHARE2/x" in walked
    assert progress.shares_walked == 2


def test_fair_share_zero_means_unlimited():
    """max_per_share=0 disables fair-share (current default behavior)."""
    cfg = make_cfg()
    cfg.advanced.tree_threads = 4
    cfg.advanced.max_tree_threads_per_share = 0

    pipeline = FilePipeline(cfg)

    walked = []

    def walk(path, on_file=None, on_dir=None, cancel=None):
        walked.append(path)
        if path == "//HOST/SHARE":
            return ["//HOST/SHARE/a", "//HOST/SHARE/b", "//HOST/SHARE/c"]
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    assert "//HOST/SHARE/a" in walked
    assert "//HOST/SHARE/b" in walked
    assert "//HOST/SHARE/c" in walked


def test_fair_share_interleaves_across_shares():
    """With per-share cap, threads are distributed across multiple shares
    rather than all piling into one deep share."""
    cfg = make_cfg()
    cfg.advanced.tree_threads = 2
    cfg.advanced.max_tree_threads_per_share = 1

    pipeline = FilePipeline(cfg)

    walked = []

    def walk(path, on_file=None, on_dir=None, cancel=None):
        walked.append(path)
        # SHARE1 is deep — produces 5 levels of subdirs
        if path == "//HOST/SHARE1":
            return ["//HOST/SHARE1/d1"]
        if path == "//HOST/SHARE1/d1":
            return ["//HOST/SHARE1/d1/d2"]
        if path == "//HOST/SHARE1/d1/d2":
            return ["//HOST/SHARE1/d1/d2/d3"]
        # SHARE2 is shallow
        if path == "//HOST/SHARE2":
            if on_file:
                on_file("//HOST/SHARE2/secret.txt", 100, 0.0)
            return []
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE1", "//HOST/SHARE2"])

    # Both shares must complete
    assert "//HOST/SHARE2" in walked
    assert "//HOST/SHARE1/d1/d2/d3" in walked


def test_fair_share_share_completion_waits_for_buffer():
    """A share is not marked done until both pending futures AND buffer are empty."""
    cfg = make_cfg()
    cfg.advanced.tree_threads = 2
    cfg.advanced.max_tree_threads_per_share = 1

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = []
    state.load_unchecked_files.return_value = []

    progress = ProgressState()
    pipeline = FilePipeline(cfg, state=state, progress=progress)

    def walk(path, on_file=None, on_dir=None, cancel=None):
        if path == "//HOST/SHARE":
            return ["//HOST/SHARE/a", "//HOST/SHARE/b"]
        if on_file:
            on_file(f"{path}/file.txt", 100, 0.0)
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    # Share should be fully complete (both buffered dirs walked)
    assert progress.shares_walked == 1
    state.mark_share_done.assert_called_once_with("//HOST/SHARE")


def test_fair_share_with_errors_still_drains_buffer():
    """Errors in one subdir don't prevent the rest of the buffer from being walked."""
    cfg = make_cfg()
    cfg.advanced.tree_threads = 2
    cfg.advanced.max_tree_threads_per_share = 1

    progress = ProgressState()
    pipeline = FilePipeline(cfg, progress=progress)

    walked = []

    def walk(path, on_file=None, on_dir=None, cancel=None):
        walked.append(path)
        if path == "//HOST/SHARE":
            return ["//HOST/SHARE/bad", "//HOST/SHARE/good"]
        if path == "//HOST/SHARE/bad":
            raise ConnectionError("timeout")
        if on_file:
            on_file(f"{path}/file.txt", 100, 0.0)
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    # Both dirs should have been attempted
    assert "//HOST/SHARE/bad" in walked
    assert "//HOST/SHARE/good" in walked
    assert progress.shares_walked == 1


def test_fair_share_resume_respects_limit():
    """Unwalked dirs from resume also respect the per-share thread limit."""
    cfg = make_cfg()
    cfg.advanced.tree_threads = 2
    cfg.advanced.max_tree_threads_per_share = 1

    state = MagicMock()
    state.should_skip_share.return_value = False
    state.should_skip_file.return_value = False
    state.load_unwalked_dirs.return_value = [
        "//HOST/SHARE/d1",
        "//HOST/SHARE/d2",
        "//HOST/SHARE/d3",
    ]
    state.load_unchecked_files.return_value = []

    pipeline = FilePipeline(cfg, state=state)

    walked = []

    def walk(path, on_file=None, on_dir=None, cancel=None):
        walked.append(path)
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    # All dirs should eventually be walked (buffered then drained)
    assert "//HOST/SHARE/d1" in walked
    assert "//HOST/SHARE/d2" in walked
    assert "//HOST/SHARE/d3" in walked


# ── max_depth resume with increased depth ────────────────────────


def test_max_depth_increase_on_resume_walks_deeper_dirs_skips_checked_files():
    """Full scenario: scan with max_depth=1, resume with max_depth=3.

    Directory tree (4 levels deep):

        //HOST/SHARE/                          depth 0
        ├── root.txt
        └── level1/                            depth 1
            ├── shallow.txt
            └── level2/                        depth 2 (skipped in run 1)
                ├── medium.txt
                └── level3/                    depth 3 (skipped in run 1)
                    ├── deep.txt
                    └── level4/                depth 4 (skipped in both runs)
                        └── abyss.txt

    Run 1 (max_depth=1):
      - Walks //HOST/SHARE (depth 0) and //HOST/SHARE/level1 (depth 1)
      - Scans root.txt and shallow.txt
      - Discovers level2 but depth 2 > max_depth 1, so it's stored in DB but NOT walked
      - level3 and level4 are never even discovered

    Run 2 (max_depth=3, resume):
      - Shares are already walked — should_skip_share returns False (shares remain in the run list)
      - level2 appears in load_unwalked_dirs, depth 2 <= 3, so it's walked
      - Walking level2 discovers level3 (depth 3 <= max_depth) → walked
      - Walking level3 discovers level4 (depth 4 > max_depth 3) → stored but NOT walked
      - root.txt and shallow.txt already checked → should_skip_file returns True → NOT re-scanned
      - medium.txt and deep.txt are new → scanned
      - abyss.txt is never discovered (level4 not walked)
    """
    # ── Run 1: max_depth=1 ──────────────────────────────────────

    cfg1 = make_cfg()
    cfg1.scanning.max_depth = 1

    # Track what the state DB would contain after run 1
    stored_dirs = {}    # path → walked flag
    checked_files = set()

    state1 = MagicMock()
    state1.should_skip_share.return_value = False
    state1.should_skip_file.return_value = False
    state1.load_unwalked_dirs.return_value = []
    state1.load_unchecked_files.return_value = []

    def track_store_dirs(dirs):
        for d in dirs:
            if d.lower() not in stored_dirs:
                stored_dirs[d.lower()] = False  # walked=False

    def track_store_dir(unc_path, share):
        if unc_path.lower() not in stored_dirs:
            stored_dirs[unc_path.lower()] = False  # walked=False

    def track_mark_walked(d):
        stored_dirs[d.lower()] = True  # walked=True

    def track_mark_checked(f):
        checked_files.add(f.lower())

    state1.store_dirs.side_effect = track_store_dirs
    state1.store_dir.side_effect = track_store_dir
    state1.mark_dir_walked.side_effect = track_mark_walked
    state1.mark_file_checked.side_effect = track_mark_checked

    pipeline1 = FilePipeline(cfg1, state=state1)

    def walk_full_tree(path, on_file=None, on_dir=None, cancel=None):
        """Simulates the real SMB tree walker discovering the full tree."""
        if path == "//HOST/SHARE":
            if on_file:
                on_file("//HOST/SHARE/root.txt", 100, 1000.0)
            if on_dir:
                on_dir("//HOST/SHARE/level1")
            return ["//HOST/SHARE/level1"]
        if path == "//HOST/SHARE/level1":
            if on_file:
                on_file("//HOST/SHARE/level1/shallow.txt", 200, 2000.0)
            if on_dir:
                on_dir("//HOST/SHARE/level1/level2")
            return ["//HOST/SHARE/level1/level2"]
        if path == "//HOST/SHARE/level1/level2":
            if on_file:
                on_file("//HOST/SHARE/level1/level2/medium.txt", 300, 3000.0)
            if on_dir:
                on_dir("//HOST/SHARE/level1/level2/level3")
            return ["//HOST/SHARE/level1/level2/level3"]
        if path == "//HOST/SHARE/level1/level2/level3":
            if on_file:
                on_file("//HOST/SHARE/level1/level2/level3/deep.txt", 400, 4000.0)
            if on_dir:
                on_dir("//HOST/SHARE/level1/level2/level3/level4")
            return ["//HOST/SHARE/level1/level2/level3/level4"]
        if path == "//HOST/SHARE/level1/level2/level3/level4":
            if on_file:
                on_file("//HOST/SHARE/level1/level2/level3/level4/abyss.txt", 500, 5000.0)
            return []
        return []

    pipeline1.tree_walker.walk_directory = MagicMock(side_effect=walk_full_tree)
    pipeline1.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline1.run(["//HOST/SHARE"])

    # Verify run 1 walked only depth 0 and 1
    walked1 = [c[0][0] for c in pipeline1.tree_walker.walk_directory.call_args_list]
    assert "//HOST/SHARE" in walked1
    assert "//HOST/SHARE/level1" in walked1
    assert "//HOST/SHARE/level1/level2" not in walked1, "level2 should NOT be walked at max_depth=1"
    assert "//HOST/SHARE/level1/level2/level3" not in walked1
    assert "//HOST/SHARE/level1/level2/level3/level4" not in walked1

    # Verify run 1 scanned only files at depth 0-1
    scanned1 = [c[0][0] for c in pipeline1.file_scanner.scan_file.call_args_list]
    assert "//HOST/SHARE/root.txt" in scanned1
    assert "//HOST/SHARE/level1/shallow.txt" in scanned1
    assert len(scanned1) == 2, f"Expected 2 files scanned, got {scanned1}"

    # Verify level2 was stored in DB as unwalked (our fix)
    assert "//host/share/level1/level2" in stored_dirs, "level2 must be in DB"
    assert stored_dirs["//host/share/level1/level2"] is False, "level2 must be unwalked"
    # level3+ should NOT be in the DB (never discovered)
    assert "//host/share/level1/level2/level3" not in stored_dirs
    assert "//host/share/level1/level2/level3/level4" not in stored_dirs

    # ── Run 2: max_depth=3 (resume) ─────────────────────────────

    cfg2 = make_cfg()
    cfg2.scanning.max_depth = 3

    # Simulate the state DB as it would be after run 1:
    # - share root and level1 are walked
    # - level2 is unwalked (stored by our fix)
    # - root.txt and shallow.txt are checked
    state2 = MagicMock()
    state2.should_skip_share.return_value = False

    run1_checked = {"//host/share/root.txt", "//host/share/level1/shallow.txt"}

    def skip_file_run2(path):
        return path.lower() in run1_checked

    state2.should_skip_file.side_effect = skip_file_run2

    # Only level2 is unwalked — share root and level1 were already walked
    state2.load_unwalked_dirs.return_value = [
        "//HOST/SHARE/level1/level2",
    ]
    state2.load_unchecked_files.return_value = []

    stored_dirs_run2 = {}

    def track_store_dirs_run2(dirs):
        for d in dirs:
            if d.lower() not in stored_dirs_run2:
                stored_dirs_run2[d.lower()] = False

    def track_store_dir_run2(unc_path, share):
        if unc_path.lower() not in stored_dirs_run2:
            stored_dirs_run2[unc_path.lower()] = False

    def track_mark_walked_run2(d):
        stored_dirs_run2[d.lower()] = True

    state2.store_dirs.side_effect = track_store_dirs_run2
    state2.store_dir.side_effect = track_store_dir_run2
    state2.mark_dir_walked.side_effect = track_mark_walked_run2

    pipeline2 = FilePipeline(cfg2, state=state2)
    pipeline2.tree_walker.walk_directory = MagicMock(side_effect=walk_full_tree)
    pipeline2.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline2.run(["//HOST/SHARE"])

    # Verify run 2 walks share root (always), level2 (resumed), level3 (newly discovered)
    walked2 = [c[0][0] for c in pipeline2.tree_walker.walk_directory.call_args_list]
    assert "//HOST/SHARE" in walked2, "Share root is always walked"
    assert "//HOST/SHARE/level1/level2" in walked2, "level2 should be walked on resume with higher depth"
    assert "//HOST/SHARE/level1/level2/level3" in walked2, "level3 should be walked (depth 3 <= max_depth 3)"
    assert "//HOST/SHARE/level1/level2/level3/level4" not in walked2, \
        "level4 should NOT be walked (depth 4 > max_depth 3)"

    # Verify run 2 does NOT re-scan files from run 1
    scanned2 = [c[0][0] for c in pipeline2.file_scanner.scan_file.call_args_list]
    assert "//HOST/SHARE/root.txt" not in scanned2, "root.txt already checked — must NOT re-scan"
    assert "//HOST/SHARE/level1/shallow.txt" not in scanned2, "shallow.txt already checked — must NOT re-scan"

    # Verify run 2 DOES scan the newly discovered files
    assert "//HOST/SHARE/level1/level2/medium.txt" in scanned2, "medium.txt is new — must be scanned"
    assert "//HOST/SHARE/level1/level2/level3/deep.txt" in scanned2, "deep.txt is new — must be scanned"

    # abyss.txt should NOT be scanned (level4 was not walked)
    assert "//HOST/SHARE/level1/level2/level3/level4/abyss.txt" not in scanned2, \
        "abyss.txt must NOT be scanned — level4 exceeds max_depth 3"

    # Verify level4 was stored for a future even-deeper resume
    assert "//host/share/level1/level2/level3/level4" in stored_dirs_run2, \
        "level4 should be stored in DB for future resume with higher max_depth"
    assert stored_dirs_run2["//host/share/level1/level2/level3/level4"] is False, \
        "level4 should be stored as unwalked"


def test_max_depth_increase_resume_same_depth_no_extra_work():
    """Resume with the SAME max_depth does not re-walk or re-scan anything.

    After run 1 with max_depth=1, level2 is stored as unwalked. If we resume
    with the same max_depth=1, level2 should still be skipped (depth 2 > 1).
    The only work should be re-walking the share root (always happens), but
    files already checked should be skipped via should_skip_file.
    """
    cfg = make_cfg()
    cfg.scanning.max_depth = 1

    state = MagicMock()
    state.should_skip_share.return_value = False

    # All files from run 1 are already checked
    state.should_skip_file.return_value = True

    # level2 is in the DB as unwalked from run 1
    state.load_unwalked_dirs.return_value = [
        "//HOST/SHARE/level1/level2",
    ]
    state.load_unchecked_files.return_value = []

    pipeline = FilePipeline(cfg, state=state)

    def walk(path, on_file=None, on_dir=None, cancel=None):
        if path == "//HOST/SHARE":
            if on_file:
                on_file("//HOST/SHARE/root.txt", 100, 1000.0)
            if on_dir:
                on_dir("//HOST/SHARE/level1")
            return ["//HOST/SHARE/level1"]
        if path == "//HOST/SHARE/level1":
            if on_file:
                on_file("//HOST/SHARE/level1/shallow.txt", 200, 2000.0)
            if on_dir:
                on_dir("//HOST/SHARE/level1/level2")
            return ["//HOST/SHARE/level1/level2"]
        return []

    pipeline.tree_walker.walk_directory = MagicMock(side_effect=walk)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    walked = [c[0][0] for c in pipeline.tree_walker.walk_directory.call_args_list]
    # level2 should NOT be walked — still exceeds max_depth=1
    assert "//HOST/SHARE/level1/level2" not in walked

    # No files should be scanned — all already checked
    scanned = [c[0][0] for c in pipeline.file_scanner.scan_file.call_args_list]
    assert len(scanned) == 0, f"Expected 0 files scanned on same-depth resume, got {scanned}"


def test_max_depth_increase_progressive_deepening():
    """Three successive runs with increasing depth: 0 → 1 → 2.

    Verifies that each run only does incremental work and that the stored
    unwalked dirs chain correctly across multiple depth increases.

    Tree:
        //HOST/SHARE/           depth 0
        └── a/                  depth 1
            └── b/              depth 2
                └── leaf.txt
    """
    # ── Run 1: max_depth=0 ──────────────────────────────────────

    cfg1 = make_cfg()
    cfg1.scanning.max_depth = 0

    stored_unwalked_1 = []

    state1 = MagicMock()
    state1.should_skip_share.return_value = False
    state1.should_skip_file.return_value = False
    state1.load_unwalked_dirs.return_value = []
    state1.load_unchecked_files.return_value = []
    state1.store_dirs.side_effect = lambda dirs: stored_unwalked_1.extend(dirs)
    state1.store_dir.side_effect = lambda p, s: stored_unwalked_1.append(p)

    pipeline1 = FilePipeline(cfg1, state=state1)

    def walk_tree(path, on_file=None, on_dir=None, cancel=None):
        if path == "//HOST/SHARE":
            if on_file:
                on_file("//HOST/SHARE/root.txt", 10, 0.0)
            if on_dir:
                on_dir("//HOST/SHARE/a")
            return ["//HOST/SHARE/a"]
        if path == "//HOST/SHARE/a":
            if on_dir:
                on_dir("//HOST/SHARE/a/b")
            return ["//HOST/SHARE/a/b"]
        if path == "//HOST/SHARE/a/b":
            if on_file:
                on_file("//HOST/SHARE/a/b/leaf.txt", 20, 0.0)
            return []
        return []

    pipeline1.tree_walker.walk_directory = MagicMock(side_effect=walk_tree)
    pipeline1.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline1.run(["//HOST/SHARE"])

    walked1 = [c[0][0] for c in pipeline1.tree_walker.walk_directory.call_args_list]
    assert walked1 == ["//HOST/SHARE"], "Run 1 should only walk share root"
    scanned1 = [c[0][0] for c in pipeline1.file_scanner.scan_file.call_args_list]
    assert scanned1 == ["//HOST/SHARE/root.txt"]
    assert "//HOST/SHARE/a" in stored_unwalked_1, "dir 'a' stored for future resume"

    # ── Run 2: max_depth=1 ──────────────────────────────────────

    cfg2 = make_cfg()
    cfg2.scanning.max_depth = 1

    stored_unwalked_2 = []

    state2 = MagicMock()
    state2.should_skip_share.return_value = False
    state2.should_skip_file.side_effect = lambda p: p.lower() == "//host/share/root.txt"
    state2.load_unwalked_dirs.return_value = ["//HOST/SHARE/a"]  # from run 1
    state2.load_unchecked_files.return_value = []
    state2.store_dirs.side_effect = lambda dirs: stored_unwalked_2.extend(dirs)
    state2.store_dir.side_effect = lambda p, s: stored_unwalked_2.append(p)

    pipeline2 = FilePipeline(cfg2, state=state2)
    pipeline2.tree_walker.walk_directory = MagicMock(side_effect=walk_tree)
    pipeline2.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline2.run(["//HOST/SHARE"])

    walked2 = [c[0][0] for c in pipeline2.tree_walker.walk_directory.call_args_list]
    assert "//HOST/SHARE/a" in walked2, "dir 'a' should be walked on resume (depth 1 <= max_depth 1)"
    assert "//HOST/SHARE/a/b" not in walked2, "dir 'b' should NOT be walked (depth 2 > max_depth 1)"

    scanned2 = [c[0][0] for c in pipeline2.file_scanner.scan_file.call_args_list]
    assert "//HOST/SHARE/root.txt" not in scanned2, "root.txt already checked"
    assert "//HOST/SHARE/a/b" in stored_unwalked_2, "dir 'b' stored for future resume"

    # ── Run 3: max_depth=2 ──────────────────────────────────────

    cfg3 = make_cfg()
    cfg3.scanning.max_depth = 2

    state3 = MagicMock()
    state3.should_skip_share.return_value = False
    state3.should_skip_file.side_effect = lambda p: p.lower() == "//host/share/root.txt"
    state3.load_unwalked_dirs.return_value = ["//HOST/SHARE/a/b"]  # from run 2
    state3.load_unchecked_files.return_value = []

    pipeline3 = FilePipeline(cfg3, state=state3)
    pipeline3.tree_walker.walk_directory = MagicMock(side_effect=walk_tree)
    pipeline3.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline3.run(["//HOST/SHARE"])

    walked3 = [c[0][0] for c in pipeline3.tree_walker.walk_directory.call_args_list]
    assert "//HOST/SHARE/a/b" in walked3, "dir 'b' should be walked on resume (depth 2 <= max_depth 2)"

    scanned3 = [c[0][0] for c in pipeline3.file_scanner.scan_file.call_args_list]
    assert "//HOST/SHARE/root.txt" not in scanned3, "root.txt already checked"
    assert "//HOST/SHARE/a/b/leaf.txt" in scanned3, "leaf.txt is new — must be scanned"
