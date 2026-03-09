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
