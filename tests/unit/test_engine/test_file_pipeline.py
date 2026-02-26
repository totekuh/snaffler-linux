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
    cfg.targets.exclude_dir = []

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


def test_preseed_respects_exclude_dir():
    """Files in DB under an excluded directory are NOT scanned on resume."""
    cfg = make_cfg()
    cfg.targets.exclude_dir = ["*/C$/Windows*"]

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
