from unittest.mock import MagicMock

from snaffler.engine.file_pipeline import FilePipeline


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

    pipeline.tree_walker.walk_tree = MagicMock(return_value=([], []))

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
    fake_walked_dirs = ["//HOST/SHARE/"]

    pipeline.tree_walker.walk_tree = MagicMock(return_value=(fake_files, fake_walked_dirs))

    pipeline.file_scanner.scan_file = MagicMock(
        side_effect=[None, object()]  # only one match
    )

    result = pipeline.run(["//HOST/SHARE"])

    assert result == 1
    assert pipeline.file_scanner.scan_file.call_count == 2


def test_file_pipeline_resume_skips_files():
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_file.side_effect = lambda p: p.endswith("a.txt")

    pipeline = FilePipeline(cfg, state=state)

    fake_files = [
        ("//HOST/SHARE/a.txt", object()),
        ("//HOST/SHARE/b.txt", object()),
    ]
    fake_walked_dirs = ["//HOST/SHARE/"]

    pipeline.tree_walker.walk_tree = MagicMock(return_value=(fake_files, fake_walked_dirs))
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
    state.should_skip_file.return_value = False

    pipeline = FilePipeline(cfg, state=state)

    fake_files = [
        ("//HOST/SHARE/a.txt", object()),
    ]
    fake_walked_dirs = ["//HOST/SHARE/"]

    pipeline.tree_walker.walk_tree = MagicMock(return_value=(fake_files, fake_walked_dirs))
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    state.mark_file_done.assert_called_once_with("//HOST/SHARE/a.txt")


# ---------- directory marking tests ----------

def test_dirs_marked_after_all_files_scanned():
    """Directories should only be marked done AFTER all file scanning completes."""
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_file.return_value = False

    pipeline = FilePipeline(cfg, state=state)

    fake_files = [
        ("//HOST/SHARE/dir1/a.txt", object()),
        ("//HOST/SHARE/dir1/b.txt", object()),
        ("//HOST/SHARE/dir2/c.txt", object()),
    ]
    fake_walked_dirs = [
        "//HOST/SHARE/",
        "//HOST/SHARE/dir1/",
        "//HOST/SHARE/dir2/",
    ]

    pipeline.tree_walker.walk_tree = MagicMock(return_value=(fake_files, fake_walked_dirs))
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    # All 3 files should be marked
    assert state.mark_file_done.call_count == 3

    # All 3 directories should be marked
    assert state.mark_dir_done.call_count == 3
    state.mark_dir_done.assert_any_call("//HOST/SHARE/")
    state.mark_dir_done.assert_any_call("//HOST/SHARE/dir1/")
    state.mark_dir_done.assert_any_call("//HOST/SHARE/dir2/")


def test_dirs_not_marked_when_scanner_raises_for_all_files():
    """If all file scans raise exceptions, dirs should still be marked
    (scanning was attempted, just failed)."""
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_file.return_value = False

    pipeline = FilePipeline(cfg, state=state)

    fake_files = [
        ("//HOST/SHARE/a.txt", object()),
        ("//HOST/SHARE/b.txt", object()),
    ]
    fake_walked_dirs = ["//HOST/SHARE/"]

    pipeline.tree_walker.walk_tree = MagicMock(return_value=(fake_files, fake_walked_dirs))
    # All scans raise exceptions
    pipeline.file_scanner.scan_file = MagicMock(side_effect=Exception("scan failed"))

    pipeline.run(["//HOST/SHARE"])

    # Files should NOT be marked (exceptions occurred before mark_file_done)
    assert state.mark_file_done.call_count == 0

    # But directories SHOULD still be marked (we completed the scanning phase)
    state.mark_dir_done.assert_called_once_with("//HOST/SHARE/")


def test_partial_scan_marks_only_successful_files():
    """When some scans succeed and some fail, only successful files are marked."""
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_file.return_value = False

    pipeline = FilePipeline(cfg, state=state)

    fake_files = [
        ("//HOST/SHARE/good1.txt", object()),
        ("//HOST/SHARE/bad.txt", object()),
        ("//HOST/SHARE/good2.txt", object()),
    ]
    fake_walked_dirs = ["//HOST/SHARE/"]

    pipeline.tree_walker.walk_tree = MagicMock(return_value=(fake_files, fake_walked_dirs))

    def scan_side_effect(path, info):
        if "bad" in path:
            raise Exception("scan failed")
        return None

    pipeline.file_scanner.scan_file = MagicMock(side_effect=scan_side_effect)

    pipeline.run(["//HOST/SHARE"])

    # Only 2 successful files marked (not the bad one)
    assert state.mark_file_done.call_count == 2

    # Directory still marked (scanning phase completed)
    state.mark_dir_done.assert_called_once_with("//HOST/SHARE/")


def test_many_files_interrupted_scenario():
    """Simulate interrupt scenario: many files, only some scanned.

    This tests the core bug fix: if we have 100 files and scanning is
    interrupted after 50, the directory should NOT be marked as done
    (in the old buggy code it would be marked during tree walking).

    With the fix, directories are only marked after ALL scanning completes,
    so an interrupt means dirs won't be marked.
    """
    cfg = make_cfg()

    state = MagicMock()
    state.should_skip_file.return_value = False

    pipeline = FilePipeline(cfg, state=state)

    # Create 100 files
    fake_files = [
        (f"//HOST/SHARE/dir/file{i}.txt", object())
        for i in range(100)
    ]
    fake_walked_dirs = ["//HOST/SHARE/", "//HOST/SHARE/dir/"]

    pipeline.tree_walker.walk_tree = MagicMock(return_value=(fake_files, fake_walked_dirs))

    # Track how many files were scanned
    scanned_count = [0]

    def scan_with_interrupt(path, info):
        scanned_count[0] += 1
        # Simulate interrupt after 50 files by raising KeyboardInterrupt
        if scanned_count[0] == 50:
            raise KeyboardInterrupt("simulated interrupt")
        return None

    pipeline.file_scanner.scan_file = MagicMock(side_effect=scan_with_interrupt)

    # The run should propagate the KeyboardInterrupt (or handle it)
    # In real code, KeyboardInterrupt would stop the executor
    # For this test, we catch it to verify the state
    try:
        pipeline.run(["//HOST/SHARE"])
    except KeyboardInterrupt:
        pass

    # Key assertion: directories should NOT be marked
    # because we didn't complete the scanning phase
    # (In the old buggy code, dirs would already be marked from tree walking)
    state.mark_dir_done.assert_not_called()


def test_no_state_no_marking():
    """Without state tracking, no marking should occur."""
    cfg = make_cfg()

    pipeline = FilePipeline(cfg, state=None)

    fake_files = [("//HOST/SHARE/a.txt", object())]
    fake_walked_dirs = ["//HOST/SHARE/"]

    pipeline.tree_walker.walk_tree = MagicMock(return_value=(fake_files, fake_walked_dirs))
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    # No state = no marking (nothing to assert on, just shouldn't crash)
