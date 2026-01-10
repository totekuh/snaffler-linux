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
    state.should_skip_file.return_value = False

    pipeline = FilePipeline(cfg, state=state)

    fake_files = [
        ("//HOST/SHARE/a.txt", object()),
    ]

    pipeline.tree_walker.walk_tree = MagicMock(return_value=fake_files)
    pipeline.file_scanner.scan_file = MagicMock(return_value=None)

    pipeline.run(["//HOST/SHARE"])

    state.mark_file_done.assert_called_once_with("//HOST/SHARE/a.txt")
