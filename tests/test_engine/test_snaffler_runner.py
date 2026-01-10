from unittest.mock import MagicMock, patch

from snaffler.engine.runner import SnafflerRunner


# ---------- helpers ----------

def make_cfg():
    cfg = MagicMock()

    # ---------- resume ----------
    cfg.resume.enabled = False
    cfg.resume.state_db = None

    # ---------- targets ----------
    cfg.targets.unc_targets = []
    cfg.targets.computer_targets = []
    cfg.targets.shares_only = False

    # ---------- auth ----------
    cfg.auth.domain = None

    # ---------- advanced (ВАЖНО!) ----------
    cfg.advanced.share_threads = 2
    cfg.advanced.tree_threads = 2
    cfg.advanced.file_threads = 2

    return cfg



# ---------- tests ----------

def test_runner_unc_targets():
    cfg = make_cfg()
    cfg.targets.unc_targets = ["//HOST/SHARE"]

    runner = SnafflerRunner(cfg)

    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    runner.file_pipeline.run.assert_called_once_with(
        ["//HOST/SHARE"]
    )


def test_runner_computer_targets():
    cfg = make_cfg()
    cfg.targets.computer_targets = ["HOST1"]

    runner = SnafflerRunner(cfg)

    runner.share_pipeline.run = MagicMock(return_value=["//HOST1/SHARE"])
    runner.file_pipeline.run = MagicMock()

    with patch("snaffler.engine.runner.print_completion_stats"):
        runner.execute()

    runner.share_pipeline.run.assert_called_once_with(["HOST1"])
    runner.file_pipeline.run.assert_called_once_with(
        ["//HOST1/SHARE"]
    )


def test_runner_domain_discovery():
    cfg = make_cfg()
    cfg.auth.domain = "example.com"

    runner = SnafflerRunner(cfg)

    with patch(
        "snaffler.engine.runner.DomainPipeline"
    ) as domain_cls, patch(
        "snaffler.engine.runner.print_completion_stats"
    ):
        domain = domain_cls.return_value
        domain.run.return_value = ["HOST1"]

        runner.share_pipeline.run = MagicMock(return_value=["//HOST1/SHARE"])
        runner.file_pipeline.run = MagicMock()

        runner.execute()

    domain.run.assert_called_once()
    runner.share_pipeline.run.assert_called_once_with(["HOST1"])
    runner.file_pipeline.run.assert_called_once_with(
        ["//HOST1/SHARE"]
    )


def test_runner_no_targets():
    cfg = make_cfg()

    runner = SnafflerRunner(cfg)

    runner.file_pipeline.run = MagicMock()

    runner.execute()

    runner.file_pipeline.run.assert_not_called()
