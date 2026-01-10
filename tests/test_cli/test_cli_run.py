from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner
from snaffler.cli.main import app

runner = CliRunner()


# ---------- helpers ----------

def base_args():
    return [
        "--no-banner",
        "--log-level", "info",
    ]


# ---------- tests ----------

def test_cli_unc_targets():
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
         patch("snaffler.cli.main.RuleLoader.load"), \
         patch("snaffler.cli.main.setup_logging"):

        instance = runner_cls.return_value

        result = runner.invoke(
            app,
            base_args() + ["--unc", "//HOST/SHARE"],
        )

    assert result.exit_code == 0
    runner_cls.assert_called_once()
    instance.execute.assert_called_once()


def test_cli_computer_targets():
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
         patch("snaffler.cli.main.RuleLoader.load"), \
         patch("snaffler.cli.main.setup_logging"):

        instance = runner_cls.return_value

        result = runner.invoke(
            app,
            base_args() + ["--computer", "HOST1"],
        )

    assert result.exit_code == 0
    instance.execute.assert_called_once()


def test_cli_domain_targets():
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
         patch("snaffler.cli.main.RuleLoader.load"), \
         patch("snaffler.cli.main.setup_logging"):

        instance = runner_cls.return_value

        result = runner.invoke(
            app,
            base_args() + ["--domain", "example.com"],
        )

    assert result.exit_code == 0
    instance.execute.assert_called_once()


def test_cli_no_targets_error():
    result = runner.invoke(
        app,
        base_args(),
    )

    assert result.exit_code != 0
    assert "No targets specified" in result.stderr



def test_cli_computer_and_file_conflict(tmp_path):
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("HOST1\n")

    result = runner.invoke(
        app,
        base_args() + [
            "--computer", "HOST1",
            "--computer-file", str(hosts),
        ],
    )

    assert result.exit_code != 0
    assert "Use either --computer or --computer-file" in result.stderr



def test_cli_load_config_file(tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("""
        [auth]
        domain = "example.com"
    """)

    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
         patch("snaffler.cli.main.RuleLoader.load"), \
         patch("snaffler.cli.main.setup_logging"):

        instance = runner_cls.return_value

        result = runner.invoke(
            app,
            base_args() + [
                "--config", str(cfg),
                "--domain", "example.com",
            ],
        )

    assert result.exit_code == 0
    instance.execute.assert_called_once()

