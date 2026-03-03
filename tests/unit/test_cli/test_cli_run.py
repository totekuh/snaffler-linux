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
    assert "No targets specified" in result.output


def test_cli_no_color_sets_flag():
    import snaffler.utils.logger as logger_mod
    original = logger_mod.NO_COLOR

    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        runner_cls.return_value.execute.return_value = None

        result = runner.invoke(
            app,
            base_args() + ["--no-color", "--unc", "//HOST/SHARE"],
        )

    assert result.exit_code == 0
    assert logger_mod.NO_COLOR is True
    logger_mod.NO_COLOR = original


def test_cli_socks_calls_setup():
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"), \
            patch("snaffler.transport.socks.setup_socks_proxy") as mock_setup:
        runner_cls.return_value.execute.return_value = None

        result = runner.invoke(
            app,
            base_args() + [
                "--unc", "//HOST/SHARE",
                "--socks", "socks5://127.0.0.1:1080",
            ],
        )

    assert result.exit_code == 0
    mock_setup.assert_called_once_with("socks5://127.0.0.1:1080")


def test_cli_web_port_without_web_warns():
    """W11: --web-port without --web emits a warning to stderr."""
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        runner_cls.return_value.execute.return_value = None

        result = runner.invoke(
            app,
            base_args() + [
                "--unc", "//HOST/SHARE",
                "--web-port", "9999",
            ],
        )

    assert result.exit_code == 0
    assert "--web-port has no effect without --web" in result.output


def test_cli_local_targets():
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        instance = runner_cls.return_value

        result = runner.invoke(
            app,
            base_args() + ["--local", "/tmp"],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    assert cfg.targets.local_targets == ["/tmp"]
    instance.execute.assert_called_once()


def test_cli_local_multiple_paths():
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        instance = runner_cls.return_value

        result = runner.invoke(
            app,
            base_args() + ["--local", "/tmp", "--local", "/var"],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    assert cfg.targets.local_targets == ["/tmp", "/var"]


def test_cli_local_exclusive_with_unc():
    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        result = runner.invoke(
            app,
            base_args() + ["--local", "/tmp", "--unc", "//srv/share"],
        )

    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_cli_local_exclusive_with_computer():
    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        result = runner.invoke(
            app,
            base_args() + ["--local", "/tmp", "--computer", "HOST1"],
        )

    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_cli_local_exclusive_with_domain():
    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        result = runner.invoke(
            app,
            base_args() + ["--local", "/tmp", "--domain", "example.com"],
        )

    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_cli_local_exclusive_with_stdin():
    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        result = runner.invoke(
            app,
            base_args() + ["--local", "/tmp", "--stdin"],
        )

    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_cli_local_nonexistent_path():
    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        result = runner.invoke(
            app,
            base_args() + ["--local", "/nonexistent/path/12345"],
        )

    assert result.exit_code != 0
    assert "does not exist" in result.output


def test_cli_local_not_a_directory(tmp_path):
    f = tmp_path / "somefile.txt"
    f.write_text("not a dir")

    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        result = runner.invoke(
            app,
            base_args() + ["--local", str(f)],
        )

    assert result.exit_code != 0
    assert "not a directory" in result.output


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
