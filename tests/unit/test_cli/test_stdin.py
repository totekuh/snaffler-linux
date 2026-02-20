"""Tests for --stdin flag (NXC pipe integration)."""

from unittest.mock import patch, MagicMock

from typer.testing import CliRunner

from snaffler.cli.main import app

runner = CliRunner()

NXC_OUTPUT = """\
SMB         10.8.50.20      445    DC01             [*] Windows Server 2022 Build 20348 x64
SMB         10.8.50.20      445    DC01             [+] CORP\\user:pass
SMB         10.8.50.20      445    DC01             [*] Enumerated shares
SMB         10.8.50.20      445    DC01             Share           Permissions     Remark
SMB         10.8.50.20      445    DC01             -----           -----------     ------
SMB         10.8.50.20      445    DC01             NETLOGON        READ            Logon server share
SMB         10.8.50.20      445    DC01             OPSshare        READ
SMB         10.8.50.20      445    DC01             SYSVOL          READ            Logon server share
"""


def _base_args():
    return ["--no-banner", "--log-level", "info"]


def test_stdin_parses_nxc_and_sets_unc_targets():
    """--stdin reads NXC output and populates unc_targets."""
    captured_cfg = {}

    def _capture_runner(cfg):
        captured_cfg["targets"] = list(cfg.targets.unc_targets)
        mock = MagicMock()
        mock.execute = MagicMock()
        return mock

    with patch("snaffler.cli.main.SnafflerRunner", side_effect=_capture_runner), \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        result = runner.invoke(app, _base_args() + ["--stdin"], input=NXC_OUTPUT)

    assert result.exit_code == 0, result.output
    targets = captured_cfg["targets"]
    assert "//10.8.50.20/NETLOGON" in targets
    assert "//10.8.50.20/OPSshare" in targets
    assert "//10.8.50.20/SYSVOL" in targets
    assert len(targets) == 3


def test_stdin_empty_input_errors():
    """--stdin with no parseable shares produces an error."""
    result = runner.invoke(app, _base_args() + ["--stdin"], input="")

    assert result.exit_code != 0
    assert "No shares found" in result.output


def test_stdin_mutual_exclusion_with_unc():
    """--stdin cannot be combined with --unc."""
    result = runner.invoke(
        app,
        _base_args() + ["--stdin", "--unc", "//HOST/SHARE"],
        input=NXC_OUTPUT,
    )

    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_stdin_mutual_exclusion_with_computer():
    """--stdin cannot be combined with --computer."""
    result = runner.invoke(
        app,
        _base_args() + ["--stdin", "--computer", "HOST1"],
        input=NXC_OUTPUT,
    )

    assert result.exit_code != 0
    assert "mutually exclusive" in result.output
