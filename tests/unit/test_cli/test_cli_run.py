from unittest.mock import patch, call

from typer.testing import CliRunner

from snaffler.cli.main import app
from snaffler.utils.logger import setup_logging

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
            base_args() + ["--local-fs", "/tmp"],
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
            base_args() + ["--local-fs", "/tmp", "--local-fs", "/var"],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    assert cfg.targets.local_targets == ["/tmp", "/var"]


def test_cli_local_exclusive_with_unc():
    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        result = runner.invoke(
            app,
            base_args() + ["--local-fs", "/tmp", "--unc", "//srv/share"],
        )

    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_cli_local_exclusive_with_computer():
    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        result = runner.invoke(
            app,
            base_args() + ["--local-fs", "/tmp", "--computer", "HOST1"],
        )

    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_cli_local_exclusive_with_domain():
    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        result = runner.invoke(
            app,
            base_args() + ["--local-fs", "/tmp", "--domain", "example.com"],
        )

    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_cli_local_exclusive_with_stdin():
    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        result = runner.invoke(
            app,
            base_args() + ["--local-fs", "/tmp", "--stdin"],
        )

    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_cli_local_nonexistent_path():
    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        result = runner.invoke(
            app,
            base_args() + ["--local-fs", "/nonexistent/path/12345"],
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
            base_args() + ["--local-fs", str(f)],
        )

    assert result.exit_code != 0
    assert "not a directory" in result.output


def test_cli_computer_cidr_expanded():
    """BUG-1: --computer with CIDR notation expands to individual IPs."""
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        instance = runner_cls.return_value

        result = runner.invoke(
            app,
            base_args() + ["--computer", "10.0.0.0/30"],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    # /30 = 2 usable host addresses: .1, .2 (network .0 and broadcast .3 excluded)
    assert sorted(cfg.targets.computer_targets) == [
        "10.0.0.1", "10.0.0.2",
    ]


def test_cli_stdin_exclusive_with_domain():
    """BUG-3: --stdin --domain is rejected as mutually exclusive."""
    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        result = runner.invoke(
            app,
            base_args() + ["--stdin", "--domain", "example.com"],
            input="",
        )

    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


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


def test_tsv_header_not_duplicated_on_second_call(tmp_path):
    """BUG-U: TSV header is only written if file is new/empty.

    Calling setup_logging twice with the same TSV file must NOT truncate
    the first session's data or duplicate the header line.
    """
    tsv_file = tmp_path / "findings.tsv"

    # First call — creates the file and writes header
    setup_logging(
        log_level="data",
        log_to_file=True,
        log_file_path=str(tsv_file),
        log_to_console=False,
        log_type="tsv",
    )

    # Simulate some data written by session 1
    tsv_file.write_text(
        tsv_file.read_text() + "2025-01-01\tRed\tTestRule\t//srv/share/f.txt\t100\t2025-01-01\tabc123\tpassword\n"
    )

    content_before = tsv_file.read_text()
    assert content_before.count("timestamp\t") == 1

    # Second call — same file, should NOT truncate or add another header
    setup_logging(
        log_level="data",
        log_to_file=True,
        log_file_path=str(tsv_file),
        log_to_console=False,
        log_type="tsv",
    )

    content_after = tsv_file.read_text()

    # Header still appears exactly once
    assert content_after.count("timestamp\t") == 1
    # Session 1 data is preserved
    assert "TestRule" in content_after


def test_setup_logging_called_before_rule_loader():
    """BUG-L: setup_logging() must be called BEFORE RuleLoader.load().

    If logging is initialized after rule loading, any warnings or errors
    during rule loading are silently lost.
    """
    call_order = []

    def track_setup_logging(*args, **kwargs):
        call_order.append("setup_logging")

    def track_rule_load(*args, **kwargs):
        call_order.append("rule_load")

    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.setup_logging", side_effect=track_setup_logging), \
            patch("snaffler.cli.main.RuleLoader.load", side_effect=track_rule_load):
        runner_cls.return_value.execute.return_value = None

        result = runner.invoke(
            app,
            base_args() + ["--unc", "//HOST/SHARE"],
        )

    assert result.exit_code == 0
    assert "setup_logging" in call_order
    assert "rule_load" in call_order
    assert call_order.index("setup_logging") < call_order.index("rule_load"), \
        f"setup_logging must be called before RuleLoader.load, got: {call_order}"


# ---------- --exclude-path / --exclude-unc alias ----------

def test_cli_exclude_unc_sets_config():
    """--exclude-unc populates cfg.targets.exclude_unc."""
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        runner_cls.return_value.execute.return_value = None

        result = runner.invoke(
            app,
            base_args() + [
                "--local-fs", "/tmp",
                "--exclude-unc", "*/Windows/*",
            ],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    assert "*/Windows/*" in cfg.targets.exclude_unc


def test_cli_exclude_path_alias_sets_config():
    """--exclude-path is an alias for --exclude-unc."""
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        runner_cls.return_value.execute.return_value = None

        result = runner.invoke(
            app,
            base_args() + [
                "--local-fs", "/tmp",
                "--exclude-path", "*/node_modules/*",
            ],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    assert "*/node_modules/*" in cfg.targets.exclude_unc


def test_cli_exclude_path_multiple():
    """Multiple --exclude-path flags accumulate."""
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        runner_cls.return_value.execute.return_value = None

        result = runner.invoke(
            app,
            base_args() + [
                "--local-fs", "/tmp",
                "--exclude-path", "*/Windows/*",
                "--exclude-path", "*/Temp/*",
            ],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    assert "*/Windows/*" in cfg.targets.exclude_unc
    assert "*/Temp/*" in cfg.targets.exclude_unc


def test_cli_exclude_path_mixed_with_exclude_unc():
    """--exclude-path and --exclude-unc can be mixed (they're the same option)."""
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        runner_cls.return_value.execute.return_value = None

        result = runner.invoke(
            app,
            base_args() + [
                "--local-fs", "/tmp",
                "--exclude-unc", "*/Windows/*",
                "--exclude-path", "*/Temp/*",
            ],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    assert "*/Windows/*" in cfg.targets.exclude_unc
    assert "*/Temp/*" in cfg.targets.exclude_unc


def test_cli_exclude_path_with_unc_targets():
    """--exclude-path also works with UNC targets, not just --local-fs."""
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        runner_cls.return_value.execute.return_value = None

        result = runner.invoke(
            app,
            base_args() + [
                "--unc", "//HOST/SHARE",
                "--exclude-path", "*/Windows/*",
            ],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    assert "*/Windows/*" in cfg.targets.exclude_unc


# ---------- FTP ----------

def test_cli_ftp_targets():
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        instance = runner_cls.return_value

        result = runner.invoke(
            app,
            base_args() + ["--ftp", "ftp://10.0.0.5/data", "--ftp", "10.0.0.6"],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    assert cfg.targets.ftp_targets == ["ftp://10.0.0.5/data", "ftp://10.0.0.6"]
    instance.execute.assert_called_once()


def test_cli_ftp_file(tmp_path):
    targets = tmp_path / "ftp_targets.txt"
    targets.write_text("ftp://10.0.0.5/share\n10.0.0.6\n# comment\n\nftp://10.0.0.7:2121\n")
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        instance = runner_cls.return_value

        result = runner.invoke(
            app,
            base_args() + ["--ftp-file", str(targets)],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    assert cfg.targets.ftp_targets == [
        "ftp://10.0.0.5/share",
        "ftp://10.0.0.6",
        "ftp://10.0.0.7:2121",
    ]
    instance.execute.assert_called_once()


def test_cli_ftp_and_ftp_file_exclusive(tmp_path):
    targets = tmp_path / "ftp_targets.txt"
    targets.write_text("10.0.0.5\n")
    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        result = runner.invoke(
            app,
            base_args() + ["--ftp", "10.0.0.5", "--ftp-file", str(targets)],
        )

    assert result.exit_code != 0
    assert "not both" in result.output


def test_cli_ftp_exclusive_with_unc():
    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        result = runner.invoke(
            app,
            base_args() + ["--ftp", "10.0.0.5", "--unc", "//srv/share"],
        )

    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


# ---------- --rescan-unreadable ----------

def test_cli_rescan_unreadable():
    """--rescan-unreadable flag wires to config and is accepted without other targets."""
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        instance = runner_cls.return_value

        result = runner.invoke(
            app,
            base_args() + ["--rescan-unreadable"],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    assert cfg.targets.rescan_unreadable is True
    instance.execute.assert_called_once()


def test_cli_rescan_unreadable_no_targets_required():
    """--rescan-unreadable doesn't need --unc, --computer, or --domain."""
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        runner_cls.return_value.execute.return_value = None

        result = runner.invoke(
            app,
            base_args() + ["--rescan-unreadable", "-u", "user", "-p", "pass"],
        )

    assert result.exit_code == 0


def test_cli_rescan_unreadable_exclusive_with_local():
    """--rescan-unreadable is mutually exclusive with --local-fs."""
    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        result = runner.invoke(
            app,
            base_args() + ["--rescan-unreadable", "--local-fs", "/tmp"],
        )

    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_cli_rescan_unreadable_exclusive_with_ftp():
    """--rescan-unreadable is mutually exclusive with --ftp."""
    with patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        result = runner.invoke(
            app,
            base_args() + ["--rescan-unreadable", "--ftp", "10.0.0.5"],
        )

    assert result.exit_code != 0
    assert "mutually exclusive" in result.output


def test_cli_rescan_unreadable_with_unc():
    """--rescan-unreadable + --unc is accepted (rescan takes priority)."""
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        runner_cls.return_value.execute.return_value = None

        result = runner.invoke(
            app,
            base_args() + ["--rescan-unreadable", "--unc", "//HOST/SHARE"],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    assert cfg.targets.rescan_unreadable is True
    assert cfg.targets.unc_targets == ["//HOST/SHARE"]


def test_cli_rescan_unreadable_with_computer():
    """--rescan-unreadable + --computer is accepted (rescan takes priority)."""
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        runner_cls.return_value.execute.return_value = None

        result = runner.invoke(
            app,
            base_args() + ["--rescan-unreadable", "--computer", "HOST1"],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    assert cfg.targets.rescan_unreadable is True


def test_cli_rescan_unreadable_with_domain():
    """--rescan-unreadable + --domain is accepted (rescan takes priority)."""
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        runner_cls.return_value.execute.return_value = None

        result = runner.invoke(
            app,
            base_args() + ["--rescan-unreadable", "--domain", "CORP.LOCAL"],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    assert cfg.targets.rescan_unreadable is True


def test_cli_rescan_unreadable_with_share_filter():
    """--rescan-unreadable + --share filter is accepted."""
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        runner_cls.return_value.execute.return_value = None

        result = runner.invoke(
            app,
            base_args() + [
                "--rescan-unreadable",
                "--share", "FINANCE*",
                "--exclude-share", "ADMIN$",
            ],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    assert cfg.targets.rescan_unreadable is True
    assert cfg.targets.share_filter == ["FINANCE*"]
    assert cfg.targets.exclude_share == ["ADMIN$"]


def test_cli_rescan_unreadable_with_exclusions(tmp_path):
    """--rescan-unreadable + --exclusions file is accepted."""
    excl_file = tmp_path / "exclusions.txt"
    excl_file.write_text("DEADHOST\nBADHOST\n")

    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        runner_cls.return_value.execute.return_value = None

        result = runner.invoke(
            app,
            base_args() + [
                "--rescan-unreadable",
                "--exclusions", str(excl_file),
            ],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    assert cfg.targets.rescan_unreadable is True
    assert "DEADHOST" in cfg.targets.exclusions


# ---------- --fast ----------

def test_cli_fast_adds_exclusions():
    """--fast prepends FAST_MODE_EXCLUSIONS to cfg.targets.exclude_unc."""
    from snaffler.config.configuration import FAST_MODE_EXCLUSIONS

    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        runner_cls.return_value.execute.return_value = None

        result = runner.invoke(
            app,
            base_args() + ["--fast", "--unc", "//HOST/SHARE"],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    for pattern in FAST_MODE_EXCLUSIONS:
        assert pattern in cfg.targets.exclude_unc


def test_cli_fast_sets_max_threads_per_share():
    """--fast auto-sets max_tree_threads_per_share when not explicitly provided."""
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        runner_cls.return_value.execute.return_value = None

        result = runner.invoke(
            app,
            base_args() + ["--fast", "--unc", "//HOST/SHARE"],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    assert cfg.advanced.max_tree_threads_per_share >= 2


def test_cli_fast_preserves_user_exclude_unc():
    """--fast exclusions are additive with user-provided --exclude-unc."""
    from snaffler.config.configuration import FAST_MODE_EXCLUSIONS

    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        runner_cls.return_value.execute.return_value = None

        result = runner.invoke(
            app,
            base_args() + [
                "--fast",
                "--unc", "//HOST/SHARE",
                "--exclude-unc", "*/my_custom/*",
            ],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    # User patterns are preserved at end
    assert "*/my_custom/*" in cfg.targets.exclude_unc
    # Fast patterns are prepended
    assert cfg.targets.exclude_unc[0] == FAST_MODE_EXCLUSIONS[0]


def test_cli_max_threads_per_share_explicit():
    """--max-threads-per-share sets the config value."""
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        runner_cls.return_value.execute.return_value = None

        result = runner.invoke(
            app,
            base_args() + [
                "--unc", "//HOST/SHARE",
                "--max-threads-per-share", "5",
            ],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    assert cfg.advanced.max_tree_threads_per_share == 5


def test_cli_fast_explicit_threads_per_share_overrides():
    """--fast + explicit --max-threads-per-share: explicit value wins."""
    with patch("snaffler.cli.main.SnafflerRunner") as runner_cls, \
            patch("snaffler.cli.main.RuleLoader.load"), \
            patch("snaffler.cli.main.setup_logging"):
        runner_cls.return_value.execute.return_value = None

        result = runner.invoke(
            app,
            base_args() + [
                "--fast",
                "--unc", "//HOST/SHARE",
                "--max-threads-per-share", "10",
            ],
        )

    assert result.exit_code == 0
    cfg = runner_cls.call_args[0][0]
    assert cfg.advanced.max_tree_threads_per_share == 10
