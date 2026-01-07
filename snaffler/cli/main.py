#!/usr/bin/env python3
from pathlib import Path
from typing import Optional, List

import click
import typer

from snaffler.config.configuration import SnafflerConfiguration
from snaffler.engine.runner import SnafflerRunner
from snaffler.utils.logger import setup_logging

app = typer.Typer(
    add_completion=False,
    help="Snaffler Linux – Find credentials and sensitive data on Windows SMB shares"
)

# ---------------- DEFAULTS ----------------

MB = 1024 * 1024

# Scanning
DEFAULT_MIN_INTEREST = 0
DEFAULT_MAX_GREP_SIZE = 2 * MB  # 2 MB
DEFAULT_MAX_SNAFFLE_SIZE = 10 * MB  # 10 MB
DEFAULT_MATCH_CONTEXT = 200  # bytes

# Auth
DEFAULT_TIMEOUT_MINUTES = 5

# Threads
DEFAULT_MAX_THREADS = 60

# Output
DEFAULT_LOG_LEVEL = "info"
DEFAULT_LOG_TYPE = "plain"


def banner():
    typer.echo(r"""
   _____ _   _          ______ ______ _      ______ _____
  / ____| \ | |   /\   |  ____|  ____| |    |  ____|  __ \
 | (___ |  \| |  /  \  | |__  | |__  | |    | |__  | |__) |
  \___ \| . ` | / /\ \ |  __| |  __| | |    |  __| |  _  /
  ____) | |\  |/ ____ \| |    | |    | |____| |____| | \ \
 |_____/|_| \_/_/    \_\_|    |_|    |______|______|_|  \_\
                                                  Impacket Port
    """)


@app.command()
def run(
        # ---------------- AUTH ----------------
        username: str = typer.Option(
            None, "-u", "--username",
            help="Username for authentication",
            rich_help_panel="Authentication",
        ),
        password: Optional[str] = typer.Option(
            None, "-p", "--password",
            help="Password for authentication (NTLM)",
            rich_help_panel="Authentication",
        ),
        nthash: Optional[str] = typer.Option(
            None, "--hash",
            help="NT hash for Pass-the-Hash authentication",
            rich_help_panel="Authentication",
        ),
        domain: Optional[str] = typer.Option(
            None, "-d", "--domain",
            help="Target Active Directory domain (e.g. CORP.LOCAL)",
            rich_help_panel="Authentication",
        ),
        dc_ip: Optional[str] = typer.Option(
            None, "-c", "--dc-ip",
            help="Domain controller IP",
            rich_help_panel="Authentication",
        ),
        timeout: int = typer.Option(
            DEFAULT_TIMEOUT_MINUTES,
            "-e", "--timeout",
            help="LDAP timeout / status update interval in minutes",
            rich_help_panel="Authentication",
        ),

        unc_path: Optional[List[str]] = typer.Option(
            None, "--unc",
            help="Direct UNC path(s) to scan (disables computer/share discovery)",
            rich_help_panel="Targeting",
        ),
        computer: Optional[List[str]] = typer.Option(
            None, "--computer",
            help="Target computer(s). Can be used multiple times.",
            rich_help_panel="Targeting",
        ),

        computer_file: Optional[Path] = typer.Option(
            None, "--computer-file",
            help="File containing computer names (one per line)",
            rich_help_panel="Targeting",
        ),
        shares_only: bool = typer.Option(
            False, "-a", "--shares-only",
            help="Only enumerate shares, skip filesystem walking",
            rich_help_panel="Targeting",
        ),

        output_file: Optional[Path] = typer.Option(
            None, "-o", "--output",
            help="Write results to file",
            rich_help_panel="Output",
        ),
        log_level: str = typer.Option(
            DEFAULT_LOG_LEVEL,
            "--log-level",
            help="Log level: debug | info | data",
            rich_help_panel="Output",
            click_type=click.Choice(
                ["debug", "info", "data"],
                case_sensitive=False,
            ),
        ),
        log_type: str = typer.Option(
            DEFAULT_LOG_TYPE,
            "-t", "--log-type",
            help="Log format: plain | json",
            rich_help_panel="Output",
        ),
        no_banner: bool = typer.Option(
            False,
            "--no-banner",
            help="Disable startup banner",
            rich_help_panel="Output",
        ),

        min_interest: int = typer.Option(
            DEFAULT_MIN_INTEREST,
            "-b", "--min-interest",
            help="Minimum interest level to report (0=all, 3=high only)",
            rich_help_panel="Scanning",
            min=0,
            max=3,
        ),
        max_grep_size: int = typer.Option(
            DEFAULT_MAX_GREP_SIZE,
            "-r", "--max-grep-size",
            help="Max file size to search inside (default: 2 MB)",
            rich_help_panel="Scanning",
        ),
        max_snaffle_size: int = typer.Option(
            DEFAULT_MAX_SNAFFLE_SIZE,
            "-l", "--max-snaffle-size",
            help="Max file size to download (default: 10 MB)",
            rich_help_panel="Scanning",
        ),

        snaffle_path: Optional[Path] = typer.Option(
            None, "-m", "--snaffle-path",
            help="Directory to copy interesting files into",
            rich_help_panel="Scanning",
        ),
        context: int = typer.Option(
            DEFAULT_MATCH_CONTEXT,
            "-j", "--context",
            help=f"Bytes of context around matched strings (default: {DEFAULT_MATCH_CONTEXT})",
            rich_help_panel="Scanning",
        ),
        max_threads: int = typer.Option(
            DEFAULT_MAX_THREADS,
            "-x", "--max-threads",
            help=f"Maximum total worker threads (default: {DEFAULT_MAX_THREADS})",
            rich_help_panel="Advanced",
        ),
        config_file: Optional[Path] = typer.Option(
            None, "-z", "--config",
            help="Path to TOML configuration file",
            rich_help_panel="Advanced",
        ),
        rule_dir: Optional[Path] = typer.Option(
            None, "-R", "--rule-dir",
            help="Directory containing custom TOML rule files",
            rich_help_panel="Advanced",
        )
):
    if not no_banner:
        banner()

    # Default to stdout if no output file is specified
    if output_file is None:
        stdout = True

    # ---------- load configuration ----------
    cfg = SnafflerConfiguration()

    if config_file:
        cfg.load_from_toml(str(config_file))

    # ---------- AUTH ----------
    cfg.auth.username = username
    cfg.auth.password = password
    cfg.auth.nthash = nthash
    cfg.auth.domain = domain
    cfg.auth.dc_ip = dc_ip
    cfg.auth.timeout = timeout

    # ---------- TARGETING ----------
    cfg.targets.path_targets = unc_path or []
    cfg.targets.shares_only = shares_only

    if computer and computer_file:
        raise typer.BadParameter("Use either --computer or --computer-file, not both")

    if computer:
        cfg.targets.computer_targets = computer

    if computer_file:
        cfg.targets.computer_targets = [
            l.strip() for l in computer_file.read_text().splitlines() if l.strip()
        ]
    # ---------- TARGET MODE VALIDATION ----------
    has_unc = bool(cfg.targets.path_targets)
    has_computers = bool(cfg.targets.computer_targets)
    has_domain = bool(cfg.auth.domain)

    # At least one targeting mode must be selected
    if not (has_unc or has_computers or has_domain):
        raise typer.BadParameter(
            "No targets specified. Use one of: "
            "--unc, --computer/--computer-file, or --domain"
        )
    # ---------- SCANNING ----------
    cfg.scanning.interest_level = min_interest
    cfg.scanning.max_size_to_grep = max_grep_size
    cfg.scanning.max_size_to_snaffle = max_snaffle_size
    cfg.scanning.match_context_bytes = context

    if snaffle_path:
        cfg.scanning.snaffle = True
        cfg.scanning.snaffle_path = str(snaffle_path)

    # ---------- ADVANCED ----------
    cfg.advanced.max_threads = max_threads

    per_bucket = max(1, max_threads // 3)
    cfg.advanced.share_threads = per_bucket
    cfg.advanced.tree_threads = per_bucket
    cfg.advanced.file_threads = per_bucket

    cfg.advanced.rule_dir = str(rule_dir) if rule_dir else None

    # ---------- OUTPUT ----------
    cfg.output.to_file = output_file is not None
    cfg.output.output_file = str(output_file) if output_file else None
    cfg.output.log_level = log_level
    cfg.output.log_type = log_type

    # ---------- validate ----------
    cfg.validate()

    # ---------- logging ----------
    setup_logging(
        log_level=cfg.output.log_level,
        log_to_file=cfg.output.to_file,
        log_file_path=cfg.output.output_file,
        log_to_console=cfg.output.to_stdout,
        log_type=cfg.output.log_type,
    )

    # ---------- run ----------
    snaff = SnafflerRunner(cfg)
    snaff.execute()


if __name__ == "__main__":
    app()
