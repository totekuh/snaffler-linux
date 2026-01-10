#!/usr/bin/env python3
from pathlib import Path
from typing import Optional, List

import click
import typer

from snaffler.classifiers.loader import RuleLoader
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
DEFAULT_MAX_READ_BYTES = 2 * MB  # 2 MB
DEFAULT_MAX_FILE_BYTES = 10 * MB  # 10 MB
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
            help="Target Active Directory domain / Kerberos realm (e.g. CORP.LOCAL)",
            rich_help_panel="Authentication",
        ),
        dc_host: Optional[str] = typer.Option(
            None,
            "--dc-host",
            help=(
                    "Domain controller hostname, FQDN or IP address. "
                    "Hostnames are required for Kerberos LDAP. "
            ),
            rich_help_panel="Authentication",
        ),
        smb_timeout: int = typer.Option(
            DEFAULT_TIMEOUT_MINUTES,
            "-e", "--timeout",
            help="SMB timeout in seconds",
            rich_help_panel="Authentication",
        ),

        kerberos: bool = typer.Option(
            False, "-k", "--kerberos",
            help=(
                    "Use Kerberos authentication. "
                    "Requires --domain and hostnames/FQDNs as targets."
            ),
            rich_help_panel="Authentication",
        ),
        use_kcache: bool = typer.Option(
            False, "--use-kcache",
            help="Use Kerberos credentials from ccache (KRB5CCNAME)",
            rich_help_panel="Authentication",
        ),

        unc_targets: Optional[List[str]] = typer.Option(
            None, "--unc",
            help="Direct UNC path(s) to scan (disables computer/share discovery)",
            rich_help_panel="Targeting",
        ),
        computer: Optional[List[str]] = typer.Option(
            None, "--computer",
            help="Target computer(s) by hostname or FQDN (note that Kerberos requires names, not IPs)",
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
            help="Log format: plain | json | tsv",
            rich_help_panel="Output",
        ),
        no_banner: bool = typer.Option(
            False,
            "-q", "--no-banner",
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
         max_read_bytes: int = typer.Option(
             DEFAULT_MAX_READ_BYTES,
             "-r", "--max-read-bytes",
             help="Maximum bytes to read from a file for content scanning (default: 2 MB)",
             rich_help_panel="Scanning",
         ),
        max_file_bytes: int = typer.Option(
            DEFAULT_MAX_FILE_BYTES,
            "-l", "--max-file-bytes",
            help="Maximum file size allowed for scanning and downloading (default: 10 MB)",
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
        ),
        resume: bool = typer.Option(
            False,
            "--resume",
            help="Resume a previous scan",
            rich_help_panel="Resume",
        ),

        state: Optional[Path] = typer.Option(
            None,
            "--state",
            help="Path to resume state database (SQLite)",
            rich_help_panel="Resume",
        ),

):
    if not no_banner:
        banner()

    # ---------- load configuration ----------
    cfg = SnafflerConfiguration()

    if config_file:
        cfg.load_from_toml(str(config_file))

    # ---------- AUTH ----------
    cfg.auth.username = username
    cfg.auth.password = password
    cfg.auth.nthash = nthash
    cfg.auth.domain = domain
    cfg.auth.dc_host = dc_host
    cfg.auth.smb_timeout = smb_timeout
    cfg.auth.kerberos = kerberos
    cfg.auth.use_kcache = use_kcache

    # ---------- TARGETING ----------
    cfg.targets.unc_targets = unc_targets or []
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
    has_unc = bool(cfg.targets.unc_targets)
    has_computers = bool(cfg.targets.computer_targets)
    has_domain = bool(cfg.auth.domain)

    # At least one targeting mode must be selected
    if not (has_unc or has_computers or has_domain):
        raise typer.BadParameter(
            "No targets specified. Use one of: "
            "--unc, --computer/--computer-file, or --domain"
        )
    # ---------- SCANNING ----------
    cfg.scanning.min_interest = min_interest
    cfg.scanning.max_read_bytes = max_read_bytes
    cfg.scanning.max_file_bytes = max_file_bytes
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

    if rule_dir:
        cfg.rules.rule_dir = f"{rule_dir}"

    # ---------- OUTPUT ----------
    cfg.output.to_file = output_file is not None
    cfg.output.output_file = str(output_file) if output_file else None
    cfg.output.log_level = log_level
    cfg.output.log_type = log_type

    # ---------- RESUME ----------
    if resume:
        cfg.resume.enabled = True

        if state:
            state_path = state
        else:
            state_path = Path("snaffler.db")

        # ensure parent dir exists
        if state_path.parent and not state_path.parent.exists():
            state_path.parent.mkdir(parents=True, exist_ok=True)

        # create DB file if missing
        if not state_path.exists():
            state_path.touch()

        cfg.resume.state_db = str(state_path)

    else:
        if state:
            typer.echo(
                "[!] Warning: --state provided without --resume. Ignoring.",
                err=True,
            )

    # ---------- validate ----------
    cfg.validate()

    # ---------- load classification rules ----------
    RuleLoader.load(cfg)

    # ---------- logging ----------
    setup_logging(
        log_level=cfg.output.log_level,
        log_to_file=cfg.output.to_file,
        log_file_path=cfg.output.output_file,
        log_to_console=not cfg.output.to_file,
        log_type=cfg.output.log_type,
    )

    # ---------- run ----------
    snaff = SnafflerRunner(cfg)
    snaff.execute()


if __name__ == "__main__":
    app()
