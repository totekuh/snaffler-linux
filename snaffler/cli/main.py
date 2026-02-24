#!/usr/bin/env python3
from importlib.metadata import version as pkg_version
from pathlib import Path
from typing import Optional, List

import click
import typer

from snaffler.classifiers.loader import RuleLoader
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.engine.runner import SnafflerRunner
from snaffler.utils.logger import setup_logging
from snaffler.utils.target_parser import expand_targets


def _get_version() -> str:
    try:
        return pkg_version("snaffler-ng")
    except Exception:
        return "1.1.2"  # fallback for PyInstaller builds


def _version_callback(value: bool):
    if value:
        typer.echo(f"snaffler-ng {_get_version()}")
        raise typer.Exit()


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

# Network
DEFAULT_TIMEOUT_SECONDS = 5

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
def main(
        version: bool = typer.Option(
            False, "-V", "--version",
            help="Show version and exit",
            callback=_version_callback,
            is_eager=True,
        ),

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
            help="AD domain for LDAP discovery, or Kerberos realm (e.g. CORP.LOCAL)",
            rich_help_panel="Targeting",
        ),
        kerberos: bool = typer.Option(
            False, "-k", "--kerberos",
            help="Use Kerberos authentication (requires -d and hostnames as targets)",
            rich_help_panel="Authentication",
        ),
        use_kcache: bool = typer.Option(
            False, "--use-kcache",
            help="Use Kerberos credentials from ccache (KRB5CCNAME)",
            rich_help_panel="Authentication",
        ),

        # ---------------- TARGETING ----------------
        unc_targets: Optional[List[str]] = typer.Option(
            None, "--unc",
            help="Direct UNC path(s) to scan (disables computer/share discovery)",
            rich_help_panel="Targeting",
        ),
        computer: Optional[List[str]] = typer.Option(
            None, "-c", "--computer",
            help="Target computer(s) by hostname, IP, CIDR (10.0.0.0/24), or range (10.0.0.1-50)",
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
        include_disabled: bool = typer.Option(
            False,
            "--include-disabled",
            help="Include disabled and stale (4+ months inactive) computer accounts",
            rich_help_panel="Targeting",
        ),
        stdin_mode: bool = typer.Option(
            False,
            "--stdin",
            help="Read NXC SMB --shares output from stdin and use as UNC targets",
            rich_help_panel="Targeting",
        ),
        share: Optional[List[str]] = typer.Option(
            None,
            "--share",
            help="Only scan shares matching glob pattern (case-insensitive, repeatable)",
            rich_help_panel="Targeting",
        ),
        exclude_share: Optional[List[str]] = typer.Option(
            None,
            "--exclude-share",
            help="Skip shares matching glob pattern (case-insensitive, repeatable)",
            rich_help_panel="Targeting",
        ),

        # ---------------- NETWORK ----------------
        dc_host: Optional[str] = typer.Option(
            None,
            "--dc-host",
            help="Domain controller hostname, FQDN or IP (required for Kerberos LDAP)",
            rich_help_panel="Network",
        ),
        smb_timeout: int = typer.Option(
            DEFAULT_TIMEOUT_SECONDS,
            "--timeout",
            help=f"SMB connection timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS})",
            rich_help_panel="Network",
        ),
        socks_proxy: Optional[str] = typer.Option(
            None, "--socks",
            help="SOCKS proxy for pivoting (e.g. socks5://127.0.0.1:1080)",
            rich_help_panel="Network",
        ),
        nameserver: Optional[str] = typer.Option(
            None, "--nameserver", "--ns",
            help="Custom DNS server for hostname resolution (e.g. DC IP)",
            rich_help_panel="Network",
        ),

        # ---------------- OUTPUT ----------------
        output_file: Optional[Path] = typer.Option(
            None, "-o", "--output",
            help="Write results to file",
            rich_help_panel="Output",
        ),
        log_level: str = typer.Option(
            DEFAULT_LOG_LEVEL,
            "--log-level",
            help="Log verbosity: debug | info | data (data = findings only)",
            rich_help_panel="Output",
            click_type=click.Choice(
                ["debug", "info", "data"],
                case_sensitive=False,
            ),
        ),
        log_type: Optional[str] = typer.Option(
            None,
            "-t", "--log-type",
            help="Output format (auto-detected from -o extension if omitted)",
            rich_help_panel="Output",
            click_type=click.Choice(
                ["plain", "json", "tsv"],
                case_sensitive=False,
            ),
        ),
        no_banner: bool = typer.Option(
            False,
            "-q", "--no-banner",
            help="Disable startup banner",
            rich_help_panel="Output",
        ),
        no_color: bool = typer.Option(
            False,
            "--no-color",
            help="Disable colored output",
            rich_help_panel="Output",
        ),

        # ---------------- SCANNING ----------------
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

        # ---------------- ADVANCED ----------------
        max_threads: int = typer.Option(
            DEFAULT_MAX_THREADS,
            "-x", "--max-threads",
            help=f"Maximum total worker threads (default: {DEFAULT_MAX_THREADS})",
            rich_help_panel="Advanced",
        ),
        dns_threads: int = typer.Option(
            100,
            "--dns-threads",
            help="Concurrent threads for DNS + port 445 reachability probes (default: 100)",
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
        stealth: bool = typer.Option(
            False,
            "--stealth",
            help="OPSEC mode: pad LDAP queries with random attributes to break IDS signatures",
            rich_help_panel="Advanced",
        ),
        state: Optional[Path] = typer.Option(
            None,
            "--state",
            help="Path to state database (default: ./snaffler.db). Auto-resumes if DB exists.",
            rich_help_panel="Advanced",
        ),
        fresh: bool = typer.Option(
            False,
            "--fresh",
            help="Ignore existing state DB and start a clean scan",
            rich_help_panel="Advanced",
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
    cfg.targets.skip_disabled_computers = not include_disabled
    cfg.targets.share_filter = share or []
    cfg.targets.exclude_share = exclude_share or []

    if computer and computer_file:
        raise typer.BadParameter("Use either --computer or --computer-file, not both")

    if computer:
        cfg.targets.computer_targets = [h.upper() for h in expand_targets(computer)]

    if computer_file:
        raw_targets = [
            l.strip() for l in computer_file.read_text().splitlines() if l.strip()
        ]
        cfg.targets.computer_targets = [h.upper() for h in expand_targets(raw_targets)]

    # ---------- STDIN (NXC) ----------
    if stdin_mode:
        if cfg.targets.unc_targets or cfg.targets.computer_targets:
            raise typer.BadParameter(
                "--stdin is mutually exclusive with --unc, --computer, and --computer-file"
            )
        import sys
        from snaffler.utils.nxc_parser import parse_nxc_shares

        raw = sys.stdin.read()
        parsed = parse_nxc_shares(raw)
        if not parsed:
            raise typer.BadParameter(
                "No shares found in stdin (expected NXC SMB --shares output)"
            )
        cfg.targets.unc_targets = parsed

    # ---------- TARGET MODE VALIDATION ----------
    has_unc = bool(cfg.targets.unc_targets)
    has_computers = bool(cfg.targets.computer_targets)
    has_domain = bool(cfg.auth.domain)

    # At least one targeting mode must be selected
    if not (has_unc or has_computers or has_domain):
        raise typer.BadParameter(
            "No targets specified. Use one of: "
            "--unc, --computer/--computer-file, --stdin, or --domain"
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
    cfg.advanced.dns_threads = dns_threads
    cfg.advanced.stealth = stealth

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
    # Auto-detect format from output file extension when --log-type not explicit
    if log_type is None and output_file:
        ext = output_file.suffix.lower()
        if ext == ".json":
            log_type = "json"
        elif ext == ".tsv":
            log_type = "tsv"
    cfg.output.log_type = log_type or DEFAULT_LOG_TYPE

    if no_color:
        from snaffler.utils import logger as _logger_mod
        _logger_mod.NO_COLOR = True

    # ---------- STATE ----------
    state_path = Path(state) if state else Path("snaffler.db")
    if state_path.parent and not state_path.parent.exists():
        state_path.parent.mkdir(parents=True, exist_ok=True)
    if fresh and state_path.exists():
        state_path.unlink()
    cfg.state.state_db = str(state_path)
    cfg.state.fresh = fresh

    # ---------- validate ----------
    cfg.validate()

    # ---------- load classification rules ----------
    RuleLoader.load(cfg)

    # ---------- logging ----------
    setup_logging(
        log_level=cfg.output.log_level,
        log_to_file=cfg.output.to_file,
        log_file_path=cfg.output.output_file,
        log_to_console=True,
        log_type=cfg.output.log_type,
    )

    # ---------- SOCKS proxy ----------
    # SOCKS must be set up before custom DNS so that DNS-over-TCP
    # queries to an internal nameserver route through the tunnel.
    if socks_proxy:
        cfg.auth.socks_proxy = socks_proxy
        try:
            from snaffler.transport.socks import setup_socks_proxy
            setup_socks_proxy(socks_proxy)
        except (ImportError, ValueError) as exc:
            raise typer.BadParameter(str(exc))

    # ---------- custom DNS ----------
    if nameserver:
        try:
            from snaffler.transport.dns import setup_custom_dns
            setup_custom_dns(nameserver)
        except (ImportError, ValueError) as exc:
            raise typer.BadParameter(str(exc))

    # ---------- run ----------
    snaff = SnafflerRunner(cfg)
    try:
        snaff.execute()
    except KeyboardInterrupt:
        raise typer.Exit(code=130)


if __name__ == "__main__":
    app()
