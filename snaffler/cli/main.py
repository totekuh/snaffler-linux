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
from snaffler.cli.results import results_app


def _get_version() -> str:
    try:
        return pkg_version("snaffler-ng")
    except Exception:
        return "1.5.6"  # fallback for PyInstaller builds


def _version_callback(value: bool):
    if value:
        typer.echo(f"snaffler-ng {_get_version()}")
        raise typer.Exit()


app = typer.Typer(
    add_completion=False,
    help="Snaffler Linux – Find credentials and sensitive data on Windows SMB shares",
)
app.add_typer(results_app, name="results")

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


def _run_grab(cfg: SnafflerConfiguration):
    """Bulk download mode: read file paths from stdin, download each."""
    import sys
    import logging
    from concurrent.futures import ThreadPoolExecutor, as_completed

    logger = logging.getLogger("snaffler")
    dest = cfg.scanning.snaffle_path
    Path(dest).mkdir(parents=True, exist_ok=True)

    # Read paths from stdin
    raw = sys.stdin.read()
    paths = [line.strip() for line in raw.splitlines() if line.strip()]
    if not paths:
        typer.echo("No file paths received on stdin.", err=True)
        raise typer.Exit(code=1)

    typer.echo(f"Grabbing {len(paths)} files to {dest}")

    # Group paths by protocol and create accessors
    smb_paths = []
    ftp_paths = []
    local_paths = []
    for p in paths:
        if p.startswith("ftp://"):
            ftp_paths.append(p)
        elif p.startswith("//"):
            smb_paths.append(p)
        else:
            local_paths.append(p)

    accessors = {}
    if smb_paths:
        from snaffler.accessors.smb_file_accessor import SMBFileAccessor
        accessors["smb"] = SMBFileAccessor(cfg)
    if ftp_paths:
        from snaffler.accessors.ftp_file_accessor import FTPFileAccessor
        accessors["ftp"] = FTPFileAccessor(cfg)
    if local_paths:
        from snaffler.accessors.local_file_accessor import LocalFileAccessor
        accessors["local"] = LocalFileAccessor()

    ok = 0
    fail = 0
    skip = 0

    def _resolve_local_path(file_path: str) -> Path:
        """Return the expected local path for a downloaded file."""
        import os
        if file_path.startswith("ftp://"):
            from snaffler.discovery.ftp_tree_walker import parse_ftp_url
            parsed = parse_ftp_url(file_path)
            if parsed:
                host, _port, remote = parsed
                return (Path(dest) / host / remote.lstrip("/")).resolve()
        elif file_path.startswith("//"):
            from snaffler.utils.path_utils import parse_unc_path
            parsed = parse_unc_path(file_path)
            if parsed:
                server, share, smb_path, _name, _ext = parsed
                clean = smb_path.lstrip("\\/").replace("\\", "/")
                return (Path(dest) / server / share / clean).resolve()
        else:
            rel = os.path.relpath(file_path, "/")
            return (Path(dest) / rel).resolve()
        return None

    def _grab_one(file_path: str) -> bool:
        """Download one file. Returns True on success."""
        if file_path.startswith("ftp://"):
            accessor = accessors["ftp"]
        elif file_path.startswith("//"):
            accessor = accessors["smb"]
        else:
            accessor = accessors["local"]
        accessor.copy_to_local(file_path, dest)
        local = _resolve_local_path(file_path)
        return local is not None and local.exists()

    workers = max(1, cfg.advanced.file_threads)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_path = {pool.submit(_grab_one, p): p for p in paths}
        for future in as_completed(future_to_path):
            p = future_to_path[future]
            try:
                if future.result():
                    ok += 1
                    logger.info(f"[OK] {p}")
                else:
                    fail += 1
                    logger.warning(f"[FAIL] {p}")
            except Exception as e:
                fail += 1
                logger.warning(f"[FAIL] {p}: {e}")

    typer.echo(f"\nDone: {ok} downloaded, {fail} failed ({len(paths)} total)")


@app.callback(invoke_without_command=True)
def main(
        ctx: typer.Context,
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
        local: Optional[List[str]] = typer.Option(
            None, "--local-fs",
            help="Local directory path(s) to scan (no SMB, scans local filesystem)",
            rich_help_panel="Targeting",
        ),
        ftp: Optional[List[str]] = typer.Option(
            None, "--ftp",
            help="FTP target URL(s) to scan (e.g. ftp://10.0.0.5/data or bare 10.0.0.5)",
            rich_help_panel="Targeting",
        ),
        ftp_file: Optional[Path] = typer.Option(
            None, "--ftp-file",
            help="File containing FTP targets (one per line, same format as --ftp)",
            rich_help_panel="Targeting",
        ),
        ftp_tls: bool = typer.Option(
            False, "--ftp-tls",
            help="Use FTPS (FTP over TLS) for --ftp targets",
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
        rescan_unreadable: bool = typer.Option(
            False, "--rescan-unreadable",
            help="Re-test previously unreadable shares from state DB with current creds",
            rich_help_panel="Targeting",
        ),
        grab: bool = typer.Option(
            False, "--grab",
            help="Bulk download mode: read file paths from stdin, download to -m dir (no scanning)",
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
        exclude_unc: Optional[List[str]] = typer.Option(
            None,
            "--exclude-unc", "--exclude-path",
            help="Skip paths matching glob pattern (case-insensitive, repeatable). Works with both UNC and local paths.",
            rich_help_panel="Targeting",
        ),
        exclusions_file: Optional[Path] = typer.Option(
            None, "--exclusions",
            help="File of hostnames/IPs to skip (one per line)",
            rich_help_panel="Targeting",
        ),
        max_hosts: Optional[int] = typer.Option(
            None, "--max-hosts",
            help="Stop after scanning N hosts (applied after exclusions)",
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
        max_depth: Optional[int] = typer.Option(
            None,
            "--max-depth",
            help="Maximum directory recursion depth (0 = share root only)",
            rich_help_panel="Scanning",
        ),
        fast: bool = typer.Option(
            False,
            "--fast",
            help="Skip known time-waster directories and interleave share walking",
            rich_help_panel="Scanning",
        ),
        match_filter: Optional[str] = typer.Option(
            None, "--match",
            help="Only output findings matching this regex (applied to path, rule, match, context)",
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
        max_threads_per_share: int = typer.Option(
            0,
            "--max-threads-per-share",
            help="Max concurrent tree-walk threads per share (0 = unlimited, --fast auto-sets)",
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

        # ---------------- WEB DASHBOARD ----------------
        web: bool = typer.Option(
            False,
            "--web",
            help="Enable live web dashboard (requires: pip install snaffler-ng[web])",
            rich_help_panel="Web Dashboard",
        ),
        web_port: int = typer.Option(
            8080,
            "--web-port",
            help="Port for web dashboard (default: 8080)",
            rich_help_panel="Web Dashboard",
        ),

):
    if ctx.invoked_subcommand is not None:
        return

    if not no_banner:
        banner()

    # ---------- load configuration ----------
    cfg = SnafflerConfiguration()

    if config_file:
        cfg.load_from_toml(str(config_file))

    # ---------- CLI → config (only override TOML when explicitly provided) ----------
    def _explicit(param: str) -> bool:
        """True if the CLI param was explicitly provided (not just the default)."""
        from click.core import ParameterSource
        return ctx.get_parameter_source(param) != ParameterSource.DEFAULT

    # ---------- AUTH ----------
    if _explicit("username"):     cfg.auth.username = username
    if _explicit("password"):     cfg.auth.password = password
    if _explicit("nthash"):       cfg.auth.nthash = nthash
    if _explicit("domain"):       cfg.auth.domain = domain
    if _explicit("dc_host"):      cfg.auth.dc_host = dc_host
    if _explicit("smb_timeout"):  cfg.auth.smb_timeout = smb_timeout
    if _explicit("kerberos"):     cfg.auth.kerberos = kerberos
    if _explicit("use_kcache"):   cfg.auth.use_kcache = use_kcache

    # ---------- TARGETING ----------
    if _explicit("unc_targets"):      cfg.targets.unc_targets = unc_targets or []
    if _explicit("local"):            cfg.targets.local_targets = local or []
    if _explicit("shares_only"):      cfg.targets.shares_only = shares_only
    if _explicit("include_disabled"): cfg.targets.skip_disabled_computers = not include_disabled
    if _explicit("rescan_unreadable"): cfg.targets.rescan_unreadable = rescan_unreadable
    if _explicit("share"):            cfg.targets.share_filter = share or []
    if _explicit("exclude_share"):    cfg.targets.exclude_share = exclude_share or []
    if _explicit("exclude_unc"):      cfg.targets.exclude_unc = exclude_unc or []

    if computer and computer_file:
        raise typer.BadParameter("Use either --computer or --computer-file, not both")

    if computer:
        from snaffler.utils.target_parser import expand_targets
        cfg.targets.computer_targets = expand_targets([h.upper() for h in computer])

    if computer_file:
        from snaffler.utils.target_parser import expand_targets
        raw = [l.strip().upper() for l in computer_file.read_text().splitlines() if l.strip()]
        cfg.targets.computer_targets = expand_targets(raw)

    if exclusions_file:
        cfg.targets.exclusions = [
            l.strip().upper() for l in exclusions_file.read_text().splitlines() if l.strip()
        ]

    if _explicit("max_hosts"):
        cfg.targets.max_hosts = max_hosts

    # ---------- GRAB MODE VALIDATION ----------
    if grab:
        if not snaffle_path:
            raise typer.BadParameter("--grab requires -m/--snaffle-path")
        if (cfg.targets.unc_targets or cfg.targets.computer_targets
                or cfg.targets.local_targets or cfg.auth.domain
                or cfg.targets.ftp_targets or stdin_mode
                or cfg.targets.rescan_unreadable):
            raise typer.BadParameter(
                "--grab is mutually exclusive with all other targeting modes"
            )

    # ---------- LOCAL TARGET VALIDATION ----------
    if cfg.targets.local_targets:
        if cfg.targets.unc_targets or cfg.targets.computer_targets or cfg.auth.domain or stdin_mode:
            raise typer.BadParameter(
                "--local-fs is mutually exclusive with --unc, --computer, --computer-file, --domain, and --stdin"
            )
        for lp in cfg.targets.local_targets:
            p = Path(lp)
            if not p.exists():
                raise typer.BadParameter(f"--local-fs path does not exist: {lp}")
            if not p.is_dir():
                raise typer.BadParameter(f"--local-fs path is not a directory: {lp}")

    # ---------- FTP TARGETS ----------
    if ftp and ftp_file:
        raise typer.BadParameter("Use either --ftp or --ftp-file, not both")

    def _normalize_ftp(raw_url: str) -> str:
        raw_url = raw_url.strip()
        if raw_url.startswith("ftp://"):
            return raw_url.rstrip("/") or raw_url
        return f"ftp://{raw_url}"

    if ftp:
        cfg.targets.ftp_targets = [_normalize_ftp(r) for r in ftp]
    if ftp_file:
        lines = [l.strip() for l in ftp_file.read_text().splitlines() if l.strip() and not l.strip().startswith("#")]
        cfg.targets.ftp_targets = [_normalize_ftp(r) for r in lines]
    if _explicit("ftp_tls"):
        cfg.targets.ftp_tls = ftp_tls

    if cfg.targets.ftp_targets:
        if cfg.targets.unc_targets or cfg.targets.computer_targets or cfg.targets.local_targets or cfg.auth.domain or stdin_mode:
            raise typer.BadParameter(
                "--ftp is mutually exclusive with --unc, --computer, --computer-file, --local-fs, --domain, and --stdin"
            )

    # ---------- STDIN (NXC) ----------
    if stdin_mode:
        if cfg.targets.unc_targets or cfg.targets.computer_targets or cfg.targets.local_targets or cfg.auth.domain:
            raise typer.BadParameter(
                "--stdin is mutually exclusive with --unc, --computer, --computer-file, --local-fs, and --domain"
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
    has_local = bool(cfg.targets.local_targets)
    has_computers = bool(cfg.targets.computer_targets)
    has_domain = bool(cfg.auth.domain)
    has_ftp = bool(cfg.targets.ftp_targets)

    # --rescan-unreadable is SMB-only, mutually exclusive with local/FTP
    if cfg.targets.rescan_unreadable and (has_local or has_ftp):
        raise typer.BadParameter(
            "--rescan-unreadable is mutually exclusive with --local-fs and --ftp"
        )

    # At least one targeting mode must be selected
    if not grab and not (has_unc or has_local or has_computers or has_domain or has_ftp
            or cfg.targets.rescan_unreadable):
        raise typer.BadParameter(
            "No targets specified. Use one of: "
            "--unc, --local-fs, --ftp, --computer/--computer-file, --stdin, --domain, "
            "--grab, or --rescan-unreadable"
        )
    # ---------- SCANNING ----------
    if _explicit("min_interest"):   cfg.scanning.min_interest = min_interest
    if _explicit("max_read_bytes"): cfg.scanning.max_read_bytes = max_read_bytes
    if _explicit("max_file_bytes"): cfg.scanning.max_file_bytes = max_file_bytes
    if _explicit("context"):        cfg.scanning.match_context_bytes = context
    if _explicit("max_depth"):      cfg.scanning.max_depth = max_depth

    if match_filter:
        import re
        try:
            re.compile(match_filter)
        except re.error as exc:
            raise typer.BadParameter(f"Invalid --match regex: {exc}")
        cfg.scanning.match_filter = match_filter

    if snaffle_path:
        cfg.scanning.snaffle = True
        cfg.scanning.snaffle_path = str(snaffle_path)

    # ---------- ADVANCED ----------
    if _explicit("max_threads"):  cfg.advanced.max_threads = max_threads
    if _explicit("dns_threads"):  cfg.advanced.dns_threads = dns_threads
    if _explicit("stealth"):      cfg.advanced.stealth = stealth

    per_bucket = max(1, cfg.advanced.max_threads // 3)
    cfg.advanced.share_threads = per_bucket
    cfg.advanced.tree_threads = per_bucket
    cfg.advanced.file_threads = per_bucket

    if _explicit("max_threads_per_share"):
        cfg.advanced.max_tree_threads_per_share = max_threads_per_share

    # ---------- --fast mode ----------
    if fast:
        from snaffler.config.configuration import FAST_MODE_EXCLUSIONS
        cfg.targets.exclude_unc = list(FAST_MODE_EXCLUSIONS) + cfg.targets.exclude_unc
        if not _explicit("max_threads_per_share"):
            cfg.advanced.max_tree_threads_per_share = max(2, per_bucket // 4)

    if _explicit("rule_dir"):
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

    # ---------- WEB DASHBOARD ----------
    if _explicit("web"):        cfg.web.enabled = web
    if _explicit("web_port"):   cfg.web.port = web_port
    if _explicit("web_port") and not cfg.web.enabled:
        typer.echo("Warning: --web-port has no effect without --web", err=True)

    # ---------- validate (errors caught by try/except below) ----------
    try:
        cfg.validate()
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)

    # ---------- logging (before rule loader so its messages are visible) ----------
    setup_logging(
        log_level=cfg.output.log_level,
        log_to_file=cfg.output.to_file,
        log_file_path=cfg.output.output_file,
        log_to_console=True,
        log_type=cfg.output.log_type,
    )

    # ---------- load classification rules ----------
    try:
        RuleLoader.load(cfg)
    except RuntimeError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)

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

    # ---------- grab mode ----------
    if grab:
        _run_grab(cfg)
        raise typer.Exit()

    # ---------- run ----------
    try:
        snaff = SnafflerRunner(cfg)
        snaff.execute()
    except KeyboardInterrupt:
        raise typer.Exit(code=130)
    except (ValueError, RuntimeError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)
    except OSError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)
    except SystemExit:
        raise  # let SystemExit (e.g. from check_fatal_os_error) propagate


if __name__ == "__main__":
    app()
