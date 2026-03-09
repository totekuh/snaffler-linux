# snaffler-ng

Impacket port of [Snaffler](https://github.com/SnaffCon/Snaffler) — a post-exploitation / red-teaming tool that discovers readable SMB shares, walks directory trees, and identifies credentials and sensitive data on Windows systems. Also works as a local filesystem scanner (`--local-fs`) and a Python library for C2 integration.

## Project Overview

- **Language**: Python 3.9+
- **Package manager**: pip / setuptools
- **Entry point**: `snaffler.cli.main:app` (Typer CLI, registered as `snaffler` console script)
- **Version**: 1.5.3
- **License**: Apache 2.0
- **Author**: totekuh

## Key Dependencies

| Package | Purpose |
|---------|---------|
| `impacket>=0.11.0` | SMB/LDAP/RPC transport, Kerberos, NTLM auth |
| `typer>=0.12.0` | CLI framework |
| `rich>=13.0.0` | Terminal output formatting |
| `tomlkit>=0.12.0` | TOML config/rule parsing (python3-tomlkit in Kali) |
| `cryptography` | Certificate parsing (PEM/DER/PKCS12) — transitive via impacket |
| `dnspython` | Custom DNS resolution for `--nameserver` — transitive via impacket |
| `pysocks>=1.7.0` | SOCKS proxy support (optional: `pip install snaffler-ng[socks]`) |
| `flask>=3.0.0` | Live web dashboard (optional: `pip install snaffler-ng[web]`) |
| `pytest>=8.0` | Testing (optional: `pip install snaffler-ng[test]`) |

## Build & Test

```bash
pip install -e .[test]   # install in dev mode with test deps
pytest                    # run all tests
pytest tests/unit/        # unit tests only
pytest tests/integration/ # integration tests only
```

### Single Binary (PyInstaller)

```bash
pip install pyinstaller
pyinstaller --onefile --name snaffler \
  --exclude-module matplotlib --exclude-module PyQt5 --exclude-module PyQt6 \
  --exclude-module PySide6 --exclude-module tkinter --exclude-module _tkinter \
  --exclude-module PIL --exclude-module numpy --exclude-module pygame \
  --exclude-module IPython --exclude-module pytest --exclude-module jedi \
  --exclude-module astroid --exclude-module impacket.examples.ntlmrelayx \
  --exclude-module impacket.examples.mssqlshell --exclude-module impacket.examples.ldap_shell \
  --exclude-module impacket.mqtt --exclude-module impacket.Dot11Crypto \
  --exclude-module impacket.Dot11KeyManager \
  snaffler/cli/main.py
```

Note: `_get_version()` in `cli/main.py` has a hardcoded fallback for frozen builds where `importlib.metadata` is unavailable. Keep pygments — rich needs it for syntax highlighting.

### CI Pipeline

CI runs on Python 3.11 via GitHub Actions (`.github/workflows/ci.yml`). Six jobs:
1. **test-build** — pytest + build Python package
2. **build-binary** — PyInstaller single ELF binary (Linux x86_64, ~23MB), smoke test (`--version`)
3. **build-binary-arm64** — PyInstaller single ELF binary (Linux aarch64), native ARM runner, smoke test (`--version`)
4. **build-binary-windows** — PyInstaller single `.exe` binary (Windows x86_64), smoke test (`--version`)
5. **build-deb** — `dpkg-buildpackage` Debian package with man page (uses `-d` flag on Ubuntu runners since `python3-typer` isn't in Ubuntu repos)
6. **release** — publishes pip package to PyPI + attaches Linux binaries (x86_64 + aarch64) + Windows `.exe` + `.deb` to GitHub Release

### Debian Packaging

`debian/` directory follows Kali conventions (`kali-dev` distribution, `0kali1` version suffix, `Kali Developers` maintainer). Built with `pybuild` + `pybuild-plugin-pyproject`. Man page installed via `snaffler-ng.manpages`. Autopkgtest runs `snaffler --help`.

## Architecture

### Pipeline Architecture (4-stage)

```
Domain Discovery → DNS Pre-Resolution → Share Discovery → File Scanning
     (LDAP)         (getaddrinfo)        (SRVSVC/SMB)     (SMB read + classify)
       ↓
  DFS Discovery ─────────────────────────────────┐
     (LDAP)                                      ↓
                                           Merge + Dedup → File Scanning
```

DNS pre-resolution filters out stale AD computer objects with no A record before share enumeration. Uses `socket.getaddrinfo` (respects `--nameserver` monkey-patch and works through `--socks`) followed by a TCP port 445 probe to confirm SMB reachability. Resolved IPs stored in `target_computer.ip` column for resume. Returns hostnames (not IPs) for Kerberos SPN compatibility. Port probe timeout: 3s (per-socket, thread-safe). DNS timeout is handled by the OS resolver or custom DNS monkey-patch (no process-global `setdefaulttimeout`). Individual `future.result()` exceptions are caught to prevent one failed host from aborting the entire loop. Concurrency controlled by `--dns-threads` (default 100).

Orchestrated by `SnafflerRunner.execute()` which selects the entry point:
1. **Rescan unreadable** (`--rescan-unreadable`) → load unreadable shares from state DB → re-test with current creds → newly readable → FilePipeline
2. **FTP targets** (`--ftp` / `--ftp-file`) → inject FTPTreeWalker + FTPFileAccessor → FilePipeline (no SMB)
3. **Local targets** (`--local-fs`) → inject LocalTreeWalker + LocalFileAccessor → FilePipeline (no SMB, no auth)
4. **UNC targets** (`--unc` or `--stdin`) → skip directly to FilePipeline
5. **Computer targets** (`--computer`) → DNS → SharePipeline → FilePipeline (hostnames used as-is, no CIDR/range expansion)
6. **Domain discovery** (`-d`) → DomainPipeline → DNS → SharePipeline + DFS discovery → merge/dedup → FilePipeline

`--local-fs`, `--ftp`, and `--rescan-unreadable` are mutually exclusive with each other. Auth validation is skipped for `--local-fs`. For `--ftp`, username defaults to "anonymous" if not provided. The `_extract_share_unc()` helper detects FTP URLs (`ftp://`) and uses `extract_ftp_root()` to group files by server. Non-UNC local paths (no `//` prefix) are returned unchanged as share keys for the resume DB.

### Module Map

```
snaffler/
├── cli/main.py              # Typer CLI, option parsing, config assembly
│   ├── results.py           # `snaffler results` subcommand: stats/findings from scan DB (plain/json/html)
├── api.py                   # Snaffler: high-level library API (walk, check_file, scan_content, check_dir)
├── config/configuration.py  # Dataclass-based config (Auth/Targeting/Scanning/Output/Advanced/Rules/Resume); local_targets for --local-fs, ftp_targets/ftp_tls for --ftp, rescan_unreadable for --rescan-unreadable
├── engine/
│   ├── runner.py            # Top-level orchestrator (SnafflerRunner), DFS merge + dedup, 30s status thread, thread rebalancing, _rescan_unreadable()
│   ├── domain_pipeline.py   # Domain → computer list + DFS targets via LDAP
│   ├── share_pipeline.py    # Computers → share UNC paths (ThreadPoolExecutor); stores all shares (readable + unreadable) with readable flag, returns only readable
│   └── file_pipeline.py     # UNC paths → parallel tree walk → file scan (ThreadPoolExecutor, _BatchWriter); DI for TreeWalker + FileAccessor
├── discovery/
│   ├── ad.py                # ADDiscovery: LDAP queries for computers/users/DFS targets (paged)
│   ├── shares.py            # ShareFinder: SRVSVC share enumeration (listShares), readability checks; get_computer_shares() returns ALL shares (readable + unreadable)
│   ├── tree.py              # TreeWalker ABC + should_scan_directory() shared function; abstract walk_directory()
│   ├── smb_tree_walker.py   # SMBTreeWalker(TreeWalker): Impacket SMB listPath, thread-local connection cache
│   ├── local_tree_walker.py # LocalTreeWalker(TreeWalker): os.scandir() based, used by Snaffler.walk()
│   └── ftp_tree_walker.py   # FTPTreeWalker(TreeWalker): ftplib MLSD/NLST, thread-local connection cache; parse_ftp_url(), build_ftp_url(), extract_ftp_root()
├── transport/
│   ├── smb.py               # SMBTransport: Impacket SMBConnection (NTLM + Kerberos)
│   ├── ldap.py              # LDAPTransport: Impacket LDAPConnection (NTLM + Kerberos)
│   ├── ftp.py               # FTPTransport: ftplib connection factory (plain + TLS), passive mode
│   ├── socks.py             # SOCKS proxy setup: PySocks monkey-patch, URL parsing (socks4/socks5)
│   ├── dns.py               # Custom DNS resolution: dnspython monkey-patch for --nameserver
├── classifiers/
│   ├── rules.py             # ClassifierRule dataclass, enums (Triage/MatchAction/MatchLocation/etc.), TOML loader
│   ├── default_rules.py     # 106 built-in rules in 32 categories (share/dir/file/content/relay/postmatch)
│   ├── evaluator.py         # RuleEvaluator: applies rules against FileContext
│   └── loader.py            # RuleLoader: loads default or custom TOML rules into config
├── analysis/
│   ├── file_scanner.py      # FileScanner: path-agnostic scan logic (file rules → content rules → cert checks → --match filter)
│   ├── certificates.py      # CertificateChecker: PEM/DER/PKCS12 parsing, private key detection
│   └── model/
│       ├── file_context.py  # FileContext: frozen dataclass (unc_path, name, ext, size, modified)
│       └── file_result.py   # FileResult: scan result with triage severity, pick_best() logic
├── accessors/
│   ├── file_accessor.py     # FileAccessor ABC: read(file_path) → bytes, copy_to_local(file_path, dest_root)
│   ├── smb_file_accessor.py # SMBFileAccessor(FileAccessor): UNC path parsing, thread-local SMB connection caching
│   ├── local_file_accessor.py # LocalFileAccessor(FileAccessor): open() + shutil.copy2, used by Snaffler.walk()
│   └── ftp_file_accessor.py # FTPFileAccessor(FileAccessor): ftplib retrbinary, thread-local connection cache
├── resume/
│   └── scan_state.py        # ScanState + SQLiteStateStore: resume support via SQLite (WAL mode)
├── utils/
│   ├── hotkeys.py           # Runtime hotkey listener: d=DEBUG, i=INFO (TTY only)
│   ├── logger.py            # Logging setup (plain/JSON/TSV formatters), colored output, finding IDs
│   ├── nxc_parser.py        # NetExec (nxc) SMB --shares output parser → UNC paths
│   ├── path_utils.py        # UNC path parsing, modified time extraction
│   ├── progress.py          # ProgressState: thread-safe counters, severity counts, scan_complete flag, snapshot(), format_status()
│   └── target_parser.py     # expand_targets(): CIDR/range expansion (used for --unc input)
├── web/
│   ├── server.py            # Flask app + daemon thread launcher (--web), REST API endpoints
│   └── dashboard.py         # Self-contained live HTML dashboard (polling, dark theme)
└── rules/
    └── example_custom_rule.toml  # Example custom TOML rule file
```

### Classification System

Rules are evaluated in a specific order with these **actions**:
- `Discard` — skip the file/share/directory entirely
- `Snaffle` — report as finding (and optionally download)
- `Relay` — match file by name/extension, then apply specified content rules
- `CheckForKeys` — parse as certificate, check for private keys
- `SendToNextScope` — pass to next evaluation stage

**Triage severity levels** (highest first):
- `Black` (3) — Critical: credentials, private keys, hash dumps
- `Red` (2) — High: config files with secrets, connection strings
- `Yellow` (1) — Medium: potentially interesting files
- `Green` (0) — Low: mildly interesting

**Rule scopes** (evaluation order):
1. `ShareEnumeration` — applied during share discovery
2. `DirectoryEnumeration` — applied during tree walking
3. `FileEnumeration` — applied during file scanning (name/ext/path matching)
4. `ContentsEnumeration` — applied to file content (regex-based)
5. `PostMatch` — false-positive filtering after a match

### Threading Model

Total threads split into 3 equal buckets (default 60 total, 20 each):
- `share_threads` — SharePipeline (ThreadPoolExecutor)
- `tree_threads` — TreeWalker in FilePipeline
- `file_threads` — FileScanner in FilePipeline
- `dns_threads` — DNS + port 445 probes (default 100, configurable via `--dns-threads`)

After share discovery completes, `_rebalance_file_threads()` adds the idle share threads to the file scanning pool.

Thread-local SMB connection caching in `SMBFileAccessor`, `ShareFinder`, and `SMBTreeWalker`.

FilePipeline uses `wait(FIRST_COMPLETED)` fan-out: each completed directory walk spawns sub-futures for discovered subdirectories, enabling intra-share parallel walking across tree threads. Share completion is tracked per-share via `share_pending` counters. When all futures for a share complete, `shares_walked` increments (for progress display) regardless of errors. Only error-free shares are marked done in the resume DB (`mark_share_done`) — shares with any walk errors have their failed directories retried on resume.

### Resume Support

SQLite database (WAL mode, thread-safe with locks) tracks:
- `target_computer` — discovered hostnames + resolved IPs (`ip` column, NULL until resolved), `done` flag
- `target_share` — discovered share UNC paths, `readable` flag (1=readable, 0=unreadable, NULL=legacy/unknown), `done` flag
- `target_dir` — discovered directories, `walked` flag (marked after all entries listed)
- `target_file` — discovered files with share/size/mtime, `checked` flag

`store_shares()` accepts both plain strings (readable=NULL, backwards compat) and `(unc_path, readable)` tuples. `load_shares()` returns shares where `readable=1` or `readable=NULL` (backwards compat). `load_unreadable_shares()` returns only `readable=0`. `update_share_readable()` sets `readable=1` for a given UNC path.

Phase flags in `sync` table: `computer_discovery_done`, `dns_resolution_done`, `share_discovery_done`. DNS resolution stores IPs incrementally; on interrupt the phase flag is NOT set, so only unresolved hosts are retried on resume. Directories are marked walked only after complete listing. Files are marked checked after scan attempt completes (regardless of result).

`_BatchWriter` daemon thread batches dir/file inserts (500 items or 1s interval) to reduce SQLite contention. On resume, unwalked dirs are re-scheduled and unchecked files from non-active shares are seeded into the scan queue. Finding counts (files_matched, severity counters) are restored from the `finding` table via `count_findings_by_triage()` in `_sync_progress_from_state()`.

### Authentication

Two auth paths, both in SMBTransport and LDAPTransport:
- **NTLM**: username/password or pass-the-hash (`--hash`)
- **Kerberos**: `-k` flag, optionally with ccache (`--use-kcache`, reads `KRB5CCNAME`)

### SOCKS Proxy Support

`--socks` flag routes all TCP connections through a SOCKS4/SOCKS5 proxy via PySocks global monkey-patch (`socket.socket = socks.socksocket`). Called once at startup in `cli/main.py` before any connections are created. Accepts `socks5://host:port`, `socks4://host:port`, `user:pass@host:port`, or bare `host:port` (defaults to SOCKS5). DNS resolution happens on the proxy side (`rdns=True`). PySocks is an optional dependency — `ImportError` with install instructions if missing.

### Custom DNS Resolution

`--nameserver` / `--ns` flag overrides system DNS by monkey-patching `socket.getaddrinfo` to resolve hostnames via a specified DNS server (typically the DC IP). Uses `dnspython` (already an impacket dependency — no new deps). DNS queries use TCP so they work through SOCKS tunnels (SOCKS only supports TCP, not UDP).

**Setup order matters**: SOCKS proxy is applied first, then the DNS monkey-patch, so DNS-over-TCP queries to an internal nameserver route through the tunnel. IP addresses and `None` hosts pass through to the original resolver unchanged. Falls back to the system resolver if the custom nameserver fails.

### Path Exclusion

`--exclude-unc` (aliased as `--exclude-path`) accepts glob patterns (repeatable) to skip directories during tree walking. Patterns are matched against the full path (case-insensitive), e.g. `*/Windows/*`, `*/node_modules/*`. Applied to both share roots (in `FilePipeline.run()`) and subdirectories (in `TreeWalker._should_scan_directory()`). Works with UNC, local, and FTP paths. Stored in `config.targets.exclude_unc` as a list of strings. Also available as `exclude_unc` parameter in the library API `Snaffler` constructor.

### Finding Post-Filter

`--match` accepts a regex pattern to fully suppress non-matching findings. Applied in `FileScanner._finalize_result()` right after the `--min-interest` severity check. Non-matching findings are not logged, not written to the finding store (DB), not downloaded, and `_finalize_result` returns `None`. The regex is matched case-insensitively against a newline-joined concatenation of `file_path`, `rule_name`, `match`, and `context` — so it works for filtering by hostname, filename, rule name, or matched content. Compiled once in `FileScanner.__init__`, stored as `self._match_re`. Config field: `cfg.scanning.match_filter` (string or None).

### Host Exclusion

`--exclusions` accepts a file of hostnames/IPs (one per line) to skip entirely. In computer mode, excluded hosts never reach DNS resolution or share discovery. In UNC mode, UNC paths with excluded hostnames are filtered out before file scanning. Has no effect in `--local-fs` mode (warns at runtime). Stored in `config.targets.exclusions` as a list of uppercase strings.

### Rescan Unreadable Shares

`--rescan-unreadable` enables credential diff mode: re-test previously access-denied shares from the state DB with current credentials (e.g., after password spraying yields new creds). Workflow:

1. Initial scan with low-privilege creds discovers shares — all are stored in `target_share` with `readable` flag (1 or 0)
2. Later, run with `--rescan-unreadable` + new creds + same `--state-file` — loads `readable=0` shares, applies `--share`/`--exclude-share` and `--exclusions` filters, re-tests each via `ShareFinder.is_share_readable()` using `ThreadPoolExecutor` (parallel, `share_threads` workers), updates DB flag on success, passes newly readable shares to `FilePipeline.run()`

Per-share exception handling ensures one connection failure doesn't abort the entire rescan. Errors are tracked separately from "still denied" in the summary log. Mutually exclusive with `--local-fs` and `--ftp`. When combined with `--unc`/`--computer`/`--domain`, a warning is logged and the rescan takes priority. Implementation in `SnafflerRunner._rescan_unreadable()`.

### Runtime Hotkeys

When stdin is a TTY, a background thread listens for single keystrokes during a scan:
- `d` — switch log level to DEBUG
- `i` — switch log level to INFO

Implemented in `utils/hotkeys.py`, started/stopped by the runner.

### Log Format Auto-Detection

When `-o`/`--output` is specified without an explicit `--log-type`, the format is auto-detected from the file extension: `.json` → JSON, `.tsv` → TSV, otherwise plain. Explicit `--log-type` always overrides auto-detection.

### UNC Path Format

Internal UNC paths use forward slashes: `//server/share/path/to/file`
SMB paths use backslashes: `\path\to\file`
Conversion happens in `path_utils.parse_unc_path()`.

## Testing

Unit tests in `tests/unit/` mirror the source structure. Test data files in `tests/data/` contain sample credential files, configs, and scripts for rule testing.

Integration tests in `tests/integration/` run the full pipeline with only the SMB transport mocked. The existing `tests/data/` directory (270 files, same ones unit tests use for rule-level assertions) is served as a fake SMB share. Integration tests verify pipeline wiring only — files go in, findings come out, progress counters update — not detection correctness. No network/root/Docker needed — works on any CI runner.

Key test directories:
- `test_accessors/` — file accessor ABC, SMB file accessor, FTP file accessor
- `test_analysis/` — file scanner, certificate checker
- `test_classifiers/rules/` — individual rule category tests (21 files)
- `test_classifiers/` — evaluator logic, loader, rules dataclass
- `test_cli/` — CLI run (flags, aliases, exclusions), dual output (auto-format), stdin, HTML report rendering, results subcommand
- `test_config/` — configuration dataclass
- `test_discovery/` — share finder, tree walker, AD discovery, FTP tree walker
- `test_engine/` — file pipeline (45 tests: fan-out, resume, max-depth, share error tracking, progress), runner (incl. rescan-unreadable tests), graceful shutdown
- `test_resume/` — scan state, SQLite state store
- `test_transport/` — SMB, LDAP, SOCKS, FTP transport tests
- `test_utils/` — hotkeys, nxc parser, progress, target parser
- `test_web/` — Flask web dashboard and REST API
- `tests/integration/test_pipeline.py` — end-to-end pipeline wiring (share discovery → file scan → findings out), SMB mocked (54 tests)
- `tests/integration/test_walk.py` — Snaffler.walk() library API against real local filesystem (tests/data/), zero mocking (89 tests)
- `tests/integration/test_local_runner.py` — SnafflerRunner.execute() with `--local-fs` against real filesystem, all flags tested with positive and negative cases; also includes `TestRescanUnreadable` (47 tests)
- `tests/integration/test_ftp.py` — FTP scanning with real pyftpdlib server (anonymous + authenticated, subpath, resume, flags, library API) (30 tests)

## Code Conventions

- Logging via `logging.getLogger("snaffler")` (single logger namespace)
- Dataclasses for configuration and models
- ABCs for transport interfaces: `FileAccessor` (read/copy) and `TreeWalker` (directory listing); SMB implementations in `SMBFileAccessor` and `SMBTreeWalker`; local FS implementations in `LocalFileAccessor` and `LocalTreeWalker`; FTP implementations in `FTPFileAccessor` and `FTPTreeWalker`
- `TreeWalker` ABC accepts `dir_rules` + `exclude_unc` directly (no `SnafflerConfiguration` dependency). `SMBTreeWalker` extracts these from cfg; `LocalTreeWalker` accepts them as constructor params.
- `Snaffler` (library API) accepts duck-typed `walker`/`reader` — defaults to local FS implementations
- `FilePipeline` (CLI pipeline) accepts injected `TreeWalker` and `FileAccessor` — defaults to SMB implementations
- `FileScanner` is path-format agnostic — works with any path string (UNC, local, etc.), uses `os.path` for name/ext extraction
- Enums for all classification constants
- Type hints used throughout (Python 3.10+ union syntax `X | None` in some files)
- No async — uses `concurrent.futures.ThreadPoolExecutor`

### Shared Classification Engine

The CLI runner and library API share 100% of the classification code — only transport and orchestration differ:

| Shared component | Used by |
|---|---|
| `should_scan_directory()` (`tree.py`) | `TreeWalker._should_scan_directory()` + `Snaffler._check_dir()` |
| `FileScanner.check_file()` | `scan_file()` (CLI) + `_scan_one()` (API) |
| `FileScanner.scan_with_data()` | Both |
| `FileScanner._evaluate_content()` | Both |
| `FileScanner._evaluate_certificate()` | Both |
| `FileScanner._evaluate_archive()` | Both |
| `RuleEvaluator` (all methods) | Both |
| `CertificateChecker` | Both |
| `DEFAULT_CERT_PASSWORDS` (`config/configuration.py`) | `ScanningConfig` + `Snaffler` constructor |

What differs by design:

| Dimension | CLI (`FilePipeline`) | Library (`Snaffler`) |
|---|---|---|
| Orchestration | ThreadPoolExecutor + queue | Single-threaded stack DFS |
| Transport | SMBTreeWalker + SMBFileAccessor (or Local via `--local-fs`, or FTP via `--ftp`) | LocalTreeWalker + LocalFileAccessor (or duck-typed) |
| Config | `SnafflerConfiguration` dataclass | `SimpleNamespace` shim |
| Output | `_finalize_result()` — logs + downloads | `_apply_filters()` — filter only, caller owns output |
| Resume | SQLite state + BatchWriter | None (stateless) |

### Library API (`snaffler.api`)

`Snaffler` class (aliased as `SnafflerEngine` for backwards compat) provides a transport-agnostic classification engine. Two usage modes:

**High-level — `walk()` generator:**

```python
from snaffler import Snaffler

s = Snaffler()
for finding in s.walk("/mnt/share"):
    print(f"[{finding.triage.label}] {finding.file_path}")
```

Single-threaded, stack-based DFS. Uses injected `walker` and `reader` for I/O. Yields `FileResult` findings.

**Low-level — two-phase check:**

```python
check = s.check_file(path, size, mtime_epoch)   # Phase 1: metadata-only (zero I/O)
if check.status == FileCheckStatus.NEEDS_CONTENT:
    result = s.scan_content(data, prior=check)   # Phase 2: content classification
```

**Pluggable transport** for C2 integration — duck typing, no ABC required:

```python
s = Snaffler(walker=BeaconWalker(beacon), reader=BeaconReader(beacon))
```

Walker contract: `walk_directory(path, on_file=None, on_dir=None, cancel=None) → list[str]`
- `on_file(path, size, mtime_epoch)` callback for each file
- Returns list of subdirectory paths

Reader contract: `read(path, max_bytes=None) → bytes | None`

Built-in implementations: `LocalTreeWalker` (os.scandir), `LocalFileAccessor` (open), `SMBTreeWalker` (impacket), `SMBFileAccessor` (impacket).

Constructor params: `walker`, `reader`, `rule_dir`, `min_interest`, `max_read_bytes`, `match_context_bytes`, `cert_passwords`, `exclude_unc`, `match_filter`, `max_depth`.

Methods: `walk(root_dir)`, `check_dir(path)`, `check_file(path, size, mtime)`, `scan_content(data, prior=...)`, `check_certificate(...)`, `peek_archive(...)`.

### DFS Discovery

During domain discovery, `ADDiscovery.get_dfs_targets()` queries AD for DFS namespace objects using two LDAP queries:

- **DFS v1**: `(objectClass=fTDfs)` — parses `remoteServerName` multivalued attribute (backslash-delimited UNC paths, `*` terminator)
- **DFS v2**: `(|(objectClass=msDFS-Namespacev2)(objectClass=msDFS-Linkv2))` — parses `msDFS-TargetListv2` XML (namespace `http://schemas.microsoft.com/dfs/2007/03`)

Results are deduplicated across both queries, then merged case-insensitively with SharePipeline output in `SnafflerRunner.execute()` via `_deduplicate_paths()`. This catches shares on NAS appliances and cross-domain servers only reachable via DFS links.
