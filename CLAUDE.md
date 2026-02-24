# snaffler-ng

Impacket port of [Snaffler](https://github.com/SnaffCon/Snaffler) — a post-exploitation / red-teaming tool that discovers readable SMB shares, walks directory trees, and identifies credentials and sensitive data on Windows systems.

## Project Overview

- **Language**: Python 3.9+
- **Package manager**: pip / setuptools
- **Entry point**: `snaffler.cli.main:app` (Typer CLI, registered as `snaffler` console script)
- **Version**: 1.1.2
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

CI runs on Python 3.11 via GitHub Actions (`.github/workflows/ci.yml`). Five jobs:
1. **test-build** — pytest + build Python package
2. **build-binary** — PyInstaller single ELF binary (Linux x86_64, ~23MB), smoke test (`--version`)
3. **build-binary-windows** — PyInstaller single `.exe` binary (Windows x86_64), smoke test (`--version`)
4. **build-deb** — `dpkg-buildpackage` Debian package with man page (uses `-d` flag on Ubuntu runners since `python3-typer` isn't in Ubuntu repos)
5. **release** — publishes pip package to PyPI + attaches Linux binary + Windows `.exe` + `.deb` to GitHub Release

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

DNS pre-resolution filters out stale AD computer objects with no A record before share enumeration. Uses `socket.getaddrinfo` (respects `--nameserver` monkey-patch and works through `--socks`). Resolved IPs stored in `target_computer.ip` column for resume. Returns hostnames (not IPs) for Kerberos SPN compatibility. Timeout: `smb_timeout` (default 5s) via scoped `socket.setdefaulttimeout`.

Orchestrated by `SnafflerRunner.execute()` which selects the entry point:
1. **UNC targets** (`--unc` or `--stdin`) → skip directly to FilePipeline
2. **Computer targets** (`--computer`) → DNS → SharePipeline → FilePipeline
3. **Domain discovery** (`-d`) → DomainPipeline → DNS → SharePipeline + DFS discovery → merge/dedup → FilePipeline

### Module Map

```
snaffler/
├── cli/main.py              # Typer CLI, option parsing, config assembly
│   ├── results.py           # `snaffler results` subcommand: stats/findings from scan DB (plain/json/html)
├── config/configuration.py  # Dataclass-based config (Auth/Targeting/Scanning/Output/Advanced/Rules/Resume)
├── engine/
│   ├── runner.py            # Top-level orchestrator (SnafflerRunner), DFS merge + dedup, 30s status thread
│   ├── domain_pipeline.py   # Domain → computer list + DFS targets via LDAP
│   ├── share_pipeline.py    # Computers → readable share UNC paths (ThreadPoolExecutor)
│   └── file_pipeline.py     # UNC paths → parallel tree walk → file scan (ThreadPoolExecutor, _BatchWriter)
├── discovery/
│   ├── ad.py                # ADDiscovery: LDAP queries for computers/users/DFS targets (paged)
│   ├── shares.py            # ShareFinder: SRVSVC share enumeration (listShares), readability checks
│   └── tree.py              # TreeWalker: SMB directory listing (non-recursive), parallel subtree walking
├── transport/
│   ├── smb.py               # SMBTransport: Impacket SMBConnection (NTLM + Kerberos)
│   ├── ldap.py              # LDAPTransport: Impacket LDAPConnection (NTLM + Kerberos)
│   ├── socks.py             # SOCKS proxy setup: PySocks monkey-patch, URL parsing (socks4/socks5)
│   ├── dns.py               # Custom DNS resolution: dnspython monkey-patch for --nameserver
├── classifiers/
│   ├── rules.py             # ClassifierRule dataclass, enums (Triage/MatchAction/MatchLocation/etc.), TOML loader
│   ├── default_rules.py     # 89 built-in rules in 27 categories (share/dir/file/content/relay/postmatch)
│   ├── evaluator.py         # RuleEvaluator: applies rules against FileContext
│   └── loader.py            # RuleLoader: loads default or custom TOML rules into config
├── analysis/
│   ├── file_scanner.py      # FileScanner: main scan logic (file rules → content rules → cert checks)
│   ├── certificates.py      # CertificateChecker: PEM/DER/PKCS12 parsing, private key detection
│   └── model/
│       ├── file_context.py  # FileContext: frozen dataclass (unc_path, name, ext, size, modified)
│       └── file_result.py   # FileResult: scan result with triage severity, pick_best() logic
├── accessors/
│   ├── file_accessor.py     # FileAccessor ABC (read, copy_to_local)
│   └── smb_file_accessor.py # SMBFileAccessor: thread-local SMB connection caching
├── resume/
│   └── scan_state.py        # ScanState + SQLiteStateStore: resume support via SQLite (WAL mode)
├── utils/
│   ├── logger.py            # Logging setup (plain/JSON/TSV formatters), colored output, finding IDs
│   ├── nxc_parser.py        # NetExec (nxc) SMB --shares output parser → UNC paths
│   ├── path_utils.py        # UNC path parsing, modified time extraction
│   ├── progress.py          # ProgressState: thread-safe counters, severity counts, format_status()
│   └── target_parser.py     # expand_targets(): CIDR/range expansion for --computer input
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

Thread-local SMB connection caching in `SMBFileAccessor`, `ShareFinder`, and `TreeWalker`.

FilePipeline uses `wait(FIRST_COMPLETED)` fan-out: each completed directory walk spawns sub-futures for discovered subdirectories, enabling intra-share parallel walking across tree threads.

### Resume Support

SQLite database (WAL mode, thread-safe with locks) tracks:
- `target_computer` — discovered hostnames + resolved IPs (`ip` column, NULL until resolved), `done` flag
- `target_share` — discovered share UNC paths, `done` flag
- `target_dir` — discovered directories, `walked` flag (marked after all entries listed)
- `target_file` — discovered files with share/size/mtime, `checked` flag

Phase flags in `sync` table: `computer_discovery_done`, `dns_resolution_done`, `share_discovery_done`. DNS resolution stores IPs incrementally; on interrupt the phase flag is NOT set, so only unresolved hosts are retried on resume. Directories are marked walked only after complete listing. Files are marked checked after scan attempt completes (regardless of result).

`_BatchWriter` daemon thread batches dir/file inserts (500 items or 1s interval) to reduce SQLite contention. On resume, unwalked dirs are re-scheduled and unchecked files from non-active shares are seeded into the scan queue.

### Authentication

Two auth paths, both in SMBTransport and LDAPTransport:
- **NTLM**: username/password or pass-the-hash (`--hash`)
- **Kerberos**: `-k` flag, optionally with ccache (`--use-kcache`, reads `KRB5CCNAME`)

### SOCKS Proxy Support

`--socks` flag routes all TCP connections through a SOCKS4/SOCKS5 proxy via PySocks global monkey-patch (`socket.socket = socks.socksocket`). Called once at startup in `cli/main.py` before any connections are created. Accepts `socks5://host:port`, `socks4://host:port`, `user:pass@host:port`, or bare `host:port` (defaults to SOCKS5). DNS resolution happens on the proxy side (`rdns=True`). PySocks is an optional dependency — `ImportError` with install instructions if missing.

### Custom DNS Resolution

`--nameserver` / `--ns` flag overrides system DNS by monkey-patching `socket.getaddrinfo` to resolve hostnames via a specified DNS server (typically the DC IP). Uses `dnspython` (already an impacket dependency — no new deps). DNS queries use TCP so they work through SOCKS tunnels (SOCKS only supports TCP, not UDP).

**Setup order matters**: SOCKS proxy is applied first, then the DNS monkey-patch, so DNS-over-TCP queries to an internal nameserver route through the tunnel. IP addresses and `None` hosts pass through to the original resolver unchanged. Falls back to the system resolver if the custom nameserver fails.

### Log Format Auto-Detection

When `-o`/`--output` is specified without an explicit `--log-type`, the format is auto-detected from the file extension: `.json` → JSON, `.tsv` → TSV, otherwise plain. Explicit `--log-type` always overrides auto-detection.

### UNC Path Format

Internal UNC paths use forward slashes: `//server/share/path/to/file`
SMB paths use backslashes: `\path\to\file`
Conversion happens in `path_utils.parse_unc_path()`.

## Testing

Unit tests in `tests/unit/` mirror the source structure. Test data files in `tests/data/` contain sample credential files, configs, and scripts for rule testing.

Integration tests in `tests/integration/` run the full pipeline with only the SMB transport mocked. The existing `tests/data/` directory (217 files, same ones unit tests use for rule-level assertions) is served as a fake SMB share. Integration tests verify pipeline wiring only — files go in, findings come out, progress counters update — not detection correctness. No network/root/Docker needed — works on any CI runner.

Key test directories:
- `test_classifiers/rules/` — individual rule category tests (12 files)
- `test_classifiers/` — evaluator logic, loader, rules dataclass
- `test_cli/` — CLI run, dual output (auto-format), stdin, HTML report rendering
- `test_discovery/` — share finder, tree walker, AD discovery
- `test_engine/` — pipeline and runner tests
- `test_transport/` — SMB, LDAP, SOCKS transport tests
- `test_utils/` — completion stats, nxc parser, progress, target parser
- `tests/integration/test_pipeline.py` — end-to-end pipeline wiring (share discovery → file scan → findings out)

## Code Conventions

- Logging via `logging.getLogger("snaffler")` (single logger namespace)
- Dataclasses for configuration and models
- ABC for `FileAccessor` interface
- Enums for all classification constants
- Type hints used throughout (Python 3.10+ union syntax `X | None` in some files)
- No async — uses `concurrent.futures.ThreadPoolExecutor`

### DFS Discovery

During domain discovery, `ADDiscovery.get_dfs_targets()` queries AD for DFS namespace objects using two LDAP queries:

- **DFS v1**: `(objectClass=fTDfs)` — parses `remoteServerName` multivalued attribute (backslash-delimited UNC paths, `*` terminator)
- **DFS v2**: `(|(objectClass=msDFS-Namespacev2)(objectClass=msDFS-Linkv2))` — parses `msDFS-TargetListv2` XML (namespace `http://schemas.microsoft.com/dfs/2007/03`)

Results are deduplicated across both queries, then merged case-insensitively with SharePipeline output in `SnafflerRunner.execute()` via `_deduplicate_paths()`. This catches shares on NAS appliances and cross-domain servers only reachable via DFS links.
