# snaffler-ng

Impacket port of [Snaffler](https://github.com/SnaffCon/Snaffler).

**snaffler-ng** is a post-exploitation / red teaming tool designed to **discover readable SMB shares**, **walk directory trees**, and **identify credentials and sensitive data** on Windows systems. Also works as an **FTP scanner**, a **local filesystem scanner**, and a **Python library** for integration into C2 frameworks and custom tooling.

## Features

- SMB share discovery via SRVSVC (NetShareEnum)
- DFS namespace discovery via LDAP (v1 + v2), merged and deduplicated with share enumeration
- **FTP server scanning** (`--ftp`) — scan FTP/FTPS servers with the same classification engine
- **Local filesystem scanning** (`--local-fs`) — same classification engine, no SMB required
- **Python library API** — two-phase classification for C2 integration, duck-typed transport
- Parallel directory tree walking with intra-share fan-out
- 103 built-in regex-based file and content classification rules
- NTLM authentication (password or pass-the-hash)
- Kerberos authentication (with ccache support)
- Multithreaded scanning (DNS / share / tree / file stages) with automatic thread rebalancing
- DNS pre-resolution with TCP port 445 probe to filter stale AD objects
- Archive peeking — scan filenames inside ZIP, 7z, and RAR archives without extraction
- Tree depth limiting (`--max-depth`)
- Finding post-filter (`--match`) — regex filter on findings by hostname, filename, rule, or content
- Host exclusion file (`--exclusions`)
- Optional file download ("snaffling")
- Resume support via SQLite state database (auto-resume on existing DB)
- Share and path filtering by glob pattern (`--share`, `--exclude-share`, `--exclude-unc` / `--exclude-path`)
- Compatible with original and custom TOML rule sets
- Deterministic, ingestion-friendly logging (plain / JSON / TSV)
- Custom DNS resolution (`--nameserver`) for internal AD hostname resolution through SOCKS tunnels
- SOCKS proxy pivoting (`--socks`)
- OPSEC mode (`--stealth`) — pads LDAP queries to break IDS signatures
- Live web dashboard (`--web`) for real-time scan monitoring
- `snaffler results` subcommand to query findings from a scan database (plain / JSON / HTML)
- Runtime hotkeys: press `d` for DEBUG, `i` for INFO during a scan
- Pipe-friendly: accepts NetExec (nxc) `--shares` output via `--stdin`

## Installation

### pip / pipx

```bash
pip install snaffler-ng
# or
pipx install snaffler-ng
```

Optional extras:

```bash
pip install snaffler-ng[socks]  # SOCKS proxy support
pip install snaffler-ng[web]    # Live web dashboard
pip install snaffler-ng[7z]     # 7-Zip archive peeking
pip install snaffler-ng[rar]    # RAR archive peeking
# pipx: use --pip-args
pipx install snaffler-ng --pip-args="[socks,web]"
```

### Standalone Binary

Pre-built single-file executables (no Python required) are attached to each [GitHub Release](https://github.com/totekuh/snaffler-ng/releases):

| Platform | File |
|----------|------|
| Linux x86_64 | `snaffler-linux-x86_64` |
| Linux aarch64 | `snaffler-linux-aarch64` |
| Windows x86_64 | `snaffler-windows-x86_64.exe` |

### Kali / Debian

```bash
sudo dpkg -i snaffler-ng_*.deb
```

## Quick Start

### Full Domain Discovery

Providing only a domain triggers full domain discovery:

```bash
snaffler \
  -u USERNAME \
  -p PASSWORD \
  -d DOMAIN.LOCAL
```

This will automatically:

- Query Active Directory for computer objects
- Discover DFS namespace targets via LDAP (v1 `fTDfs` + v2 `msDFS-Linkv2`)
- Resolve hostnames and probe port 445 reachability
- Enumerate SMB shares on discovered hosts
- Merge and deduplicate DFS and SMB share paths
- Scan all readable shares

When using Kerberos, set `KRB5CCNAME` to a valid ticket cache and use hostnames/FQDNs:

```bash
snaffler \
-k \
--use-kcache \
-d DOMAIN.LOCAL \
--dc-host CORP-DC02
```

---

### Targeted Scans

Scan a specific UNC path (no discovery):
```bash
snaffler \
  -u USERNAME \
  -p PASSWORD \
  --unc //192.168.1.10/Share
```

![snaffler-ng run](https://github.com/user-attachments/assets/4cd12508-88f3-4724-9a1e-6c5991cddafa)

Scan multiple computers (share discovery enabled):
```bash
snaffler \
  -u USERNAME \
  -p PASSWORD \
  --computer 192.168.1.10 \
  --computer 192.168.1.11
```

Load target computers from file:
```bash
snaffler \
  -u USERNAME \
  -p PASSWORD \
  --computer-file targets.txt
```

### Local Filesystem Scanning

Scan local directories without any SMB or network configuration:

```bash
snaffler --local-fs /mnt/share
snaffler --local-fs /tmp/extracted --local-fs /home/user/Documents
```

Uses the same classification engine, rules, and multithreaded pipeline as SMB mode — just reads from the local filesystem instead. Useful for:

- Scanning mounted NFS/CIFS shares
- Post-compromise triage of extracted filesystems
- Offline analysis of forensic images
- Testing rules against local data

`--local-fs` is mutually exclusive with `--unc`, `--ftp`, `--computer`, `--domain`, and `--stdin`.

---

### FTP Server Scanning

Scan FTP servers with the same classification engine — all 106 rules, content scanning, archive peeking, resume, and download work identically:

```bash
# Anonymous FTP
snaffler --ftp ftp://10.0.0.5

# With credentials
snaffler --ftp ftp://10.0.0.5 -u ftpuser -p ftppass

# Scan a specific directory on the server
snaffler --ftp ftp://10.0.0.5/Data/Shared

# Custom port
snaffler --ftp ftp://10.0.0.5:2121/backup

# Multiple FTP targets
snaffler --ftp ftp://10.0.0.5 --ftp ftp://10.0.0.6/docs

# FTPS (FTP over TLS)
snaffler --ftp ftp://10.0.0.5 --ftp-tls

# Combine with scanning flags
snaffler --ftp ftp://10.0.0.5 --max-depth 3 --match "password" --min-interest 2
```

Bare hostnames are accepted — `snaffler --ftp 10.0.0.5` is equivalent to `snaffler --ftp ftp://10.0.0.5`. Without `-u`/`-p`, anonymous login is attempted.

`--ftp` is mutually exclusive with `--unc`, `--local-fs`, `--computer`, `--domain`, and `--stdin`.

---

### Archive Peeking

snaffler-ng can look inside ZIP, 7z, and RAR archives without extracting files. Archive members are matched against file rules — if an archive contains `web.config` or `id_rsa`, it gets flagged:

```bash
# ZIP works out of the box. For 7z and RAR, install optional extras:
pip install snaffler-ng[7z,rar]
```

### Filtering Shares and Directories

Only scan specific shares:
```bash
snaffler -u USER -p PASS -d DOMAIN.LOCAL --share "SYSVOL" --share "IT*"
```

Exclude shares and paths by glob:
```bash
snaffler -u USER -p PASS -d DOMAIN.LOCAL \
  --exclude-share "IPC$" --exclude-share "print$" \
  --exclude-path "*/Windows/*" --exclude-path "*/.snapshot/*"

# --exclude-path (alias: --exclude-unc) works with --local-fs too
snaffler --local-fs /mnt/share --exclude-path "*/node_modules/*" --exclude-path "*/.git/*"
```

### Depth Limiting and Post-Filtering

Limit directory recursion depth to avoid deep trees:
```bash
snaffler -u USER -p PASS -d DOMAIN.LOCAL --max-depth 5
```

Filter findings by regex (matches against hostname, filename, rule name, or content):
```bash
snaffler -u USER -p PASS -d DOMAIN.LOCAL --match "password|connectionstring"
```

Exclude specific hosts from scanning:
```bash
snaffler -u USER -p PASS -d DOMAIN.LOCAL --exclusions hosts_to_skip.txt
```

### Pipe from NetExec (nxc)

Pipe `nxc smb --shares` output directly into snaffler-ng with `--stdin`:

```bash
nxc smb 10.8.50.20 -u user -p pass --shares | snaffler -u user -p pass --stdin
```

This parses NXC's share output, extracts UNC paths, and feeds them into the file scanner. Snaffler's existing share/directory rules handle filtering.

### Custom DNS Server

Use `--nameserver` (or `--ns`) to resolve hostnames through a specific DNS server instead of the system resolver. Useful for lab environments, split DNS, or any setup where the system resolver can't reach the target domain:

```bash
# Point at the DC for name resolution
snaffler -u USER -p PASS -d DOMAIN.LOCAL --dc-host 192.168.201.11 --ns 192.168.201.11

# Combine with SOCKS — DNS queries use TCP and route through the tunnel automatically
snaffler -u USER -p PASS -d DOMAIN.LOCAL --dc-host 192.168.201.11 \
  --socks socks5://127.0.0.1:1080 --ns 192.168.201.11
```

### Web Dashboard

Launch a live web dashboard to monitor scan progress and findings in a browser:

```bash
snaffler -u USER -p PASS -d DOMAIN.LOCAL --web --web-port 8080
```

Requires the `web` extra (`pip install snaffler-ng[web]`).

## Logging & Output Formats

snaffler-ng supports three output formats, each with a distinct purpose:

- `Plain` (default, human-readable)
- `JSON` (structured, SIEM-friendly)
- `TSV` (flat, ingestion-friendly)

When using `-o`/`--output`, the format is auto-detected from the file extension (`.json` → JSON, `.tsv` → TSV). Use `--log-type` to override.

## Resume Support

Large environments are expected. Scan state is tracked in a SQLite database (`snaffler.db` by default).

Scans **auto-resume** when the state database exists:

```bash
# First run — creates snaffler.db
snaffler -u USER -p PASS --computer-file targets.txt

# Interrupted? Just re-run the same command — it picks up where it left off
snaffler -u USER -p PASS --computer-file targets.txt
```

Use `--state` to specify a custom database path, or `--fresh` to ignore existing state and start clean:

```bash
snaffler -u USER -p PASS -d DOMAIN.LOCAL --state /tmp/scan1.db
snaffler -u USER -p PASS -d DOMAIN.LOCAL --fresh
```

## Querying Results

After a scan, use `snaffler results` to query findings from the state database:

```bash
snaffler results                              # plain text summary
snaffler results -f json                      # JSON output
snaffler results -f html > report.html        # HTML report with search bar
snaffler results -b 2                         # Red+ severity only
snaffler results -s /path/to/snaffler.db      # custom DB path
```

## Library API

snaffler-ng can be used as a Python library for integration into C2 frameworks, custom tooling, or automated pipelines.

### Walk a directory

```python
from snaffler import Snaffler

for finding in Snaffler().walk("/mnt/share"):
    print(f"[{finding.triage.label}] {finding.file_path}")
    if finding.match:
        print(f"  matched: {finding.match}")
```

### Two-phase classification (for C2 integration)

Minimize beacon traffic — most files are skipped at phase 1 (metadata-only, zero I/O):

```python
from snaffler import Snaffler
from snaffler.api import FileCheckStatus

s = Snaffler()

# Phase 1: metadata only — instant, no file read
check = s.check_file(path, size=4096, mtime_epoch=1700000000.0)

if check.status == FileCheckStatus.NEEDS_CONTENT:
    # Phase 2: only download + classify when needed
    result = s.scan_content(file_bytes, prior=check)

elif check.status == FileCheckStatus.MATCHED:
    result = check.result  # matched on filename alone (e.g. ntds.dit)
```

### Custom transport (duck-typed)

Plug in any transport — no ABC required, just implement `walk_directory` and `read`:

```python
class BeaconWalker:
    def walk_directory(self, path, on_file=None, on_dir=None, cancel=None):
        for entry in beacon.ls(path):
            if entry.is_dir:
                if on_dir: on_dir(entry.path)
            elif on_file:
                on_file(entry.path, entry.size, entry.mtime)
        return [e.path for e in beacon.ls(path) if e.is_dir]

class BeaconReader:
    def read(self, path, max_bytes=None):
        return beacon.download(path, max_bytes)

s = Snaffler(walker=BeaconWalker(), reader=BeaconReader())
for finding in s.walk("C:\\Users"):
    beacon.report(finding.file_path, finding.triage.label)
```

### Constructor parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `walker` | `LocalTreeWalker()` | Directory listing provider |
| `reader` | `LocalFileAccessor()` | File content reader |
| `rule_dir` | `None` | Custom TOML rules directory |
| `min_interest` | `0` | Minimum severity (0=all, 3=Black only) |
| `max_read_bytes` | `2MB` | Content scan byte limit |
| `match_context_bytes` | `200` | Context bytes around regex matches |
| `cert_passwords` | built-in list | Passwords to try on PKCS12 certs |
| `exclude_unc` | `None` | Glob patterns to skip directories (works on any path format) |
| `match_filter` | `None` | Regex post-filter on findings |
| `max_depth` | `None` | Maximum directory recursion depth |

## Authentication Options

- NTLM username/password
- NTLM pass-the-hash (`--hash`)
- Kerberos (`-k`)
- Kerberos via existing ccache (`--use-kcache`)
- SOCKS proxy pivoting (`--socks`)
- Custom DNS server (`--nameserver` / `--ns`)
