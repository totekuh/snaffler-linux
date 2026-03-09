# snaffler-ng

Impacket port of [Snaffler](https://github.com/SnaffCon/Snaffler).

**snaffler-ng** is a post-exploitation tool that discovers readable SMB shares, walks directory trees, and identifies credentials and sensitive data on Windows networks. Also scans FTP servers, local filesystems, and works as a Python library for C2 integration.

## Install

```bash
pip install snaffler-ng
# or
pipx install snaffler-ng
```

Pre-built binaries (no Python required) are available on the [Releases](https://github.com/totekuh/snaffler-ng/releases) page for Linux x86_64, Linux aarch64, and Windows x86_64. Debian/Kali: `sudo dpkg -i snaffler-ng_*.deb`.

Optional extras:

```bash
pip install snaffler-ng[socks]      # SOCKS proxy support
pip install snaffler-ng[web]        # live web dashboard
pip install snaffler-ng[7z,rar]     # 7z/RAR archive peeking
```

## Quick Start

```bash
# Full domain discovery — finds computers, resolves DNS, enumerates shares, scans everything
snaffler -u USER -p PASS -d DOMAIN.LOCAL

# Kerberos with ccache
snaffler -k --use-kcache -d DOMAIN.LOCAL --dc-host CORP-DC02

# Scan specific UNC paths
snaffler -u USER -p PASS --unc //10.0.0.5/Share --unc //10.0.0.6/Data

# Scan specific computers (share discovery enabled)
snaffler -u USER -p PASS --computer 10.0.0.5 --computer 10.0.0.6

# Local filesystem (no auth needed)
snaffler --local-fs /mnt/share

# FTP server (anonymous)
snaffler --ftp ftp://10.0.0.5
```

![snaffler-ng run](https://github.com/user-attachments/assets/4cd12508-88f3-4724-9a1e-6c5991cddafa)

## Targeting Modes

### Domain Discovery (`-d`)

Queries AD for computers + DFS namespaces, resolves DNS, probes port 445, enumerates shares, then scans:

```bash
snaffler -u USER -p PASS -d DOMAIN.LOCAL
snaffler -u USER -p PASS -d DOMAIN.LOCAL --max-hosts 50   # cap at 50 hosts
snaffler -u USER -p PASS -d DOMAIN.LOCAL --shares-only    # enumerate shares without scanning
```

### Computer List (`--computer` / `--computer-file`)

Skip LDAP discovery, target specific hosts:

```bash
snaffler -u USER -p PASS --computer 10.0.0.5 --computer 10.0.0.6
snaffler -u USER -p PASS --computer-file targets.txt
```

### UNC Paths (`--unc`)

Skip share discovery, scan specific paths directly:

```bash
snaffler -u USER -p PASS --unc //10.0.0.5/Share --unc //10.0.0.6/IT
```

### Pipe from NetExec (`--stdin`)

```bash
nxc smb 10.0.0.0/24 -u user -p pass --shares | snaffler -u user -p pass --stdin
```

### FTP Servers (`--ftp` / `--ftp-file`)

Same classification engine, all 106 rules, content scanning, resume, and download:

```bash
snaffler --ftp ftp://10.0.0.5                                # anonymous
snaffler --ftp ftp://10.0.0.5/Data -u ftpuser -p ftppass     # with creds + subpath
snaffler --ftp ftp://10.0.0.5:2121 --ftp-tls                 # custom port + TLS
snaffler --ftp-file ftp_targets.txt -u ftpuser -p ftppass     # load from file
```

Bare hostnames accepted: `--ftp 10.0.0.5` becomes `ftp://10.0.0.5`. Without `-u`/`-p`, anonymous login is attempted.

### Local Filesystem (`--local-fs`)

No network, no auth — useful for mounted shares, extracted filesystems, or testing rules:

```bash
snaffler --local-fs /mnt/share
snaffler --local-fs /tmp/extracted --local-fs /home/user/Documents
```

### Rescan Unreadable Shares (`--rescan-unreadable`)

Re-test previously access-denied shares with new credentials — useful after password spraying:

```bash
# Initial scan with low-privilege creds
snaffler -u lowpriv -p 'Password1' -d CORP.LOCAL --state scan.db

# Later, with higher-privilege creds
snaffler --rescan-unreadable -u highpriv -p 'NewPass!' --state scan.db
```

The initial scan stores all discovered shares (readable and unreadable) in the state DB. `--rescan-unreadable` loads only the previously denied shares, re-tests them with current credentials, and scans any that are now accessible. Respects `--share`, `--exclude-share`, and `--exclusions` filters.

## Filtering

```bash
# Only scan specific shares
snaffler ... --share "SYSVOL" --share "IT*"

# Exclude shares
snaffler ... --exclude-share "IPC$" --exclude-share "print$"

# Exclude paths (glob, works with all modes)
snaffler ... --exclude-path "*/Windows/*" --exclude-path "*/.snapshot/*"

# Limit directory recursion depth
snaffler ... --max-depth 5

# Regex post-filter on findings (matches path, rule name, content)
snaffler ... --match "password|connectionstring"

# Skip specific hosts
snaffler ... --exclusions hosts_to_skip.txt

# Stop after N hosts
snaffler ... --max-hosts 50
```

## Output

### Formats

Three output formats: **plain** (default), **JSON**, **TSV**. Auto-detected from `-o` file extension:

```bash
snaffler ... -o findings.json    # JSON
snaffler ... -o findings.tsv     # TSV
snaffler ... -o findings.txt     # plain
snaffler ... -o out.log -t json  # explicit override
```

### Resume

Scan state is tracked in SQLite (`snaffler.db`). Scans auto-resume when the DB exists:

```bash
snaffler -u USER -p PASS -d DOMAIN.LOCAL              # creates snaffler.db
# interrupted? re-run the same command — picks up where it left off
snaffler -u USER -p PASS -d DOMAIN.LOCAL              # resumes

snaffler ... --state /tmp/scan1.db                     # custom DB path
snaffler ... --fresh                                   # ignore existing state
```

### Querying Results

```bash
snaffler results                              # plain text summary
snaffler results -f json                      # JSON
snaffler results -f html > report.html        # self-contained HTML report
snaffler results -b 2                         # Red+ severity only
snaffler results -s /path/to/snaffler.db      # custom DB path
```

### Web Dashboard

Live browser dashboard for monitoring scan progress and findings:

```bash
snaffler ... --web --web-port 8080
```

Requires `pip install snaffler-ng[web]`.

### Archive Peeking

Scans filenames inside ZIP, 7z, and RAR archives without extraction:

```bash
pip install snaffler-ng[7z,rar]   # ZIP works out of the box
```

## Authentication & Network

| Flag | Description |
|------|-------------|
| `-u` / `-p` | NTLM username/password |
| `--hash` | NTLM pass-the-hash |
| `-k` | Kerberos authentication |
| `--use-kcache` | Kerberos via existing ccache (`KRB5CCNAME`) |
| `--socks` | SOCKS proxy pivoting (`socks5://127.0.0.1:1080`) |
| `--nameserver` / `--ns` | Custom DNS server (uses TCP, works through SOCKS) |
| `--dc-host` | Domain controller hostname or IP |
| `--stealth` | OPSEC mode: pad LDAP queries to break IDS signatures |

```bash
# SOCKS + custom DNS through tunnel
snaffler -u USER -p PASS -d DOMAIN.LOCAL \
  --socks socks5://127.0.0.1:1080 --ns 192.168.201.11 --dc-host 192.168.201.11
```

### Runtime Hotkeys

During a scan, press `d` for DEBUG output, `i` to switch back to INFO.

## Library API

### Walk a directory

```python
from snaffler import Snaffler

for finding in Snaffler().walk("/mnt/share"):
    print(f"[{finding.triage.label}] {finding.file_path}")
    if finding.match:
        print(f"  matched: {finding.match}")
```

### Two-phase classification (C2 integration)

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
| `exclude_unc` | `None` | Glob patterns to skip directories |
| `match_filter` | `None` | Regex post-filter on findings |
| `max_depth` | `None` | Maximum directory recursion depth |
