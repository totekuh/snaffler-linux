# snaffler-ng

Impacket port of [Snaffler](https://github.com/SnaffCon/Snaffler).

**snaffler-ng** is a post-exploitation / red teaming tool designed to **discover readable SMB shares**, **walk directory trees**, and **identify credentials and sensitive data** on Windows systems.

## Features

- SMB share discovery via SRVSVC (NetShareEnum)
- DFS namespace discovery via LDAP (v1 + v2), merged and deduplicated with share enumeration
- Parallel directory tree walking with intra-share fan-out
- 103 built-in regex-based file and content classification rules
- NTLM authentication (password or pass-the-hash)
- Kerberos authentication (with ccache support)
- Multithreaded scanning (DNS / share / tree / file stages) with automatic thread rebalancing
- DNS pre-resolution with TCP port 445 probe to filter stale AD objects
- Optional file download ("snaffling")
- Resume support via SQLite state database (auto-resume on existing DB)
- Share and directory filtering by glob pattern (`--share`, `--exclude-share`, `--exclude-dir`)
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

### pip

```bash
pip install snaffler-ng
```

Optional extras:

```bash
pip install snaffler-ng[socks]  # SOCKS proxy support
pip install snaffler-ng[web]    # Live web dashboard
```

### Standalone Binary

Pre-built single-file executables (no Python required) are attached to each [GitHub Release](https://github.com/totekuh/snaffler-ng/releases):

| Platform | File |
|----------|------|
| Linux x86_64 | `snaffler-linux-x86_64` |
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

### Filtering Shares and Directories

Only scan specific shares:
```bash
snaffler -u USER -p PASS -d DOMAIN.LOCAL --share "SYSVOL" --share "IT*"
```

Exclude shares and directories by glob:
```bash
snaffler -u USER -p PASS -d DOMAIN.LOCAL \
  --exclude-share "IPC$" --exclude-share "print$" \
  --exclude-dir "Windows" --exclude-dir ".snapshot"
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

## Authentication Options

- NTLM username/password
- NTLM pass-the-hash (`--hash`)
- Kerberos (`-k`)
- Kerberos via existing ccache (`--use-kcache`)
- SOCKS proxy pivoting (`--socks`)
- Custom DNS server (`--nameserver` / `--ns`)
