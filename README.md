# snaffler-ng

Impacket port of [Snaffler](https://github.com/SnaffCon/Snaffler).

**snaffler-ng** is a post-exploitation / red teaming tool designed to **discover readable SMB shares**, **walk directory trees**, and **identify credentials and sensitive data** on Windows systems.

## Features

- SMB share discovery via SRVSVC (NetShareEnum)
- DFS namespace discovery via LDAP (v1 + v2), merged and deduplicated with share enumeration
- Recursive directory tree walking
- Regex-based file and content classification
- NTLM authentication (password or pass-the-hash)
- Kerberos authentication
- Multithreaded scanning (share / tree / file stages)
- Optional file download (“snaffling”)
- Resume support via SQLite state database
- Compatible with original and custom TOML rule sets
- Deterministic, ingestion-friendly logging (plain / JSON / TSV)

## Installation

```bash
pip install snaffler-ng
```

## Quick Start

### Full Domain Discovery

Providing only a domain triggers full domain discovery:

```bash
snaffler run \
  -u USERNAME \
  -p PASSWORD \
  -d DOMAIN.LOCAL
```

This will automatically:

- Query Active Directory for computer objects
- Discover DFS namespace targets via LDAP (v1 `fTDfs` + v2 `msDFS-Linkv2`)
- Enumerate SMB shares on discovered hosts
- Merge and deduplicate DFS and SMB share paths
- Scan all readable shares

When using Kerberos, set `KRB5CCNAME` to a valid ticket cache and use hostnames/FQDNs:

```bash
snaffler run \
-k \
--use-kcache \
-d DOMAIN.LOCAL \
--dc-host CORP-DC02
```

---

### Targeted Scans

Scan a specific UNC path (no discovery):
```bash
snaffler run \
  -u USERNAME \
  -p PASSWORD \
  --unc //192.168.1.10/Share
```

![snaffler-ng run](https://github.com/user-attachments/assets/4cd12508-88f3-4724-9a1e-6c5991cddafa)

Scan multiple computers (share discovery enabled):
```bash
snaffler run \
  -u USERNAME \
  -p PASSWORD \
  --computer 192.168.1.10 \
  --computer 192.168.1.11
```

Load target computers from file:
```bash
snaffler run \
  -u USERNAME \
  -p PASSWORD \
  --computer-file targets.txt
```

## Logging & Output Formats

snaffler-ng supports three output formats, each with a distinct purpose:

- `Plain` (default, human-readable)
- `JSON` (structured, SIEM-friendly)
- `TSV` (flat, ingestion-friendly)

## Resume Support

Large environments are expected.

You can resume interrupted scans using the `--resume` argument:

```bash
snaffler run \
-u USERNAME \
-p PASSWORD \
--computer-file targets.txt \
--resume
```

State tracks processed shares, directories, and files to avoid re-scanning.

## Authentication Options

- NTLM username/password
- NTLM pass-the-hash (`--hash`)
- Kerberos (`-k`)
- Kerberos via existing ccache (`--use-kcache`)
