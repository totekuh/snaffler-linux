# Snaffler Linux

Linux port of [Snaffler](https://github.com/SnaffCon/Snaffler) using Impacket.

## Description

A tool for pentesters to find credentials and sensitive data on Windows shares from Linux. Discovers shares, walks file trees, and classifies files using regex rules.

## Quick Start

```bash
# Install
pip install -e .

# Scan specific share
snaffler -u AD_USERNAME -p AD_PASSWORD -i //192.168.1.10/Share -s

# Auto-discover shares on targets
snaffler -u AD_USERNAME -p AD_PASSWORD -n 192.168.1.10,192.168.1.11 -s -o results.log

# Use NT hash (pass-the-hash)
snaffler -u AD_USERNAME --hash NTHASH -d AD_DOMAIN -c DC_IP -s
```

## Key Options

- `-i/--unc` - Direct UNC paths (disables discovery)
- `-n/--computers` - Target computers (comma-sep or file)
- `-s/--stdout` / `-o/--output` - Output to stdout/file
- `-a/--shares-only` - Only enumerate shares
- `-b/--boring` - Interest threshold (0=all, 3=critical)
- `-m/--snaffle-path` - Auto-download files
- `-v/--verbose` - Log level: trace/debug/info/data

## How It Works

1. Discovers domain computers (optional) or uses provided targets
2. Enumerates readable SMB shares
3. Walks directory trees
4. Classifies files using built-in rules (or custom TOML rules)
5. Searches file contents for secrets (passwords, keys, tokens)



