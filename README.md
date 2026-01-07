# snaffler-ng

Linux port of [Snaffler](https://github.com/SnaffCon/Snaffler) using Impacket.

Snaffler Linux is a post-exploitation / red teaming tool designed to **discover readable SMB shares**, **walk directory trees**, and **identify credentials and sensitive data** on Windows systems from Linux.

## Features

- SMB share discovery via RPC or SMB
- Recursive directory tree walking
- File and content classification using regex-based rules
- NTLM authentication (password or pass-the-hash)
- Multithreaded scanning
- Optional automatic file download (“snaffling”)
- Compatible with custom TOML rule sets

## Installation

```bash
pip install -e .
```


## Quick Start

Discover computers from Active Directory and scan their shares:
```bash
snaffler run \
  -u USERNAME \
  -p PASSWORD \
  -d DOMAIN.LOCAL
```

Scan a specific UNC path (no discovery):
```bash
snaffler run \
  -u USERNAME \
  -p PASSWORD \
  --unc //192.168.1.10/Share
```

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


