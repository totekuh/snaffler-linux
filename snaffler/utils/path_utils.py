#!/usr/bin/env python3
from datetime import datetime
from pathlib import Path
from typing import Optional


def parse_unc_path(unc_path: str):
    parts = [p for p in unc_path.split("/") if p]
    if len(parts) < 3:
        return None

    server, share = parts[0], parts[1]
    smb_path = "\\" + "\\".join(parts[2:])

    p = Path(unc_path)
    file_name = p.name
    ext = p.suffix  # may be ""

    return server, share, smb_path, file_name, ext


def extract_unc_host(path: str) -> Optional[str]:
    """Extract hostname from ``//server/share/...`` path.

    Returns ``None`` for non-UNC paths (no ``//`` prefix) or malformed paths.
    """
    if not path.startswith("//"):
        return None
    parts = path.strip("/").split("/")
    return parts[0] if parts else None


def extract_unc_share_name(path: str) -> Optional[str]:
    """Extract share name from ``//server/share/...`` path.

    Returns ``None`` for non-UNC paths or paths with fewer than two components.
    """
    if not path.startswith("//"):
        return None
    parts = path.strip("/").split("/")
    return parts[1] if len(parts) >= 2 else None


def extract_share_root(path: str) -> str:
    """Extract ``//server/share`` (or ``ftp://host:port``) as share key.

    For FTP URLs returns ``ftp://host:port``.
    For local paths (not starting with ``//``) returns the path unchanged.
    """
    if path.startswith("ftp://"):
        from snaffler.discovery.ftp_tree_walker import extract_ftp_root
        return extract_ftp_root(path)
    normalized = path.replace("\\", "/")
    if not normalized.startswith("//"):
        return path
    parts = [p for p in normalized.split("/") if p]
    if len(parts) >= 2:
        return f"//{parts[0]}/{parts[1]}"
    return path


def get_modified_time(file_info) -> Optional[datetime]:
    try:
        return datetime.fromtimestamp(file_info.get_mtime_epoch())
    except Exception:
        return None
