#!/usr/bin/env python3
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple


def parse_unc_base(unc_path: str) -> Optional[Tuple[str, str, str]]:
    """Parse UNC path into base components.

    Args:
        unc_path: UNC path like //server/share/path or //server/share

    Returns:
        Tuple of (server, share, path) where path uses forward slashes
        and defaults to "/" for share root. Returns None if invalid.
    """
    normalized = unc_path.replace("\\", "/")
    parts = [p for p in normalized.split("/") if p]

    if len(parts) < 2:
        return None

    server = parts[0]
    share = parts[1]
    path = "/" + "/".join(parts[2:]) if len(parts) > 2 else "/"

    return server, share, path


def parse_unc_path(unc_path: str):
    """Parse UNC file path into components including filename.

    Args:
        unc_path: UNC path to a file like //server/share/dir/file.txt

    Returns:
        Tuple of (server, share, smb_path, file_name, ext) where smb_path
        uses backslashes. Returns None if path doesn't include a file.
    """
    base = parse_unc_base(unc_path)
    if not base:
        return None

    server, share, path = base

    # Need at least a filename (not just share root)
    if path == "/":
        return None

    smb_path = "\\" + path[1:].replace("/", "\\")

    p = Path(unc_path)
    file_name = p.name
    ext = p.suffix  # may be ""

    return server, share, smb_path, file_name, ext


def get_modified_time(file_info) -> Optional[datetime]:
    try:
        return datetime.fromtimestamp(file_info.get_mtime_epoch())
    except Exception:
        return None
