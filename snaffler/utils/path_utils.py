#!/usr/bin/env python3
from datetime import datetime
from pathlib import Path
from typing import Optional


def parse_unc_path(unc_path: str):
    parts = [p for p in unc_path.replace("\\", "/").split("/") if p]
    if len(parts) < 3:
        return None

    server, share = parts[0], parts[1]
    smb_path = "\\" + "\\".join(parts[2:])

    file_name = Path(unc_path).name
    ext = Path(unc_path).suffix

    if ext.lower() == ".bak":
        stripped = file_name[:-4]
        alt = Path(stripped).suffix
        if alt:
            ext = alt

    if not ext:
        return None

    return server, share, smb_path, file_name, ext


def get_modified_time(file_info) -> Optional[datetime]:
    try:
        return datetime.fromtimestamp(file_info.get_mtime_epoch())
    except Exception:
        return None
