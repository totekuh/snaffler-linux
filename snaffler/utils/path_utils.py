#!/usr/bin/env python3
from datetime import datetime
from pathlib import Path
from typing import Optional

def parse_unc_path(unc_path: str):
    print(unc_path)

    parts = [p for p in unc_path.split("/") if p]
    if len(parts) < 3:
        return None

    server, share = parts[0], parts[1]
    smb_path = "\\" + "\\".join(parts[2:])

    p = Path(unc_path)
    file_name = p.name
    ext = p.suffix  # may be ""

    return server, share, smb_path, file_name, ext


def get_modified_time(file_info) -> Optional[datetime]:
    try:
        return datetime.fromtimestamp(file_info.get_mtime_epoch())
    except Exception:
        return None
