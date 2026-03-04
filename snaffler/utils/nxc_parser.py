"""Parse NetExec (nxc) SMB --shares output into UNC paths."""

import re

_NXC_LINE = re.compile(r"^SMB\s+(\S+)\s+\d+\s+\S+\s+(.+)$")
_SKIP = re.compile(r"^\[|^Share\s|^-{3,}")

# Known NXC permission tokens (case-insensitive comparison)
_PERMISSION_TOKENS = {"READ", "WRITE", "READ,WRITE", "NO"}


def parse_nxc_shares(text: str) -> list[str]:
    """Extract UNC paths from NXC SMB --shares output.

    Each share line looks like:
        SMB  10.8.50.20  445  DC01  OPSshare  READ

    Only includes shares where the permission field contains READ.
    Shares with no permission field are included for backward compatibility.
    Shares with ``NO ACCESS`` are excluded.

    Returns deduplicated list of ``//ip/share`` paths.
    """
    paths: list[str] = []
    for line in text.splitlines():
        m = _NXC_LINE.match(line)
        if not m:
            continue
        ip, content = m.group(1), m.group(2).strip()
        if not content or _SKIP.match(content):
            continue
        parts = content.split()
        share = parts[0]
        # Detect whether the second token is a permission field or a remark.
        # NXC permission values: READ, WRITE, READ,WRITE, NO ACCESS
        if len(parts) >= 2 and parts[1].upper() in _PERMISSION_TOKENS:
            remaining = " ".join(parts[1:]).upper()
            if remaining.startswith("NO ACCESS"):
                continue
            if "READ" not in remaining:
                continue
        # No recognized permission token → remark only (include for backward compat)
        paths.append(f"//{ip}/{share}")
    return list(dict.fromkeys(paths))  # dedupe, preserve order
