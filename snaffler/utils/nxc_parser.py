"""Parse NetExec (nxc) SMB --shares output into UNC paths."""

import re

_NXC_LINE = re.compile(r"^SMB\s+(\S+)\s+\d+\s+\S+\s+(.+)$")
_SKIP = re.compile(r"^\[|^Share\s|^-{3,}")


def parse_nxc_shares(text: str) -> list[str]:
    """Extract UNC paths from NXC SMB --shares output.

    Each share line looks like:
        SMB  10.8.50.20  445  DC01  OPSshare  READ

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
        share = content.split()[0]
        paths.append(f"//{ip}/{share}")
    return list(dict.fromkeys(paths))  # dedupe, preserve order
