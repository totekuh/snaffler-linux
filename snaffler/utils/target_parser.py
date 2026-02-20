#!/usr/bin/env python3
"""Expand CIDR, dash-range, and plain targets into individual host strings."""

import ipaddress
import logging
from typing import List

logger = logging.getLogger("snaffler")


def expand_targets(targets: List[str]) -> List[str]:
    """Expand a list of targets that may contain CIDR notation or dash ranges.

    Supported formats:
    - CIDR: ``10.0.0.0/24``
    - Dash range (last octet): ``10.0.0.1-50``
    - Dash range (full IPs): ``10.0.0.1-10.0.0.50``
    - Plain hostname or IP: passed through unchanged
    """
    result: List[str] = []
    for target in targets:
        result.extend(_expand_single(target))
    return result


def _expand_single(target: str) -> List[str]:
    # CIDR notation
    if "/" in target:
        return _expand_cidr(target)

    # Dash range
    if "-" in target:
        return _expand_range(target)

    # Plain hostname or IP — pass through
    return [target]


def _expand_cidr(target: str) -> List[str]:
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        logger.error("Invalid CIDR notation '%s': %s", target, exc)
        raise ValueError(f"Invalid CIDR notation '{target}': {exc}") from exc

    hosts = [str(addr) for addr in network.hosts()]

    # ip_network.hosts() already skips network/broadcast for /31+
    # For /32 it returns empty, so fall back to the network address
    if not hosts:
        hosts = [str(network.network_address)]

    logger.info("Expanded %s → %d hosts", target, len(hosts))
    return hosts


def _expand_range(target: str) -> List[str]:
    parts = target.split("-", 1)
    left, right = parts[0].strip(), parts[1].strip()

    # Full IP on both sides: 10.0.0.1-10.0.0.50
    if "." in right:
        return _expand_full_range(left, right, target)

    # Last-octet range: 10.0.0.1-50
    return _expand_octet_range(left, right, target)


def _expand_full_range(left: str, right: str, original: str) -> List[str]:
    try:
        start = ipaddress.ip_address(left)
        end = ipaddress.ip_address(right)
    except ValueError as exc:
        logger.error("Invalid IP range '%s': %s", original, exc)
        raise ValueError(f"Invalid IP range '{original}': {exc}") from exc

    if end < start:
        raise ValueError(f"Invalid IP range '{original}': end address is before start")

    hosts = []
    current = start
    while current <= end:
        hosts.append(str(current))
        current += 1

    logger.info("Expanded %s → %d hosts", original, len(hosts))
    return hosts


def _expand_octet_range(left: str, right: str, original: str) -> List[str]:
    try:
        base_ip = ipaddress.ip_address(left)
    except ValueError as exc:
        logger.error("Invalid IP range '%s': %s", original, exc)
        raise ValueError(f"Invalid IP range '{original}': {exc}") from exc

    try:
        end_octet = int(right)
    except ValueError as exc:
        logger.error("Invalid IP range '%s': end octet is not a number", original)
        raise ValueError(
            f"Invalid IP range '{original}': end octet '{right}' is not a number"
        ) from exc

    # Extract base octets and start octet
    octets = str(base_ip).split(".")
    start_octet = int(octets[3])
    base = ".".join(octets[:3])

    if not (0 <= end_octet <= 255) or not (0 <= start_octet <= 255):
        raise ValueError(f"Invalid IP range '{original}': octet out of range")

    if end_octet < start_octet:
        raise ValueError(f"Invalid IP range '{original}': end octet is before start")

    hosts = [f"{base}.{i}" for i in range(start_octet, end_octet + 1)]

    logger.info("Expanded %s → %d hosts", original, len(hosts))
    return hosts
