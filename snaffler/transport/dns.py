"""
Custom DNS resolution via a specified nameserver.

Uses dnspython (already an impacket dependency) to resolve hostnames
through a user-specified DNS server. Useful when the system resolver
can't reach the target DNS — e.g. lab environments, split DNS, or
pivoting through SOCKS where internal AD hostnames aren't resolvable.

DNS queries use TCP so they also work through SOCKS tunnels. When
combined with --socks, the SOCKS monkey-patch must be applied BEFORE
calling setup_custom_dns().
"""

import ipaddress
import logging
import socket

_original_getaddrinfo = socket.getaddrinfo
logger = logging.getLogger("snaffler")


def setup_custom_dns(nameserver: str) -> None:
    """Monkey-patch socket.getaddrinfo to resolve via a custom nameserver.

    Replaces the system DNS resolver so all hostname lookups (SMB, LDAP,
    Kerberos) go through the specified server. IP addresses and None hosts
    pass through to the original resolver unchanged.

    When used with --socks, the SOCKS proxy must be set up first so that
    DNS-over-TCP queries to the nameserver are routed through the tunnel.

    Args:
        nameserver: IP address of the DNS server to use.

    Raises:
        ImportError: If dnspython is not installed.
        ValueError: If nameserver is not a valid IP address.
    """
    try:
        import dns.resolver
    except ImportError:
        raise ImportError(
            "dnspython is required for --nameserver support. "
            "Install it with: pip install dnspython"
        )

    # Validate nameserver is an IP address
    try:
        ipaddress.ip_address(nameserver)
    except ValueError:
        raise ValueError(
            f"--nameserver must be an IP address, got: {nameserver!r}"
        )

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [nameserver]

    def custom_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        # Pass through non-hostname lookups
        if host is None:
            return _original_getaddrinfo(host, port, family, type, proto, flags)

        # Already an IP address — no resolution needed
        try:
            ipaddress.ip_address(host)
            return _original_getaddrinfo(host, port, family, type, proto, flags)
        except ValueError:
            pass

        # Resolve hostname via custom nameserver (TCP for SOCKS compatibility)
        try:
            answers = resolver.resolve(host, "A", tcp=True)

            # Normalize port to int
            if isinstance(port, str):
                port_num = socket.getservbyname(port)
            elif port is None:
                port_num = 0
            else:
                port_num = int(port)

            results = []
            for rdata in answers:
                results.append(
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", (str(rdata), port_num))
                )
            if results:
                return results
        except Exception as exc:
            logger.debug("Custom DNS resolution failed for %s: %s", host, exc)

        # Fallback to system resolver
        return _original_getaddrinfo(host, port, family, type, proto, flags)

    socket.getaddrinfo = custom_getaddrinfo
