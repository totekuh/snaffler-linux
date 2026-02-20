"""
SOCKS proxy support for tunneling SMB/LDAP connections through a pivot host.

Uses PySocks to monkey-patch socket.socket globally so all TCP connections
(SMB, LDAP, Kerberos) are routed through the proxy. Must be called once
at startup before any connections are made.
"""

import socket
from urllib.parse import urlparse

# PySocks proxy type constants (avoids importing socks at module level)
SOCKS4 = 1
SOCKS5 = 2


def parse_socks_url(url: str) -> tuple:
    """Parse a SOCKS proxy URL into (proxy_type, host, port, username, password).

    Accepted formats:
        socks5://host:port
        socks4://host:port
        socks5://user:pass@host:port
        host:port              (defaults to SOCKS5)

    Returns:
        Tuple of (proxy_type, host, port, username, password).
        username and password may be None.

    Raises:
        ValueError: If the URL is malformed or missing required components.
    """
    # Bare host:port (no scheme) — default to SOCKS5
    if "://" not in url:
        url = f"socks5://{url}"

    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    if scheme == "socks5":
        proxy_type = SOCKS5
    elif scheme == "socks4":
        proxy_type = SOCKS4
    else:
        raise ValueError(
            f"Unsupported SOCKS scheme: {scheme!r} (use socks4 or socks5)"
        )

    host = parsed.hostname
    if not host:
        raise ValueError(f"Missing host in SOCKS proxy URL: {url!r}")

    port = parsed.port
    if not port:
        raise ValueError(f"Missing port in SOCKS proxy URL: {url!r}")

    username = parsed.username or None
    password = parsed.password or None

    return (proxy_type, host, port, username, password)


def setup_socks_proxy(proxy_url: str) -> None:
    """Apply global SOCKS monkey-patch so all new sockets route through the proxy.

    Must be called before any SMB/LDAP connections are created.

    Raises:
        ImportError: If PySocks is not installed.
        ValueError: If proxy_url is malformed.
    """
    try:
        import socks
    except ImportError:
        raise ImportError(
            "PySocks is required for --socks support. "
            "Install it with: pip install pysocks"
        )

    proxy_type, host, port, username, password = parse_socks_url(proxy_url)

    socks.set_default_proxy(
        proxy_type=proxy_type,
        addr=host,
        port=port,
        rdns=True,
        username=username,
        password=password,
    )
    socket.socket = socks.socksocket
