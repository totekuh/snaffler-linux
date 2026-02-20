"""Tests for SOCKS proxy URL parsing and setup."""

import socket
from unittest.mock import MagicMock, patch

import pytest

from snaffler.transport.socks import (
    SOCKS4,
    SOCKS5,
    parse_socks_url,
    setup_socks_proxy,
)


# ---------- parse_socks_url ----------

class TestParseSocksUrl:

    def test_socks5_url(self):
        result = parse_socks_url("socks5://127.0.0.1:1080")
        assert result == (SOCKS5, "127.0.0.1", 1080, None, None)

    def test_socks4_url(self):
        result = parse_socks_url("socks4://10.0.0.1:9050")
        assert result == (SOCKS4, "10.0.0.1", 9050, None, None)

    def test_bare_host_port_defaults_to_socks5(self):
        result = parse_socks_url("127.0.0.1:1080")
        assert result == (SOCKS5, "127.0.0.1", 1080, None, None)

    def test_authenticated_proxy(self):
        result = parse_socks_url("socks5://admin:s3cret@proxy.local:1080")
        assert result == (SOCKS5, "proxy.local", 1080, "admin", "s3cret")

    def test_missing_port_raises(self):
        with pytest.raises(ValueError, match="Missing port"):
            parse_socks_url("socks5://127.0.0.1")

    def test_missing_host_raises(self):
        with pytest.raises(ValueError, match="Missing host"):
            parse_socks_url("socks5://:1080")

    def test_bad_scheme_raises(self):
        with pytest.raises(ValueError, match="Unsupported SOCKS scheme"):
            parse_socks_url("http://127.0.0.1:1080")

    def test_uppercase_scheme(self):
        result = parse_socks_url("SOCKS5://127.0.0.1:1080")
        assert result == (SOCKS5, "127.0.0.1", 1080, None, None)

    def test_hostname_target(self):
        result = parse_socks_url("socks5://proxy.corp.local:1080")
        assert result == (SOCKS5, "proxy.corp.local", 1080, None, None)


# ---------- setup_socks_proxy ----------

class TestSetupSocksProxy:

    def test_patches_socket(self):
        mock_socks = MagicMock()
        original_socket = socket.socket

        with patch.dict("sys.modules", {"socks": mock_socks}):
            setup_socks_proxy("socks5://127.0.0.1:1080")

            mock_socks.set_default_proxy.assert_called_once_with(
                proxy_type=SOCKS5,
                addr="127.0.0.1",
                port=1080,
                rdns=True,
                username=None,
                password=None,
            )
            assert socket.socket is mock_socks.socksocket

        # restore
        socket.socket = original_socket

    def test_raises_import_error_without_pysocks(self):
        with patch.dict("sys.modules", {"socks": None}):
            with pytest.raises(ImportError, match="PySocks is required"):
                setup_socks_proxy("socks5://127.0.0.1:1080")
