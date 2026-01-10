from unittest.mock import MagicMock, patch

import pytest

from snaffler.transport.ldap import LDAPTransport


def make_cfg():
    cfg = MagicMock()
    cfg.auth.domain = "example.com"
    cfg.auth.dc_host = None
    cfg.auth.username = "user"
    cfg.auth.password = "pass"
    cfg.auth.nthash = None
    cfg.auth.kerberos = False
    cfg.auth.use_kcache = False
    return cfg


def test_ldap_no_domain_raises():
    cfg = make_cfg()
    cfg.auth.domain = None

    transport = LDAPTransport(cfg)

    with pytest.raises(ValueError):
        transport.connect()


def test_ldap_kerberos_login():
    cfg = make_cfg()
    cfg.auth.kerberos = True
    cfg.auth.nthash = "NTHASH"

    with patch("snaffler.transport.ldap.LDAPConnection") as ldap_cls:
        ldap = ldap_cls.return_value

        transport = LDAPTransport(cfg)
        result = transport.connect()

    ldap_cls.assert_called_once_with(
        "ldap://example.com",
        "example.com",
    )

    ldap.kerberosLogin.assert_called_once()
    assert result is ldap


def test_ldap_ntlm_with_nthash():
    cfg = make_cfg()
    cfg.auth.nthash = "NTHASH"

    with patch("snaffler.transport.ldap.LDAPConnection") as ldap_cls:
        ldap = ldap_cls.return_value

        transport = LDAPTransport(cfg)
        result = transport.connect()

    ldap.login.assert_called_once_with(
        "user",
        "",
        "example.com",
        "",
        "NTHASH",
    )
    assert result is ldap


def test_ldap_ntlm_with_password():
    cfg = make_cfg()

    with patch("snaffler.transport.ldap.LDAPConnection") as ldap_cls:
        ldap = ldap_cls.return_value

        transport = LDAPTransport(cfg)
        result = transport.connect()

    ldap.login.assert_called_once_with(
        "user",
        "pass",
        "example.com",
    )
    assert result is ldap
