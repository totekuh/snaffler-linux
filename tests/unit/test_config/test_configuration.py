import os
import tempfile

import pytest
import typer

from snaffler.config.configuration import (
    SnafflerConfiguration,
    AuthConfig,
)


# ---------- defaults ----------

def test_default_configuration():
    cfg = SnafflerConfiguration()

    assert cfg.auth.username == ""
    assert cfg.auth.smb_timeout == 5

    assert cfg.targets.unc_targets == []
    assert cfg.targets.computer_targets == []

    assert cfg.advanced.share_threads == 20
    assert cfg.advanced.tree_threads == 20
    assert cfg.advanced.file_threads == 20


# ---------- validation ----------

def test_validate_mixed_targets():
    cfg = SnafflerConfiguration()
    cfg.targets.unc_targets = ["//HOST/SHARE"]
    cfg.targets.computer_targets = ["HOST"]

    with pytest.raises(ValueError):
        cfg.validate()


def test_validate_rule_dir_not_exists():
    cfg = SnafflerConfiguration()
    cfg.rules.rule_dir = "/no/such/dir"

    with pytest.raises(ValueError):
        cfg.validate()


def test_validate_rule_dir_not_directory(tmp_path):
    file = tmp_path / "rules.txt"
    file.write_text("x")

    cfg = SnafflerConfiguration()
    cfg.rules.rule_dir = str(file)

    with pytest.raises(ValueError):
        cfg.validate()


# ---------- kerberos ----------

def test_kerberos_with_password_invalid():
    cfg = SnafflerConfiguration()
    cfg.auth.kerberos = True
    cfg.auth.password = "secret"
    cfg.auth.domain = "example.com"

    with pytest.raises(typer.BadParameter):
        cfg.validate()


def test_kerberos_requires_domain():
    cfg = SnafflerConfiguration()
    cfg.auth.kerberos = True

    with pytest.raises(typer.BadParameter):
        cfg.validate()


def test_kerberos_kcache_requires_env(monkeypatch):
    cfg = SnafflerConfiguration()
    cfg.auth.kerberos = True
    cfg.auth.use_kcache = True
    cfg.auth.domain = "example.com"

    monkeypatch.delenv("KRB5CCNAME", raising=False)

    with pytest.raises(typer.BadParameter):
        cfg.validate()


def test_kerberos_kcache_no_username(monkeypatch):
    cfg = SnafflerConfiguration()
    cfg.auth.kerberos = True
    cfg.auth.use_kcache = True
    cfg.auth.domain = "example.com"
    cfg.auth.username = "user"

    monkeypatch.setenv("KRB5CCNAME", "/tmp/krb5cc")

    with pytest.raises(typer.BadParameter):
        cfg.validate()


def test_valid_kerberos_kcache(monkeypatch):
    cfg = SnafflerConfiguration()
    cfg.auth.kerberos = True
    cfg.auth.use_kcache = True
    cfg.auth.domain = "example.com"

    monkeypatch.setenv("KRB5CCNAME", "/tmp/krb5cc")

    cfg.validate()  # no exception


# ---------- TOML ----------

def test_load_from_toml(tmp_path):
    toml_file = tmp_path / "config.toml"
    toml_file.write_text("""
        [auth]
        username = "admin"
        domain = "example.com"

        [advanced]
        share_threads = 5
    """)

    cfg = SnafflerConfiguration()
    cfg.load_from_toml(str(toml_file))

    assert cfg.auth.username == "admin"
    assert cfg.auth.domain == "example.com"
    assert cfg.advanced.share_threads == 5

