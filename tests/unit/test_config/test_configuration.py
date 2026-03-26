import os
import tempfile

import pytest

from snaffler.config.configuration import (
    SnafflerConfiguration,
    AuthConfig,
    StateConfig,
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


# ---------- local targets ----------

def test_default_local_targets_empty():
    cfg = SnafflerConfiguration()
    assert cfg.targets.local_targets == []


def test_validate_local_mixed_with_unc():
    cfg = SnafflerConfiguration()
    cfg.targets.local_targets = ["/tmp"]
    cfg.targets.unc_targets = ["//HOST/SHARE"]

    with pytest.raises(ValueError, match="Cannot mix local"):
        cfg.validate()


def test_validate_local_mixed_with_computer():
    cfg = SnafflerConfiguration()
    cfg.targets.local_targets = ["/tmp"]
    cfg.targets.computer_targets = ["HOST1"]

    with pytest.raises(ValueError, match="Cannot mix local"):
        cfg.validate()


def test_validate_local_skips_auth_validation():
    """In local mode, Kerberos auth errors are skipped (no network needed)."""
    cfg = SnafflerConfiguration()
    cfg.targets.local_targets = ["/tmp"]
    cfg.auth.kerberos = True
    # No domain set — would normally raise "Kerberos requires domain"

    cfg.validate()  # no exception


def test_validate_local_still_checks_scan_config():
    """Local mode still validates non-auth config like max_read_bytes."""
    cfg = SnafflerConfiguration()
    cfg.targets.local_targets = ["/tmp"]
    cfg.scanning.max_read_bytes = 999999999
    cfg.scanning.max_file_bytes = 1

    with pytest.raises(ValueError, match="max_read_bytes"):
        cfg.validate()


# ---------- kerberos ----------

def test_kerberos_with_password_valid():
    """Kerberos + password is valid — impacket requests a TGT from the KDC."""
    cfg = SnafflerConfiguration()
    cfg.auth.kerberos = True
    cfg.auth.password = "secret"
    cfg.auth.domain = "example.com"

    cfg.validate()  # no exception


def test_kerberos_with_nthash_valid():
    """Kerberos + nthash is valid — impacket uses RC4 for the TGT."""
    cfg = SnafflerConfiguration()
    cfg.auth.kerberos = True
    cfg.auth.nthash = "aad3b435b51404eeaad3b435b51404ee"
    cfg.auth.domain = "example.com"

    cfg.validate()  # no exception


def test_kerberos_requires_domain():
    cfg = SnafflerConfiguration()
    cfg.auth.kerberos = True

    with pytest.raises(ValueError):
        cfg.validate()


def test_kerberos_kcache_requires_env(monkeypatch):
    cfg = SnafflerConfiguration()
    cfg.auth.kerberos = True
    cfg.auth.use_kcache = True
    cfg.auth.domain = "example.com"

    monkeypatch.delenv("KRB5CCNAME", raising=False)

    with pytest.raises(ValueError):
        cfg.validate()


def test_kerberos_kcache_no_username(monkeypatch):
    cfg = SnafflerConfiguration()
    cfg.auth.kerberos = True
    cfg.auth.use_kcache = True
    cfg.auth.domain = "example.com"
    cfg.auth.username = "user"

    monkeypatch.setenv("KRB5CCNAME", "/tmp/krb5cc")

    with pytest.raises(ValueError):
        cfg.validate()


def test_valid_kerberos_kcache(monkeypatch):
    cfg = SnafflerConfiguration()
    cfg.auth.kerberos = True
    cfg.auth.use_kcache = True
    cfg.auth.domain = "example.com"

    monkeypatch.setenv("KRB5CCNAME", "/tmp/krb5cc")

    cfg.validate()  # no exception


# ---------- TOML ----------

def test_state_config_no_fresh_attribute():
    """BUG-4: StateConfig.fresh field was removed."""
    sc = StateConfig()
    assert not hasattr(sc, "fresh")


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


# ---------- BUG-Z5: load_from_toml accepts wrong types silently ----------

def test_load_from_toml_rejects_string_for_list(tmp_path):
    """BUG-Z5: A string value where a list is expected should be skipped
    with a warning, not silently accepted (causing character-by-character iteration)."""
    toml_file = tmp_path / "bad_types.toml"
    toml_file.write_text("""
        [targets]
        exclude_unc = "*/Windows/*"
    """)

    cfg = SnafflerConfiguration()
    cfg.load_from_toml(str(toml_file))

    # The string should NOT have been set — exclude_unc should remain a list
    assert isinstance(cfg.targets.exclude_unc, list)
    assert cfg.targets.exclude_unc == []


def test_load_from_toml_rejects_int_for_string(tmp_path):
    """BUG-Z5: An integer value where a string is expected should be skipped."""
    toml_file = tmp_path / "bad_types.toml"
    toml_file.write_text("""
        [auth]
        username = 12345
    """)

    cfg = SnafflerConfiguration()
    cfg.load_from_toml(str(toml_file))

    # username should remain unchanged (default "")
    assert cfg.auth.username == ""


def test_load_from_toml_accepts_correct_types(tmp_path):
    """BUG-Z5: Correct types should still be accepted normally."""
    toml_file = tmp_path / "good_types.toml"
    toml_file.write_text("""
        [auth]
        username = "admin"
        smb_timeout = 10
        kerberos = true

        [targets]
        exclude_unc = ["*/Windows/*", "*/temp/*"]

        [advanced]
        max_threads = 100
    """)

    cfg = SnafflerConfiguration()
    cfg.load_from_toml(str(toml_file))

    assert cfg.auth.username == "admin"
    assert cfg.auth.smb_timeout == 10
    assert cfg.auth.kerberos is True
    assert cfg.targets.exclude_unc == ["*/Windows/*", "*/temp/*"]
    assert cfg.advanced.max_threads == 100


def test_load_from_toml_rejects_string_for_int(tmp_path):
    """BUG-Z5: A string value where an int is expected should be skipped."""
    toml_file = tmp_path / "bad_types.toml"
    toml_file.write_text("""
        [advanced]
        max_threads = "fast"
    """)

    cfg = SnafflerConfiguration()
    cfg.load_from_toml(str(toml_file))

    # max_threads should remain default (60)
    assert cfg.advanced.max_threads == 60


def test_load_from_toml_rejects_int_for_bool(tmp_path):
    """BUG-Z5: An integer where a bool is expected should be skipped
    (even though bool is a subclass of int in Python)."""
    toml_file = tmp_path / "bad_types.toml"
    toml_file.write_text("""
        [auth]
        kerberos = 1
    """)

    cfg = SnafflerConfiguration()
    cfg.load_from_toml(str(toml_file))

    # kerberos should remain default (False)
    assert cfg.auth.kerberos is False


def test_load_from_toml_allows_none_for_optional(tmp_path):
    """BUG-Z5: None values should be accepted for Optional fields."""
    toml_file = tmp_path / "none_types.toml"
    toml_file.write_text("""
        [auth]
        domain = "example.com"
    """)

    cfg = SnafflerConfiguration()
    cfg.load_from_toml(str(toml_file))

    # domain default is None, setting to string should work
    assert cfg.auth.domain == "example.com"

