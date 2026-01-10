"""
Configuration management for Snaffler Linux
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import toml
import typer


# ---------------- AUTH ----------------

@dataclass
class AuthConfig:
    username: str = ""
    password: Optional[str] = None
    nthash: Optional[str] = None
    domain: Optional[str] = None
    dc_host: Optional[str] = None
    smb_timeout: int = 5

    # Kerberos
    kerberos: bool = False
    use_kcache: bool = False


# ---------------- TARGETING ----------------

@dataclass
class TargetingConfig:
    unc_targets: List[str] = field(default_factory=list)
    computer_targets: List[str] = field(default_factory=list)

    shares_only: bool = False

    scan_sysvol: bool = True
    scan_netlogon: bool = True

    ldap_filter: str = "(objectClass=computer)"
    exclusions: List[str] = field(default_factory=list)


# ---------------- SCANNING ----------------

@dataclass
class ScanningConfig:
    min_interest: int = 0
    max_file_size: int = 104_857_600  # 100 MB
    max_read_bytes: int = 2_097_152  # 2 MB
    max_file_bytes: int = 10_485_760  # 10 MB
    snaffle: bool = False
    snaffle_path: Optional[str] = None
    match_context_bytes: int = 200
    cert_passwords: List[str] = field(default_factory=lambda: [
        "", "password", "mimikatz", "1234", "abcd", "secret",
        "MyPassword", "myPassword", "MyClearTextPassword",
        "P@ssw0rd", "testpassword", "changeme", "changeit"
    ])


# ---------------- OUTPUT ----------------

@dataclass
class OutputConfig:
    to_file: bool = False
    output_file: Optional[str] = None

    log_level: str = "info"
    log_type: str = "plain"


# ---------------- ADVANCED ----------------

@dataclass
class AdvancedConfig:
    max_threads: int = 60
    share_threads: int = 20
    tree_threads: int = 20
    file_threads: int = 20


@dataclass
class RulesConfig:
    rule_dir: Optional[str] = None
    share: list = field(default_factory=list)
    directory: list = field(default_factory=list)
    file: list = field(default_factory=list)
    content: list = field(default_factory=list)
    postmatch: list = field(default_factory=list)


# ---------------- RESUME ----------------

@dataclass
class ResumeConfig:
    enabled: bool = False
    state_db: Optional[str] = None


# ---------------- ROOT CONFIG ----------------
@dataclass
class SnafflerConfiguration:
    auth: AuthConfig = field(default_factory=AuthConfig)
    targets: TargetingConfig = field(default_factory=TargetingConfig)
    scanning: ScanningConfig = field(default_factory=ScanningConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    advanced: AdvancedConfig = field(default_factory=AdvancedConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
    resume: ResumeConfig = field(default_factory=ResumeConfig)

    # ---------- validation ----------
    def validate(self):
        if self.scanning.max_read_bytes > self.scanning.max_file_bytes:
            raise ValueError("max_read_bytes cannot exceed max_file_bytes")

        if self.targets.unc_targets and self.targets.computer_targets:
            raise ValueError("Cannot mix UNC targets and computer targets")

        if self.rules.rule_dir:
            p = Path(self.rules.rule_dir)
            if not p.exists():
                raise ValueError(f"rule_dir does not exist: {p}")
            if not p.is_dir():
                raise ValueError(f"rule_dir is not a directory: {p}")

        # ---------- AUTH VALIDATION ----------
        if self.auth.kerberos:
            if self.auth.password or self.auth.nthash:
                raise typer.BadParameter(
                    "Kerberos cannot be used with password or NT hash authentication"
                )
            if not self.auth.domain:
                raise typer.BadParameter(
                    "Kerberos authentication requires a domain"
                )

            if self.auth.use_kcache and self.auth.username:
                raise typer.BadParameter(
                    "Cannot specify username when using Kerberos ccache"
                )

            if self.auth.use_kcache:
                import os
                if "KRB5CCNAME" not in os.environ:
                    raise typer.BadParameter(
                        "KRB5CCNAME not set but Kerberos ccache was requested"
                    )

    # ---------- TOML ----------

    def load_from_toml(self, path: str):
        data = toml.load(path)

        for section, values in data.items():
            if hasattr(self, section):
                obj = getattr(self, section)
                for key, value in values.items():
                    if hasattr(obj, key):
                        setattr(obj, key, value)
