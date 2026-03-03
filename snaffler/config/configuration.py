"""
Configuration management for Snaffler Linux
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import tomlkit
import typer

# Shared default cert passwords — used by both CLI (ScanningConfig) and
# library API (Snaffler).  Keep in one place so they never diverge.
DEFAULT_CERT_PASSWORDS: List[str] = [
    "", "password", "mimikatz", "1234", "abcd", "secret",
    "MyPassword", "myPassword", "MyClearTextPassword",
    "P@ssw0rd", "testpassword", "changeme", "changeit",
    "SolarWinds.R0cks", "ThePasswordToKeyonPFXFile",
    "@OurPassword1", "@de08nt2128",
]


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

    # SOCKS proxy
    socks_proxy: Optional[str] = None


# ---------------- TARGETING ----------------

@dataclass
class TargetingConfig:
    unc_targets: List[str] = field(default_factory=list)
    computer_targets: List[str] = field(default_factory=list)
    local_targets: List[str] = field(default_factory=list)

    shares_only: bool = False

    scan_sysvol: bool = True
    scan_netlogon: bool = True

    ldap_filter: str = "(objectClass=computer)"
    exclusions: List[str] = field(default_factory=list)

    skip_disabled_computers: bool = True
    max_computer_staleness_months: int = 4

    share_filter: List[str] = field(default_factory=list)
    exclude_share: List[str] = field(default_factory=list)
    exclude_unc: List[str] = field(default_factory=list)


# ---------------- SCANNING ----------------

@dataclass
class ScanningConfig:
    min_interest: int = 0
    max_read_bytes: int = 2_097_152  # 2 MB
    max_file_bytes: int = 10_485_760  # 10 MB
    snaffle: bool = False
    snaffle_path: Optional[str] = None
    match_context_bytes: int = 200
    max_depth: Optional[int] = None  # Max directory recursion depth (None = unlimited)
    match_filter: Optional[str] = None  # Regex filter for findings (path/rule/match/context)
    cert_passwords: List[str] = field(
        default_factory=lambda: list(DEFAULT_CERT_PASSWORDS)
    )


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
    dns_threads: int = 100
    stealth: bool = False


@dataclass
class RulesConfig:
    rule_dir: Optional[str] = None
    share: list = field(default_factory=list)
    directory: list = field(default_factory=list)
    file: list = field(default_factory=list)
    content: list = field(default_factory=list)
    postmatch: list = field(default_factory=list)


# ---------------- STATE ----------------

@dataclass
class StateConfig:
    state_db: str = "snaffler.db"
    fresh: bool = False


# ---------------- WEB DASHBOARD ----------------

@dataclass
class WebConfig:
    enabled: bool = False
    port: int = 8080


# ---------------- ROOT CONFIG ----------------
@dataclass
class SnafflerConfiguration:
    auth: AuthConfig = field(default_factory=AuthConfig)
    targets: TargetingConfig = field(default_factory=TargetingConfig)
    scanning: ScanningConfig = field(default_factory=ScanningConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    advanced: AdvancedConfig = field(default_factory=AdvancedConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
    state: StateConfig = field(default_factory=StateConfig)
    web: WebConfig = field(default_factory=WebConfig)

    # ---------- validation ----------
    def validate(self):
        if self.scanning.max_read_bytes > self.scanning.max_file_bytes:
            raise ValueError("max_read_bytes cannot exceed max_file_bytes")

        if self.targets.unc_targets and self.targets.computer_targets:
            raise ValueError("Cannot mix UNC targets and computer targets")

        if self.targets.local_targets and (
            self.targets.unc_targets or self.targets.computer_targets
        ):
            raise ValueError("Cannot mix local targets with UNC or computer targets")

        if self.rules.rule_dir:
            p = Path(self.rules.rule_dir)
            if not p.exists():
                raise ValueError(f"rule_dir does not exist: {p}")
            if not p.is_dir():
                raise ValueError(f"rule_dir is not a directory: {p}")

        # Auth validation is irrelevant in local mode (no network connections)
        if self.targets.local_targets:
            return

        # ---------- AUTH VALIDATION ----------
        if self.auth.kerberos:
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
        with open(path, "r") as f:
            data = tomlkit.load(f)

        for section, values in data.items():
            if hasattr(self, section):
                obj = getattr(self, section)
                for key, value in values.items():
                    if hasattr(obj, key):
                        setattr(obj, key, value)
