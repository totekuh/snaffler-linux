"""
Configuration management for Snaffler Linux
"""

from dataclasses import dataclass, field
from typing import List, Optional, Any

import toml


# ---------------- AUTH ----------------

@dataclass
class AuthConfig:
    username: str = ""
    password: Optional[str] = None
    nthash: Optional[str] = None
    domain: Optional[str] = None
    dc_ip: Optional[str] = None
    timeout: int = 5


# ---------------- TARGETING ----------------

@dataclass
class TargetingConfig:
    path_targets: List[str] = field(default_factory=list)
    computer_targets: List[str] = field(default_factory=list)

    shares_only: bool = False

    scan_sysvol: bool = True
    scan_netlogon: bool = True

    ldap_filter: str = "(objectClass=computer)"
    exclusions: List[str] = field(default_factory=list)


# ---------------- SCANNING ----------------

@dataclass
class ScanningConfig:
    interest_level: int = 0
    max_size_to_grep: int = 2_097_152  # 2 MB
    max_size_to_snaffle: int = 10_485_760  # 10 MB
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


# ---------------- ROOT CONFIG ----------------

@dataclass
class SnafflerConfiguration:
    auth: AuthConfig = field(default_factory=AuthConfig)
    targets: TargetingConfig = field(default_factory=TargetingConfig)
    scanning: ScanningConfig = field(default_factory=ScanningConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    advanced: AdvancedConfig = field(default_factory=AdvancedConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)

    # runtime-only (populated later)
    share_classifiers: List[Any] = field(default_factory=list)
    dir_classifiers: List[Any] = field(default_factory=list)
    file_classifiers: List[Any] = field(default_factory=list)
    contents_classifiers: List[Any] = field(default_factory=list)

    # ---------- validation ----------

    def validate(self):
        if self.targets.path_targets and self.targets.computer_targets:
            raise ValueError("Cannot mix path targets and computer targets")

    # ---------- TOML ----------

    def load_from_toml(self, path: str):
        data = toml.load(path)

        for section, values in data.items():
            if hasattr(self, section):
                obj = getattr(self, section)
                for key, value in values.items():
                    if hasattr(obj, key):
                        setattr(obj, key, value)
