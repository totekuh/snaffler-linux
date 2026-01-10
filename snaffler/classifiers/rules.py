"""
Classification rules system
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

import toml


class EnumerationScope(Enum):
    """When to apply a rule"""
    SHARE_ENUMERATION = "ShareEnumeration"
    DIRECTORY_ENUMERATION = "DirectoryEnumeration"
    FILE_ENUMERATION = "FileEnumeration"
    CONTENTS_ENUMERATION = "ContentsEnumeration"
    POST_MATCH = "PostMatch"


class MatchLocation(Enum):
    """What part of the file/share to match against"""
    SHARE_NAME = "ShareName"
    FILE_PATH = "FilePath"
    FILE_NAME = "FileName"
    FILE_EXTENSION = "FileExtension"
    FILE_CONTENT_AS_STRING = "FileContentAsString"
    FILE_CONTENT_AS_BYTES = "FileContentAsBytes"
    FILE_LENGTH = "FileLength"
    FILE_MD5 = "FileMD5"


class MatchListType(Enum):
    """How to match the wordlist"""
    EXACT = "Exact"
    CONTAINS = "Contains"
    REGEX = "Regex"
    ENDS_WITH = "EndsWith"
    STARTS_WITH = "StartsWith"


class MatchAction(Enum):
    """What to do when a rule matches"""
    DISCARD = "Discard"
    SEND_TO_NEXT_SCOPE = "SendToNextScope"
    SNAFFLE = "Snaffle"
    RELAY = "Relay"
    CHECK_FOR_KEYS = "CheckForKeys"
    ENTER_ARCHIVE = "EnterArchive"


class Triage(Enum):
    BLACK = ("Black", 3)  # Critical - credentials, keys, etc.
    RED = ("Red", 2)  # High - config files with secrets, etc.
    YELLOW = ("Yellow", 1)  # Medium - potentially interesting
    GREEN = ("Green", 0)  # Low - mildly interesting

    def __init__(self, label: str, level: int):
        self.label = label
        self.level = level

    def below(self, min_level: int) -> bool:
        return self.level < min_level

    def more_severe_than(self, other: "Triage") -> bool:
        return self.level > other.level


@dataclass
class ClassifierRule:
    """A rule for classifying files/shares"""

    rule_name: str
    enumeration_scope: EnumerationScope
    match_action: MatchAction
    match_location: MatchLocation
    wordlist_type: MatchListType
    wordlist: List[str] = field(default_factory=list)
    triage: Triage = Triage.GREEN
    description: str = ""
    content_rule_names: List[str] = field(default_factory=list)
    match_length: int = 0
    match_md5: Optional[str] = None
    regexes: List[re.Pattern] = field(default_factory=list)

    def __post_init__(self):
        """Compile regexes from wordlist if needed"""
        if self.wordlist_type == MatchListType.REGEX:
            self.regexes = [
                re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                for pattern in self.wordlist
            ]
        elif self.wordlist_type in [MatchListType.CONTAINS, MatchListType.EXACT,
                                    MatchListType.STARTS_WITH, MatchListType.ENDS_WITH]:
            # Convert to regex for consistent matching
            patterns = []
            for word in self.wordlist:
                escaped = re.escape(word)
                if self.wordlist_type == MatchListType.EXACT:
                    pattern = f"^{escaped}$"
                elif self.wordlist_type == MatchListType.CONTAINS:
                    pattern = escaped
                elif self.wordlist_type == MatchListType.STARTS_WITH:
                    pattern = f"^{escaped}"
                elif self.wordlist_type == MatchListType.ENDS_WITH:
                    pattern = f"{escaped}$"
                patterns.append(pattern)

            self.regexes = [
                re.compile(pattern, re.IGNORECASE)
                for pattern in patterns
            ]

    def matches(self, text: str) -> Optional[re.Match]:
        """
        Check if text matches any of the rule's patterns

        Args:
            text: Text to match against

        Returns:
            Match object if matched, None otherwise
        """
        if not text:
            return None

        for regex in self.regexes:
            match = regex.search(text)
            if match:
                return match

        return None

    @classmethod
    def from_toml(cls, toml_data: dict) -> 'ClassifierRule':
        """Create a ClassifierRule from TOML data"""
        return cls(
            rule_name=toml_data.get('RuleName', 'Unknown'),
            enumeration_scope=EnumerationScope(toml_data.get('EnumerationScope', 'FileEnumeration')),
            match_action=MatchAction(toml_data.get('MatchAction', 'Snaffle')),
            match_location=MatchLocation(toml_data.get('MatchLocation', 'FileName')),
            wordlist_type=MatchListType(toml_data.get('WordListType', 'Contains')),
            wordlist=toml_data.get('WordList', []),
            triage=Triage(toml_data.get('Triage', 'Green')),
            description=toml_data.get('Description', ''),
            content_rule_names=toml_data.get('RelayTargets', []),
            match_length=toml_data.get('MatchLength', 0),
            match_md5=toml_data.get('MatchMD5'),
        )


def load_rules_from_toml(toml_path: str) -> List[ClassifierRule]:
    """
    Load classifier rules from a TOML file

    Args:
        toml_path: Path to TOML file containing rules

    Returns:
        List of ClassifierRule objects
    """
    with open(toml_path, 'r') as f:
        data = toml.load(f)

    rules = []
    if 'ClassifierRules' in data:
        for rule_data in data['ClassifierRules']:
            try:
                rule = ClassifierRule.from_toml(rule_data)
                rules.append(rule)
            except Exception as e:
                print(f"Error loading rule: {e}")
                continue

    return rules


def load_rules_from_directory(rules_dir: str) -> List[ClassifierRule]:
    """
    Load all TOML rule files from a directory

    Args:
        rules_dir: Path to directory containing TOML rule files

    Returns:
        List of ClassifierRule objects
    """
    from pathlib import Path

    rules = []
    rules_path = Path(rules_dir)

    # Find all .toml files recursively
    for toml_file in rules_path.rglob('*.toml'):
        try:
            file_rules = load_rules_from_toml(str(toml_file))
            rules.extend(file_rules)
        except Exception as e:
            print(f"Error loading {toml_file}: {e}")

    return rules
