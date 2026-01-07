from dataclasses import dataclass
from typing import Optional

from snaffler.classifiers.rules import MatchLocation, MatchAction


@dataclass
class RuleDecision:
    action: MatchAction
    match: Optional[str] = None
    relay_targets: Optional[list] = None

class RuleEvaluator:
    def match_file_rule(self, rule, full_path, name, ext, size):
        if rule.match_location == MatchLocation.FILE_PATH:
            return rule.matches(full_path)
        if rule.match_location == MatchLocation.FILE_NAME:
            return rule.matches(name)
        if rule.match_location == MatchLocation.FILE_EXTENSION:
            return rule.matches(ext)
        if rule.match_location == MatchLocation.FILE_LENGTH:
            return f"size == {size}" if rule.match_length == size else None
        return None

    def should_discard(self, rules, unc_path, name) -> bool:
        for rule in rules:
            if rule.match_action != MatchAction.DISCARD:
                continue

            text = unc_path if rule.match_location == MatchLocation.FILE_PATH else name
            if rule.matches(text):
                return True

        return False
