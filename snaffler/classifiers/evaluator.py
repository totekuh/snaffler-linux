from dataclasses import dataclass
from typing import Optional, List

from snaffler.analysis.model.file_context import FileContext
from snaffler.classifiers.rules import MatchLocation, MatchAction


@dataclass
class RuleDecision:
    action: MatchAction
    match: Optional[str] = None
    content_rule_names: Optional[List[str]] = None


class RuleEvaluator:
    def __init__(self, file_rules, content_rules, postmatch_rules):
        self.file_rules = file_rules
        self.content_rules = content_rules
        self.postmatch_rules = postmatch_rules

        self.content_rules_by_name = {
            r.rule_name: r for r in content_rules
        }

    def evaluate_file_rule(self, rule, ctx: FileContext) -> Optional[RuleDecision]:
        if rule.match_location == MatchLocation.FILE_PATH:
            match = rule.matches(ctx.unc_path)
        elif rule.match_location == MatchLocation.FILE_NAME:
            match = rule.matches(ctx.name)
        elif rule.match_location == MatchLocation.FILE_EXTENSION:
            match = rule.matches(ctx.ext)
        elif rule.match_location == MatchLocation.FILE_LENGTH:
            match = f"size == {ctx.size}" if rule.match_length == ctx.size else None
        else:
            match = None

        if not match:
            return None

        return RuleDecision(
            action=rule.match_action,
            match=match if isinstance(match, str) else match.group(0),
            content_rule_names=rule.content_rule_names,
        )

    def should_discard_postmatch(self, ctx: FileContext) -> bool:
        for rule in self.postmatch_rules:
            if rule.match_action != MatchAction.DISCARD:
                continue

            text = (
                ctx.unc_path
                if rule.match_location == MatchLocation.FILE_PATH
                else ctx.name
            )

            if rule.matches(text):
                return True

        return False
