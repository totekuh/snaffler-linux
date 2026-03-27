# snaffler/classifiers/loader.py

import logging
import re
from typing import List

from snaffler.classifiers.default_rules import get_default_rules
from snaffler.classifiers.rules import (
    ClassifierRule, EnumerationScope, MatchAction,
    MatchLocation, MatchListType, Triage,
    load_rules_from_directory,
)
from snaffler.config.configuration import SnafflerConfiguration

logger = logging.getLogger("snaffler")


class RuleLoader:
    @staticmethod
    def load(cfg: SnafflerConfiguration) -> None:
        if cfg.rules.rule_dir:
            logger.info(f"Loading custom rules from: {cfg.rules.rule_dir}")
            rules = load_rules_from_directory(cfg.rules.rule_dir)
        else:
            logger.info("Loading default classification rules")
            rules = get_default_rules()

        if not rules:
            raise RuntimeError("No classification rules loaded")

        cfg.rules.share = [
            r for r in rules if r.enumeration_scope == EnumerationScope.SHARE_ENUMERATION
        ]
        cfg.rules.directory = [
            r for r in rules if r.enumeration_scope == EnumerationScope.DIRECTORY_ENUMERATION
        ]
        cfg.rules.file = [
            r for r in rules if r.enumeration_scope == EnumerationScope.FILE_ENUMERATION
        ]
        cfg.rules.content = [
            r for r in rules if r.enumeration_scope == EnumerationScope.CONTENTS_ENUMERATION
        ]
        cfg.rules.postmatch = [
            r for r in rules if r.enumeration_scope == EnumerationScope.POST_MATCH
        ]

        logger.info(f"Loaded {len(rules)} classification rules")


def build_domain_user_rule(usernames: List[str]) -> ClassifierRule:
    """Build a content rule that matches any of the given usernames.

    Creates one alternation regex rather than per-user rules for efficiency.
    Usernames are matched when surrounded by typical config-file delimiters
    (whitespace, quotes, ``=``, ``:``, commas, backslashes).
    """
    if not usernames:
        raise ValueError("Cannot build domain user rule with empty username list")

    escaped = [re.escape(u) for u in usernames]
    delim = r"""(?:^|[\s'"=:,\\])"""
    end_delim = r"""(?:$|[\s'"=:,\\])"""
    alternation = "|".join(escaped)
    pattern = f"{delim}({alternation}){end_delim}"

    return ClassifierRule(
        rule_name="DynamicDomainUsers",
        enumeration_scope=EnumerationScope.CONTENTS_ENUMERATION,
        match_action=MatchAction.SNAFFLE,
        match_location=MatchLocation.FILE_CONTENT_AS_STRING,
        wordlist_type=MatchListType.REGEX,
        wordlist=[pattern],
        triage=Triage.RED,
        description="Dynamic rule matching interesting AD usernames in file contents",
    )
