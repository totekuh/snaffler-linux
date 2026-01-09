# snaffler/classifiers/loader.py

import logging

from snaffler.classifiers.default_rules import get_default_rules
from snaffler.classifiers.rules import load_rules_from_directory, EnumerationScope
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
