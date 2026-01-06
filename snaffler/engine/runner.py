"""
Main Snaffler controller - orchestrates all components
"""
import logging
from datetime import datetime

from snaffler.classifiers.default_rules import get_default_rules
from snaffler.classifiers.rules import load_rules_from_directory, EnumerationScope
from snaffler.config.configuration import SnafflerConfiguration
from snaffler.discovery.files import FileScanner
from snaffler.discovery.shares import ShareFinder
from snaffler.discovery.tree import TreeWalker
from snaffler.engine.domain_pipeline import DomainPipeline
from snaffler.engine.file_pipeline import FilePipeline
from snaffler.engine.share_pipeline import SharePipeline

logger = logging.getLogger('snaffler')


class SnafflerRunner:
    """Main Snaffler controller"""

    def __init__(self, cfg: SnafflerConfiguration):
        self.cfg = cfg
        self.start_time = None

        adv = cfg.advanced
        targets = cfg.targets

        # Load classification rules
        self._load_rules()

        self.share_finder = ShareFinder(cfg=self.cfg)

        self.tree_walker = TreeWalker(self.cfg)
        self.file_scanner = FileScanner(self.cfg)

        self.file_pipeline = FilePipeline(
            tree_walker=self.tree_walker,
            file_scanner=self.file_scanner,
            tree_threads=adv.tree_threads,
            file_threads=adv.file_threads,
        )
        # ---------- Pipelines ----------
        self.share_pipeline = SharePipeline(
            share_finder=self.share_finder,
            max_workers=adv.share_threads,
            shares_only=targets.shares_only,
        )

        self.file_pipeline = FilePipeline(
            tree_walker=self.tree_walker,
            file_scanner=self.file_scanner,
            tree_threads=adv.tree_threads,
            file_threads=adv.file_threads,
        )

    def _load_rules(self):
        if self.cfg.rules.rule_dir:
            logger.info(f"Loading custom rules from: {self.cfg.rules.rule_dir}")
            rules = load_rules_from_directory(self.cfg.rules.rule_dir)
        else:
            logger.info("Loading default classification rules")
            rules = get_default_rules()

        self.cfg.rules.share = [
            r for r in rules if r.enumeration_scope == EnumerationScope.SHARE_ENUMERATION
        ]
        self.cfg.rules.directory = [
            r for r in rules if r.enumeration_scope == EnumerationScope.DIRECTORY_ENUMERATION
        ]
        self.cfg.rules.file = [
            r for r in rules if r.enumeration_scope == EnumerationScope.FILE_ENUMERATION
        ]
        self.cfg.rules.content = [
            r for r in rules if r.enumeration_scope == EnumerationScope.CONTENTS_ENUMERATION
        ]
        self.cfg.rules.postmatch = [
            r for r in rules if r.enumeration_scope == EnumerationScope.POST_MATCH
        ]

        logger.info(f"Loaded {len(rules)} classification rules")
        logger.info(f"  Share rules: {len(self.cfg.rules.share)}")
        logger.info(f"  Directory rules: {len(self.cfg.rules.directory)}")
        logger.info(f"  File rules: {len(self.cfg.rules.file)}")
        logger.info(f"  Content rules: {len(self.cfg.rules.content)}")
        logger.info(f"  Post match rules: {len(self.cfg.rules.postmatch)}")

    def execute(self):
        self.start_time = datetime.now()
        logger.info(f"Starting Snaffler at {self.start_time:%Y-%m-%d %H:%M:%S}")

        try:
            # ---------- Direct UNC paths ----------
            if self.cfg.targets.path_targets:
                logger.info(f"Using direct path targets: {len(self.cfg.targets.path_targets)}")
                self.file_pipeline.run(self.cfg.targets.path_targets)

            # ---------- Explicit computer list ----------
            elif self.cfg.targets.computer_targets:
                logger.info(f"Using specific computer targets: {len(self.cfg.targets.computer_targets)}")
                share_paths = self.share_pipeline.run(self.cfg.targets.computer_targets)
                if share_paths:
                    self.file_pipeline.run(share_paths)

            # ---------- Domain discovery ----------
            elif self.cfg.auth.domain:
                logger.info("Starting full domain discovery")
                domain_pipeline = DomainPipeline(self.cfg)
                computers = domain_pipeline.run()
                if computers:
                    share_paths = self.share_pipeline.run(computers)
                    if share_paths:
                        self.file_pipeline.run(share_paths)

            else:
                logger.error("No targets specified")
                return

            self._print_completion_stats()

        except KeyboardInterrupt:
            logger.warning("Interrupted by user")
            raise

    def _print_completion_stats(self):
        """Print completion statistics"""
        if self.start_time:
            end_time = datetime.now()
            duration = end_time - self.start_time

            logger.info("-" * 60)
            logger.info(f"Started:  {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            logger.info(f"Finished: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
            logger.info(f"Duration: {duration}")
            logger.info("-" * 60)
