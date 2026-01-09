"""
Domain discovery pipeline
Expands a domain into a list of target computers
"""

import logging
from typing import List

from snaffler.config.configuration import SnafflerConfiguration
from snaffler.discovery.ad import ADDiscovery

logger = logging.getLogger("snaffler")


class DomainPipeline:
    """
    Domain → computers pipeline
    """

    def __init__(self, cfg: SnafflerConfiguration):
        self.cfg = cfg

        auth = cfg.auth
        targets = cfg.targets

        self.domain = auth.domain
        self.ldap_filter = targets.ldap_filter
        self.exclusions = targets.exclusions or []

        self.ad = ADDiscovery(cfg)

    def run(self) -> List[str]:
        """
        Execute domain discovery

        Returns:
            List of computer names
        """
        logger.info("Running domain discovery pipeline")

        computers = self.ad.get_domain_computers(
            ldap_filter=self.ldap_filter
        )

        if not computers:
            logger.warning("No computers found in AD")
            return []

        logger.info(f"Discovered {len(computers)} computers from AD")

        if self.exclusions:
            before = len(computers)
            computers = [c for c in computers if c not in self.exclusions]
            logger.info(
                f"Excluded {before - len(computers)} computers via exclusions list"
            )

        return computers
