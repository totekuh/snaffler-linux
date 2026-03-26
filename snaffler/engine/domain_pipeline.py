"""
Domain discovery pipeline
Expands a domain into a list of target computers
"""

import logging
from typing import List

from snaffler.config.configuration import SnafflerConfiguration
from snaffler.discovery.ad import ADDiscovery
from snaffler.utils.path_utils import extract_unc_host

logger = logging.getLogger("snaffler")


class DomainPipeline:
    """
    Domain → computers pipeline
    """

    def __init__(self, cfg: SnafflerConfiguration, exclusion_set: frozenset | None = None):
        self.cfg = cfg

        auth = cfg.auth
        targets = cfg.targets

        self.domain = auth.domain
        self.ldap_filter = targets.ldap_filter
        if exclusion_set is not None:
            self._exclusion_set = exclusion_set
        else:
            self._exclusion_set = frozenset(
                e.upper() for e in (targets.exclusions or [])
            )

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

        if self._exclusion_set:
            before = len(computers)
            computers = [c for c in computers if c.upper() not in self._exclusion_set]
            logger.info(
                f"Excluded {before - len(computers)} computers via exclusions list"
            )

        return computers

    def get_dfs_shares(self) -> List[str]:
        """Query AD for DFS namespace targets, applying exclusion filters."""
        dfs_paths = self.ad.get_dfs_targets()
        if self._exclusion_set:
            dfs_paths = [
                p for p in dfs_paths
                if (extract_unc_host(p) or "").upper() not in self._exclusion_set
            ]
        return dfs_paths
