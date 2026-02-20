"""
Active Directory discovery via LDAP (Impacket, paged)
"""

import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import List

from impacket.ldap import ldapasn1
from impacket.ldap.ldap import SimplePagedResultsControl, LDAPSessionError

from snaffler.config.configuration import SnafflerConfiguration
from snaffler.transport.ldap import LDAPTransport

logger = logging.getLogger("snaffler")

# Windows FILETIME epoch: Jan 1, 1601
_FILETIME_EPOCH = datetime(1601, 1, 1)

# UAC flag for disabled accounts
_UAC_ACCOUNTDISABLE = 0x2


class ADDiscovery:
    """
    Active Directory discovery via LDAP

    Responsibilities:
    - Query computers
    - Query users
    - No auth logic (delegated to LDAPTransport)
    """

    def __init__(self, cfg: SnafflerConfiguration):
        self.cfg = cfg
        self.ldap_transport = LDAPTransport(cfg)

        if not cfg.auth.domain:
            raise ValueError("AD discovery requires cfg.auth.domain")

        self.domain = cfg.auth.domain
        self.base_dn = ",".join(f"DC={p}" for p in self.domain.split("."))

        self.skip_disabled = cfg.targets.skip_disabled_computers
        staleness_months = cfg.targets.max_computer_staleness_months
        self._staleness_cutoff = datetime.now() - timedelta(days=staleness_months * 30)

        # Internal accumulators (used by callbacks)
        self._computers: List[str] = []
        self._skipped_disabled: int = 0
        self._skipped_stale: int = 0
        self._users: List[str] = []

    # ------------------------------------------------------------------
    # Computers
    # ------------------------------------------------------------------

    def _computer_callback(self, item):
        if not isinstance(item, ldapasn1.SearchResultEntry):
            return

        dns = None
        name = None
        uac = 0
        llts = None

        for attr in item["attributes"]:
            t = str(attr["type"]).lower()
            if t == "dnshostname" and attr["vals"]:
                dns = str(attr["vals"][0])
            elif t == "name" and attr["vals"]:
                name = str(attr["vals"][0])
            elif t == "useraccountcontrol" and attr["vals"]:
                try:
                    uac = int(str(attr["vals"][0]))
                except (ValueError, TypeError):
                    pass
            elif t == "lastlogontimestamp" and attr["vals"]:
                llts = str(attr["vals"][0])

        hostname = dns or (f"{name}.{self.domain}" if name else None)
        if not hostname:
            return

        if self.skip_disabled:
            # Skip disabled computer accounts
            if uac & _UAC_ACCOUNTDISABLE:
                self._skipped_disabled += 1
                logger.debug(f"Skipping disabled computer: {hostname}")
                return

            # Skip stale computer accounts (no login within staleness window)
            if llts:
                try:
                    filetime = int(llts)
                    last_logon = _FILETIME_EPOCH + timedelta(microseconds=filetime // 10)
                    if last_logon < self._staleness_cutoff:
                        self._skipped_stale += 1
                        logger.debug(
                            f"Skipping stale computer: {hostname} "
                            f"(last logon: {last_logon.strftime('%Y-%m-%d')})"
                        )
                        return
                except (ValueError, TypeError, OverflowError):
                    logger.debug(f"Could not parse lastLogonTimeStamp for {hostname}")

        self._computers.append(hostname)

    def get_domain_computers(
            self,
            ldap_filter: str = "(&(objectCategory=computer)(objectClass=computer))",
    ) -> List[str]:
        logger.info(f"Querying LDAP for computers: {ldap_filter}")
        self._computers = []
        self._skipped_disabled = 0
        self._skipped_stale = 0

        attrs = ["dNSHostName", "name", "userAccountControl", "lastLogonTimeStamp"]

        try:
            ldap = self.ldap_transport.connect()

            paged = SimplePagedResultsControl(size=1000)

            ldap.search(
                searchBase=self.base_dn,
                searchFilter=ldap_filter,
                attributes=attrs,
                sizeLimit=0,
                searchControls=[paged],
                perRecordCallback=self._computer_callback,
            )

            ldap.close()

        except LDAPSessionError as e:
            logger.error(f"LDAP error while querying computers: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error during LDAP computer discovery: {e}",
                exc_info=True,
            )

        if self.skip_disabled and (self._skipped_disabled or self._skipped_stale):
            logger.info(
                f"Skipped {self._skipped_disabled} disabled and "
                f"{self._skipped_stale} stale computer accounts "
                f"(use --no-skip-disabled to include them)"
            )
        logger.info(f"Found {len(self._computers)} live computers in AD")
        return self._computers

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def _user_callback(self, item, match_strings, min_len):
        if not isinstance(item, ldapasn1.SearchResultEntry):
            return

        for attr in item["attributes"]:
            if str(attr["type"]).lower() != "samaccountname":
                continue

            for val in attr["vals"]:
                username = str(val)

                if len(username) < min_len:
                    continue

                u = username.lower()
                if any(s in u for s in match_strings):
                    self._users.append(username)
                    return

    def get_domain_users(
            self,
            match_strings: List[str] | None = None,
            min_len: int = 6,
    ) -> List[str]:
        if not match_strings:
            match_strings = ["sql", "svc", "service", "backup", "admin"]

        logger.info("Querying LDAP for interesting domain users")
        self._users = []

        try:
            ldap = self.ldap_transport.connect()

            paged = SimplePagedResultsControl(size=1000)

            ldap.search(
                searchBase=self.base_dn,
                searchFilter="(&(objectClass=user)(objectCategory=person))",
                attributes=["sAMAccountName"],
                sizeLimit=0,
                searchControls=[paged],
                perRecordCallback=lambda item: self._user_callback(
                    item, match_strings, min_len
                ),
            )

            ldap.close()

        except LDAPSessionError as e:
            logger.error(f"LDAP error while querying users: {e}")
        except Exception as e:
            logger.error(
                f"Unexpected error during LDAP user discovery: {e}",
                exc_info=True,
            )

        logger.info(f"Found {len(self._users)} interesting users in AD")
        return self._users

    # ------------------------------------------------------------------
    # DFS targets
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_unc_target(raw: str) -> str | None:
        """Normalize ``\\\\server\\share`` → ``//server/share``.

        Returns None for malformed entries or the ``*`` terminator used
        by DFS v1 ``remoteServerName`` attributes.
        """
        if not raw or raw.strip() == "*":
            return None
        s = raw.strip().replace("\\", "/").lstrip("/")
        parts = s.split("/")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            return None
        return f"//{parts[0]}/{parts[1]}"

    def _dfs_v1_callback(self, item):
        """Process an ``fTDfs`` LDAP entry (DFS v1)."""
        if not isinstance(item, ldapasn1.SearchResultEntry):
            return
        for attr in item["attributes"]:
            if str(attr["type"]).lower() != "remoteservername":
                continue
            for val in attr["vals"]:
                parsed = self._parse_unc_target(str(val))
                if parsed:
                    self._dfs_targets.add(parsed)

    def _dfs_v2_callback(self, item):
        """Process an ``msDFS-Namespacev2`` / ``msDFS-Linkv2`` entry (DFS v2)."""
        if not isinstance(item, ldapasn1.SearchResultEntry):
            return
        for attr in item["attributes"]:
            if str(attr["type"]).lower() != "msdfs-targetlistv2":
                continue
            for val in attr["vals"]:
                xml_text = str(val)
                try:
                    root = ET.fromstring(xml_text)
                except ET.ParseError:
                    logger.debug(f"Malformed msDFS-TargetListv2 XML: {xml_text[:120]}")
                    continue
                ns = "{http://schemas.microsoft.com/dfs/2007/03}"
                for target_el in root.iter(f"{ns}target"):
                    if target_el.text:
                        parsed = self._parse_unc_target(target_el.text)
                        if parsed:
                            self._dfs_targets.add(parsed)

    def get_dfs_targets(self) -> List[str]:
        """Query AD for DFS namespace objects and return deduplicated UNC paths."""
        self._dfs_targets: set = set()

        # --- DFS v1: fTDfs ---
        try:
            ldap = self.ldap_transport.connect()
            paged = SimplePagedResultsControl(size=1000)
            ldap.search(
                searchBase=self.base_dn,
                searchFilter="(objectClass=fTDfs)",
                attributes=["remoteServerName"],
                sizeLimit=0,
                searchControls=[paged],
                perRecordCallback=self._dfs_v1_callback,
            )
            ldap.close()
        except LDAPSessionError as e:
            logger.error(f"LDAP error during DFS v1 discovery: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during DFS v1 discovery: {e}", exc_info=True)

        # --- DFS v2: msDFS-Namespacev2 / msDFS-Linkv2 ---
        try:
            ldap = self.ldap_transport.connect()
            paged = SimplePagedResultsControl(size=1000)
            ldap.search(
                searchBase=self.base_dn,
                searchFilter="(|(objectClass=msDFS-Namespacev2)(objectClass=msDFS-Linkv2))",
                attributes=["msDFS-TargetListv2"],
                sizeLimit=0,
                searchControls=[paged],
                perRecordCallback=self._dfs_v2_callback,
            )
            ldap.close()
        except LDAPSessionError as e:
            logger.error(f"LDAP error during DFS v2 discovery: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during DFS v2 discovery: {e}", exc_info=True)

        targets = sorted(self._dfs_targets)
        logger.info(f"Found {len(targets)} DFS target paths in AD")
        return targets
