"""
Active Directory discovery via LDAP (Impacket, paged)
"""

import logging
from typing import List

from impacket.ldap import ldapasn1
from impacket.ldap.ldap import SimplePagedResultsControl, LDAPSessionError

from snaffler.config.configuration import SnafflerConfiguration
from snaffler.transport.ldap import LDAPTransport

logger = logging.getLogger("snaffler")


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
            raise ValueError("ADDiscovery requires cfg.auth.domain")

        self.domain = cfg.auth.domain
        self.base_dn = ",".join(f"DC={p}" for p in self.domain.split("."))

        # Internal accumulators (used by callbacks)
        self._computers: List[str] = []
        self._users: List[str] = []

    # ------------------------------------------------------------------
    # Computers
    # ------------------------------------------------------------------

    def _computer_callback(self, item):
        if not isinstance(item, ldapasn1.SearchResultEntry):
            return

        dns = None
        name = None

        for attr in item["attributes"]:
            t = str(attr["type"]).lower()
            if t == "dnshostname" and attr["vals"]:
                dns = str(attr["vals"][0])
            elif t == "name" and attr["vals"]:
                name = str(attr["vals"][0])

        if dns:
            self._computers.append(dns)
        elif name:
            self._computers.append(f"{name}.{self.domain}")

    def get_domain_computers(
            self,
            ldap_filter: str = "(&(objectCategory=computer)(objectClass=computer))",
    ) -> List[str]:
        logger.info(f"Querying LDAP for computers: {ldap_filter}")
        self._computers = []

        try:
            ldap = self.ldap_transport.connect()

            paged = SimplePagedResultsControl(size=1000)

            ldap.search(
                searchBase=self.base_dn,
                searchFilter=ldap_filter,
                attributes=["dNSHostName", "name"],
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

        logger.info(f"Found {len(self._computers)} computers in AD")
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
