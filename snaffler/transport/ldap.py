from impacket.ldap.ldap import LDAPConnection

from snaffler.config.configuration import SnafflerConfiguration
from snaffler.transport.auth import authenticate_ldap


class LDAPTransport:
    def __init__(self, cfg: SnafflerConfiguration):
        self.cfg = cfg
        self.auth = cfg.auth

    def connect(self) -> LDAPConnection:
        if not self.auth.domain:
            raise ValueError("LDAP connection requires a domain")

        target = self.auth.dc_host or self.auth.domain

        ldap = LDAPConnection(
            f"ldap://{target}",
            self.auth.domain,
        )

        authenticate_ldap(ldap, self.auth)
        return ldap
