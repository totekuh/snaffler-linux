from impacket.ldap.ldap import LDAPConnection

from snaffler.config.configuration import SnafflerConfiguration


class LDAPTransport:
    """
    LDAP transport wrapper for Active Directory

    Responsibilities:
    - Establish LDAP connection
    - Handle NTLM auth
    - Auto-discover DC if needed
    """

    def __init__(self, cfg: SnafflerConfiguration):
        self.cfg = cfg
        self.auth = cfg.auth

        self.username = self.auth.username or ""
        self.password = self.auth.password or ""
        self.nthash = self.auth.nthash or ""
        self.domain = self.auth.domain
        self.dc_ip = self.auth.dc_ip

    def connect(self) -> LDAPConnection:
        if not self.domain:
            raise ValueError("LDAP connection requires a domain")

        target = self.dc_ip or self.domain

        ldap = LDAPConnection(
            f"ldap://{target}",
            self.domain,
        )

        if self.nthash:
            ldap.login(
                self.username,
                "",
                self.domain,
                "",
                self.nthash,
            )
        else:
            ldap.login(
                self.username,
                self.password,
                self.domain,
            )

        return ldap
