from impacket.ldap.ldap import LDAPConnection

from snaffler.config.configuration import SnafflerConfiguration


class LDAPTransport:
    def __init__(self, cfg: SnafflerConfiguration):
        self.cfg = cfg
        self.auth = cfg.auth

    def connect(self) -> LDAPConnection:
        if not self.auth.domain:
            raise ValueError("LDAP connection requires a domain")

        target = self.auth.dc_ip or self.auth.domain

        ldap = LDAPConnection(
            f"ldap://{target}",
            self.auth.domain,
        )

        # ---------------- Kerberos ----------------
        if self.auth.kerberos:
            ldap.kerberosLogin(
                user=self.auth.username or "",
                password=self.auth.password or "",
                domain=self.auth.domain,
                lmhash="",
                nthash=self.auth.nthash or "",
                kdcHost=self.auth.dc_ip,
                useCache=self.auth.use_kcache,
            )
            return ldap

        # ---------------- NTLM ----------------
        if self.auth.nthash:
            ldap.login(
                self.auth.username,
                "",
                self.auth.domain,
                "",
                self.auth.nthash,
            )
        else:
            ldap.login(
                self.auth.username,
                self.auth.password or "",
                self.auth.domain,
            )

        return ldap
