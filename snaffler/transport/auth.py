"""Shared authentication helpers for SMB and LDAP transports."""


def authenticate_smb(smb, auth):
    """Authenticate an SMBConnection using Kerberos or NTLM.

    Args:
        smb: An impacket SMBConnection instance.
        auth: Auth config object with username, password, domain, nthash,
              kerberos, dc_host, and use_kcache attributes.
    """
    if auth.kerberos:
        smb.kerberosLogin(
            user=auth.username or "",
            password=auth.password or "",
            domain=auth.domain or "",
            lmhash="",
            nthash=auth.nthash or "",
            aesKey=None,
            kdcHost=auth.dc_host,
            useCache=auth.use_kcache,
        )
    elif auth.nthash:
        smb.login(
            auth.username,
            "",
            auth.domain or "",
            "",
            auth.nthash,
        )
    else:
        smb.login(
            auth.username,
            auth.password or "",
            auth.domain or "",
        )


def authenticate_ldap(ldap_conn, auth):
    """Authenticate an LDAPConnection using Kerberos or NTLM.

    Args:
        ldap_conn: An impacket LDAPConnection instance.
        auth: Auth config object with username, password, domain, nthash,
              kerberos, dc_host, and use_kcache attributes.
    """
    if auth.kerberos:
        ldap_conn.kerberosLogin(
            user=auth.username or "",
            password=auth.password or "",
            domain=auth.domain,
            lmhash="",
            nthash=auth.nthash or "",
            kdcHost=auth.dc_host,
            useCache=auth.use_kcache,
        )
    elif auth.nthash:
        ldap_conn.login(
            auth.username,
            "",
            auth.domain,
            "",
            auth.nthash,
        )
    else:
        ldap_conn.login(
            auth.username,
            auth.password or "",
            auth.domain,
        )
