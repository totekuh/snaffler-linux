"""Tests for snaffler.utils.nxc_parser."""

from snaffler.utils.nxc_parser import parse_nxc_shares

NXC_SINGLE_HOST = """\
SMB         10.8.50.20      445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:YOURCOMPANY.LOCAL) (signing:True) (SMBv1:False)
SMB         10.8.50.20      445    DC01             [+] YOURCOMPANY.LOCAL\\user:pass (Pwn3d!)
SMB         10.8.50.20      445    DC01             [*] Enumerated shares
SMB         10.8.50.20      445    DC01             Share           Permissions     Remark
SMB         10.8.50.20      445    DC01             -----           -----------     ------
SMB         10.8.50.20      445    DC01             ADMIN$                          Remote Admin
SMB         10.8.50.20      445    DC01             C$                              Default share
SMB         10.8.50.20      445    DC01             IPC$            READ            Remote IPC
SMB         10.8.50.20      445    DC01             NETLOGON        READ            Logon server share
SMB         10.8.50.20      445    DC01             OPSshare        READ
SMB         10.8.50.20      445    DC01             SYSVOL          READ            Logon server share
"""


def test_parse_single_host():
    result = parse_nxc_shares(NXC_SINGLE_HOST)
    assert "//10.8.50.20/ADMIN$" in result
    assert "//10.8.50.20/C$" in result
    assert "//10.8.50.20/IPC$" in result
    assert "//10.8.50.20/NETLOGON" in result
    assert "//10.8.50.20/OPSshare" in result
    assert "//10.8.50.20/SYSVOL" in result
    assert len(result) == 6


def test_skip_status_lines():
    """Lines with [*], [+], [-] content are skipped."""
    text = (
        "SMB  10.0.0.1  445  HOST  [*] Windows 10\n"
        "SMB  10.0.0.1  445  HOST  [+] user:pass\n"
        "SMB  10.0.0.1  445  HOST  [-] login failed\n"
    )
    assert parse_nxc_shares(text) == []


def test_skip_header_separator():
    """Share/separator header lines are skipped."""
    text = (
        "SMB  10.0.0.1  445  HOST  Share           Permissions     Remark\n"
        "SMB  10.0.0.1  445  HOST  -----           -----------     ------\n"
    )
    assert parse_nxc_shares(text) == []


def test_multiple_hosts():
    text = (
        "SMB  10.0.0.1  445  HOST1  Data        READ\n"
        "SMB  10.0.0.2  445  HOST2  Backup      READ,WRITE\n"
        "SMB  10.0.0.2  445  HOST2  Users       READ\n"
    )
    result = parse_nxc_shares(text)
    assert result == ["//10.0.0.1/Data", "//10.0.0.2/Backup", "//10.0.0.2/Users"]


def test_empty_input():
    assert parse_nxc_shares("") == []


def test_no_shares_only_status():
    text = (
        "SMB  10.0.0.1  445  HOST  [*] Windows Server 2019\n"
        "SMB  10.0.0.1  445  HOST  [+] AUTH OK\n"
    )
    assert parse_nxc_shares(text) == []


def test_deduplication():
    text = (
        "SMB  10.0.0.1  445  HOST  Share1  READ\n"
        "SMB  10.0.0.1  445  HOST  Share1  READ\n"
        "SMB  10.0.0.1  445  HOST  Share2  READ\n"
    )
    result = parse_nxc_shares(text)
    assert result == ["//10.0.0.1/Share1", "//10.0.0.1/Share2"]


def test_non_smb_lines_ignored():
    """Lines not starting with SMB are skipped."""
    text = (
        "INFO Starting scan\n"
        "SMB  10.0.0.1  445  HOST  Data  READ\n"
        "Some random output\n"
    )
    result = parse_nxc_shares(text)
    assert result == ["//10.0.0.1/Data"]


def test_share_no_permissions():
    """Share lines without permission columns are still parsed."""
    text = "SMB  10.0.0.1  445  HOST  ADMIN$                          Remote Admin\n"
    result = parse_nxc_shares(text)
    assert result == ["//10.0.0.1/ADMIN$"]
