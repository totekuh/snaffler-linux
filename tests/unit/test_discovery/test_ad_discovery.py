from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch, PropertyMock

from snaffler.discovery.ad import ADDiscovery, _FILETIME_EPOCH
from impacket.ldap.ldap import LDAPSessionError


# ---------- helpers ----------

class AcceptAll:
    def __instancecheck__(self, instance):
        return True


class FakeAttr:
    def __init__(self, t, vals):
        self._type = t
        self._vals = vals

    def __getitem__(self, key):
        if key == "type":
            return self._type
        if key == "vals":
            return self._vals
        raise KeyError(key)



class FakeEntry:
    def __init__(self, attrs):
        self.attributes = attrs

    def __getitem__(self, item):
        if item == "attributes":
            return self.attributes
        raise KeyError


def fake_computer(dns=None, name=None, uac=0, llts=None):
    attrs = []
    if dns:
        attrs.append(FakeAttr("dNSHostName", [dns]))
    if name:
        attrs.append(FakeAttr("name", [name]))
    attrs.append(FakeAttr("userAccountControl", [str(uac)]))
    if llts is not None:
        attrs.append(FakeAttr("lastLogonTimeStamp", [str(llts)]))
    return FakeEntry(attrs)


def _make_cfg(domain="example.com", skip_disabled=True, staleness_months=4):
    cfg = MagicMock()
    cfg.auth.domain = domain
    cfg.targets.skip_disabled_computers = skip_disabled
    cfg.targets.max_computer_staleness_months = staleness_months
    return cfg


def fake_user(name):
    return FakeEntry([FakeAttr("sAMAccountName", [name])])


# ---------- tests ----------

def test_get_domain_computers_dns_hostname():
    cfg = _make_cfg()

    discovery = ADDiscovery(cfg)
    ldap = MagicMock()

    def search(**kwargs):
        cb = kwargs["perRecordCallback"]
        cb(fake_computer(dns="host1.example.com"))

    ldap.search.side_effect = search

    with patch.object(
        discovery.ldap_transport, "connect", return_value=ldap
    ), patch(
        "snaffler.discovery.ad.ldapasn1.SearchResultEntry",
        AcceptAll(),
    ):
        result = discovery.get_domain_computers()

    assert result == ["host1.example.com"]


def test_get_domain_computers_name_fallback():
    cfg = _make_cfg()

    discovery = ADDiscovery(cfg)
    ldap = MagicMock()

    def search(**kwargs):
        cb = kwargs["perRecordCallback"]
        cb(fake_computer(name="HOST2"))

    ldap.search.side_effect = search

    with patch.object(
        discovery.ldap_transport, "connect", return_value=ldap
    ), patch(
        "snaffler.discovery.ad.ldapasn1.SearchResultEntry",
        AcceptAll(),
    ):
        result = discovery.get_domain_computers()

    assert result == ["HOST2.example.com"]


def test_get_domain_users_filters():
    cfg = _make_cfg()

    discovery = ADDiscovery(cfg)
    ldap = MagicMock()

    def search(**kwargs):
        cb = kwargs["perRecordCallback"]
        cb(fake_user("sqlsvc"))
        cb(fake_user("user"))
        cb(fake_user("ADMIN_BACKUP"))

    ldap.search.side_effect = search

    with patch.object(
        discovery.ldap_transport, "connect", return_value=ldap
    ), patch(
        "snaffler.discovery.ad.ldapasn1.SearchResultEntry",
        AcceptAll(),
    ):
        users = discovery.get_domain_users(
            match_strings=["sql", "backup"],
            min_len=5,
        )

    assert set(users) == {"sqlsvc", "ADMIN_BACKUP"}


def test_get_domain_users_ldap_error():
    cfg = _make_cfg()

    discovery = ADDiscovery(cfg)
    ldap = MagicMock()
    ldap.search.side_effect = Exception("boom")

    with patch.object(
        discovery.ldap_transport, "connect", return_value=ldap
    ):
        users = discovery.get_domain_users()

    assert users == []


def _datetime_to_filetime(dt):
    """Convert a datetime to Windows FILETIME (100-nanosecond intervals since 1601-01-01)."""
    delta = dt - _FILETIME_EPOCH
    return int(delta.total_seconds() * 10_000_000)


def test_skip_disabled_computer():
    cfg = _make_cfg()
    discovery = ADDiscovery(cfg)
    ldap = MagicMock()

    recent = _datetime_to_filetime(datetime.now() - timedelta(days=1))

    def search(**kwargs):
        cb = kwargs["perRecordCallback"]
        # UAC 0x2 = disabled
        cb(fake_computer(dns="disabled.example.com", uac=0x2, llts=recent))
        cb(fake_computer(dns="active.example.com", uac=0x1000, llts=recent))

    ldap.search.side_effect = search

    with patch.object(
        discovery.ldap_transport, "connect", return_value=ldap
    ), patch(
        "snaffler.discovery.ad.ldapasn1.SearchResultEntry",
        AcceptAll(),
    ):
        result = discovery.get_domain_computers()

    assert result == ["active.example.com"]
    assert discovery._skipped_disabled == 1


def test_skip_stale_computer():
    cfg = _make_cfg(staleness_months=4)
    discovery = ADDiscovery(cfg)
    ldap = MagicMock()

    recent = _datetime_to_filetime(datetime.now() - timedelta(days=10))
    old = _datetime_to_filetime(datetime.now() - timedelta(days=365))

    def search(**kwargs):
        cb = kwargs["perRecordCallback"]
        cb(fake_computer(dns="recent.example.com", uac=0x1000, llts=recent))
        cb(fake_computer(dns="stale.example.com", uac=0x1000, llts=old))

    ldap.search.side_effect = search

    with patch.object(
        discovery.ldap_transport, "connect", return_value=ldap
    ), patch(
        "snaffler.discovery.ad.ldapasn1.SearchResultEntry",
        AcceptAll(),
    ):
        result = discovery.get_domain_computers()

    assert result == ["recent.example.com"]
    assert discovery._skipped_stale == 1


def test_no_skip_disabled_flag():
    cfg = _make_cfg(skip_disabled=False)
    discovery = ADDiscovery(cfg)
    ldap = MagicMock()

    old = _datetime_to_filetime(datetime.now() - timedelta(days=365))

    def search(**kwargs):
        cb = kwargs["perRecordCallback"]
        cb(fake_computer(dns="disabled.example.com", uac=0x2, llts=old))
        cb(fake_computer(dns="stale.example.com", uac=0x1000, llts=old))

    ldap.search.side_effect = search

    with patch.object(
        discovery.ldap_transport, "connect", return_value=ldap
    ), patch(
        "snaffler.discovery.ad.ldapasn1.SearchResultEntry",
        AcceptAll(),
    ):
        result = discovery.get_domain_computers()

    assert len(result) == 2
    assert "disabled.example.com" in result
    assert "stale.example.com" in result
    assert discovery._skipped_disabled == 0
    assert discovery._skipped_stale == 0


# ---------- DFS target tests ----------

def fake_dfs_v1_entry(remote_server_names):
    """Create a fake fTDfs entry with remoteServerName multivalued attr."""
    return FakeEntry([FakeAttr("remoteServerName", remote_server_names)])


def fake_dfs_v2_entry(xml_blob):
    """Create a fake msDFS-Linkv2 entry with msDFS-TargetListv2 XML."""
    return FakeEntry([FakeAttr("msDFS-TargetListv2", [xml_blob])])


DFS_V2_XML = (
    '<targets xmlns="http://schemas.microsoft.com/dfs/2007/03">'
    '<target state="online">\\\\nas01.corp.local\\data</target>'
    '<target state="online">\\\\nas02.corp.local\\data</target>'
    '</targets>'
)


def test_parse_unc_target_normal():
    assert ADDiscovery._parse_unc_target("\\\\server.domain.com\\share") == "//server.domain.com/share"


def test_parse_unc_target_star():
    assert ADDiscovery._parse_unc_target("*") is None


def test_parse_unc_target_empty():
    assert ADDiscovery._parse_unc_target("") is None
    assert ADDiscovery._parse_unc_target(None) is None


def test_parse_unc_target_malformed():
    assert ADDiscovery._parse_unc_target("\\\\serveronly") is None
    assert ADDiscovery._parse_unc_target("just-a-string") is None


def test_dfs_v1_callback():
    cfg = _make_cfg()
    discovery = ADDiscovery(cfg)
    discovery._dfs_targets = set()

    entry = fake_dfs_v1_entry([
        "\\\\server1.domain.com\\shareroot",
        "\\\\server2.domain.com\\shareroot",
        "*",
    ])

    with patch("snaffler.discovery.ad.ldapasn1.SearchResultEntry", AcceptAll()):
        discovery._dfs_v1_callback(entry)

    assert discovery._dfs_targets == {
        "//server1.domain.com/shareroot",
        "//server2.domain.com/shareroot",
    }


def test_dfs_v2_callback():
    cfg = _make_cfg()
    discovery = ADDiscovery(cfg)
    discovery._dfs_targets = set()

    entry = fake_dfs_v2_entry(DFS_V2_XML)

    with patch("snaffler.discovery.ad.ldapasn1.SearchResultEntry", AcceptAll()):
        discovery._dfs_v2_callback(entry)

    assert discovery._dfs_targets == {
        "//nas01.corp.local/data",
        "//nas02.corp.local/data",
    }


def test_dfs_v2_callback_malformed_xml():
    cfg = _make_cfg()
    discovery = ADDiscovery(cfg)
    discovery._dfs_targets = set()

    entry = fake_dfs_v2_entry("not valid xml <<<<")

    with patch("snaffler.discovery.ad.ldapasn1.SearchResultEntry", AcceptAll()):
        discovery._dfs_v2_callback(entry)

    assert discovery._dfs_targets == set()


def test_get_dfs_targets_mixed_v1_v2():
    cfg = _make_cfg()
    discovery = ADDiscovery(cfg)

    call_count = 0

    def search(**kwargs):
        nonlocal call_count
        cb = kwargs["perRecordCallback"]
        if call_count == 0:
            # v1 query
            cb(fake_dfs_v1_entry([
                "\\\\fileserver.domain.com\\docs",
                "\\\\nas01.corp.local\\data",
                "*",
            ]))
        else:
            # v2 query — includes nas01 duplicate
            cb(fake_dfs_v2_entry(DFS_V2_XML))
        call_count += 1

    ldap = MagicMock()
    ldap.search.side_effect = search

    with patch.object(
        discovery.ldap_transport, "connect", return_value=ldap
    ), patch(
        "snaffler.discovery.ad.ldapasn1.SearchResultEntry", AcceptAll()
    ):
        result = discovery.get_dfs_targets()

    # nas01 appears in both v1 and v2 — should be deduplicated
    assert "//nas01.corp.local/data" in result
    assert "//nas02.corp.local/data" in result
    assert "//fileserver.domain.com/docs" in result
    assert len(result) == 3


def test_get_dfs_targets_empty():
    cfg = _make_cfg()
    discovery = ADDiscovery(cfg)

    ldap = MagicMock()
    ldap.search.side_effect = lambda **kwargs: None  # no callbacks fired

    with patch.object(
        discovery.ldap_transport, "connect", return_value=ldap
    ):
        result = discovery.get_dfs_targets()

    assert result == []


def test_get_dfs_targets_ldap_error():
    cfg = _make_cfg()
    discovery = ADDiscovery(cfg)

    ldap = MagicMock()
    ldap.search.side_effect = Exception("connection refused")

    with patch.object(
        discovery.ldap_transport, "connect", return_value=ldap
    ):
        result = discovery.get_dfs_targets()

    assert result == []
