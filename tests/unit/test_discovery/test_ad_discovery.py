from unittest.mock import MagicMock, patch

from snaffler.discovery.ad import ADDiscovery


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


def fake_computer(dns=None, name=None):
    attrs = []
    if dns:
        attrs.append(FakeAttr("dNSHostName", [dns]))
    if name:
        attrs.append(FakeAttr("name", [name]))
    return FakeEntry(attrs)


def fake_user(name):
    return FakeEntry([FakeAttr("sAMAccountName", [name])])


# ---------- tests ----------

def test_get_domain_computers_dns_hostname():
    cfg = MagicMock()
    cfg.auth.domain = "example.com"

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
    cfg = MagicMock()
    cfg.auth.domain = "example.com"

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
    cfg = MagicMock()
    cfg.auth.domain = "example.com"

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
    cfg = MagicMock()
    cfg.auth.domain = "example.com"

    discovery = ADDiscovery(cfg)
    ldap = MagicMock()
    ldap.search.side_effect = Exception("boom")

    with patch.object(
        discovery.ldap_transport, "connect", return_value=ldap
    ):
        users = discovery.get_domain_users()

    assert users == []
