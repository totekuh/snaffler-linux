from unittest.mock import MagicMock, patch

from snaffler.engine.domain_pipeline import DomainPipeline


def make_cfg():
    cfg = MagicMock()

    cfg.auth.domain = "example.com"
    cfg.targets.ldap_filter = "(objectClass=computer)"
    cfg.targets.exclusions = []

    return cfg


def test_domain_pipeline_basic():
    cfg = make_cfg()

    with patch(
        "snaffler.engine.domain_pipeline.ADDiscovery"
    ) as ad_cls:
        ad = ad_cls.return_value
        ad.get_domain_computers.return_value = [
            "host1.example.com",
            "host2.example.com",
        ]

        pipeline = DomainPipeline(cfg)
        result = pipeline.run()

    assert result == ["host1.example.com", "host2.example.com"]
    ad.get_domain_computers.assert_called_once_with(
        ldap_filter="(objectClass=computer)"
    )


def test_domain_pipeline_exclusions():
    cfg = make_cfg()
    cfg.targets.exclusions = ["host2.example.com"]

    with patch(
        "snaffler.engine.domain_pipeline.ADDiscovery"
    ) as ad_cls:
        ad = ad_cls.return_value
        ad.get_domain_computers.return_value = [
            "host1.example.com",
            "host2.example.com",
        ]

        pipeline = DomainPipeline(cfg)
        result = pipeline.run()

    assert result == ["host1.example.com"]


def test_domain_pipeline_empty_result():
    cfg = make_cfg()

    with patch(
        "snaffler.engine.domain_pipeline.ADDiscovery"
    ) as ad_cls:
        ad = ad_cls.return_value
        ad.get_domain_computers.return_value = []

        pipeline = DomainPipeline(cfg)
        result = pipeline.run()

    assert result == []


def test_get_dfs_shares_delegates():
    cfg = make_cfg()

    with patch(
        "snaffler.engine.domain_pipeline.ADDiscovery"
    ) as ad_cls:
        ad = ad_cls.return_value
        ad.get_dfs_targets.return_value = [
            "//nas01.corp.local/data",
            "//fileserver.domain.com/docs",
        ]

        pipeline = DomainPipeline(cfg)
        result = pipeline.get_dfs_shares()

    assert result == [
        "//nas01.corp.local/data",
        "//fileserver.domain.com/docs",
    ]
    ad.get_dfs_targets.assert_called_once()


def test_get_dfs_shares_applies_exclusions():
    cfg = make_cfg()
    cfg.targets.exclusions = ["NAS01.CORP.LOCAL"]

    with patch(
        "snaffler.engine.domain_pipeline.ADDiscovery"
    ) as ad_cls:
        ad = ad_cls.return_value
        ad.get_dfs_targets.return_value = [
            "//nas01.corp.local/data",
            "//fileserver.domain.com/docs",
        ]

        pipeline = DomainPipeline(cfg)
        result = pipeline.get_dfs_shares()

    assert result == ["//fileserver.domain.com/docs"]


def test_dfs_exclusion_exact_hostname_no_false_positive():
    """BUG-N: excluding 'NAS01' must NOT filter '//nas01server/share' (substring)."""
    cfg = make_cfg()
    cfg.targets.exclusions = ["NAS01"]

    with patch(
        "snaffler.engine.domain_pipeline.ADDiscovery"
    ) as ad_cls:
        ad = ad_cls.return_value
        ad.get_dfs_targets.return_value = [
            "//nas01server/share",
            "//other/docs",
        ]

        pipeline = DomainPipeline(cfg)
        result = pipeline.get_dfs_shares()

    # "nas01server" != "NAS01", so the path must NOT be excluded
    assert "//nas01server/share" in result
    assert "//other/docs" in result


def test_dfs_exclusion_exact_hostname_case_insensitive():
    """BUG-N: excluding 'NAS01.CORP.LOCAL' DOES filter '//nas01.corp.local/share'."""
    cfg = make_cfg()
    cfg.targets.exclusions = ["NAS01.CORP.LOCAL"]

    with patch(
        "snaffler.engine.domain_pipeline.ADDiscovery"
    ) as ad_cls:
        ad = ad_cls.return_value
        ad.get_dfs_targets.return_value = [
            "//nas01.corp.local/share",
            "//fileserver.domain.com/docs",
        ]

        pipeline = DomainPipeline(cfg)
        result = pipeline.get_dfs_shares()

    assert result == ["//fileserver.domain.com/docs"]
