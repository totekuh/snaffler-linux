#!/usr/bin/env python3
import pytest

from snaffler.utils.target_parser import expand_targets


class TestCIDR:
    def test_slash_24_expands_to_254(self):
        result = expand_targets(["10.0.0.0/24"])
        assert len(result) == 254
        assert result[0] == "10.0.0.1"
        assert result[-1] == "10.0.0.254"

    def test_slash_32_expands_to_1(self):
        result = expand_targets(["10.0.0.5/32"])
        assert result == ["10.0.0.5"]

    def test_slash_31_expands_to_2(self):
        result = expand_targets(["10.0.0.4/31"])
        assert result == ["10.0.0.4", "10.0.0.5"]

    def test_slash_16(self):
        result = expand_targets(["172.16.0.0/16"])
        assert len(result) == 65534

    def test_non_strict_host_bits(self):
        """10.0.0.5/24 should be treated as 10.0.0.0/24 (strict=False)."""
        result = expand_targets(["10.0.0.5/24"])
        assert len(result) == 254
        assert result[0] == "10.0.0.1"

    def test_invalid_cidr_raises(self):
        with pytest.raises(ValueError, match="Invalid CIDR"):
            expand_targets(["999.999.999.0/24"])


class TestDashRange:
    def test_last_octet_range(self):
        result = expand_targets(["10.0.0.1-5"])
        assert result == [
            "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"
        ]

    def test_single_ip_range(self):
        result = expand_targets(["10.0.0.3-3"])
        assert result == ["10.0.0.3"]

    def test_full_range(self):
        result = expand_targets(["10.0.0.1-10.0.0.5"])
        assert result == [
            "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"
        ]

    def test_full_range_single(self):
        result = expand_targets(["10.0.0.1-10.0.0.1"])
        assert result == ["10.0.0.1"]

    def test_reversed_range_raises(self):
        with pytest.raises(ValueError, match="before start"):
            expand_targets(["10.0.0.5-10.0.0.1"])

    def test_reversed_octet_raises(self):
        with pytest.raises(ValueError, match="before start"):
            expand_targets(["10.0.0.50-10"])

    def test_invalid_base_ip_raises(self):
        with pytest.raises(ValueError, match="Invalid IP range"):
            expand_targets(["999.0.0.1-5"])

    def test_non_numeric_end_raises(self):
        with pytest.raises(ValueError, match="not a number"):
            expand_targets(["10.0.0.1-abc"])


class TestPassthrough:
    def test_hostname_passthrough(self):
        result = expand_targets(["dc01.corp.local"])
        assert result == ["dc01.corp.local"]

    def test_bare_ip_passthrough(self):
        result = expand_targets(["10.0.0.1"])
        assert result == ["10.0.0.1"]

    def test_empty_list(self):
        assert expand_targets([]) == []


class TestMixed:
    def test_mixed_targets(self):
        targets = [
            "dc01.corp.local",
            "10.0.0.0/30",
            "192.168.1.10-15",
            "172.16.0.1",
        ]
        result = expand_targets(targets)
        assert result == [
            "dc01.corp.local",
            "10.0.0.1", "10.0.0.2",           # /30 = 2 usable hosts
            "192.168.1.10", "192.168.1.11",
            "192.168.1.12", "192.168.1.13",
            "192.168.1.14", "192.168.1.15",
            "172.16.0.1",
        ]
