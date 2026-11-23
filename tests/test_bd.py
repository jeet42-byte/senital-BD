from sentinel.bd import BdIpRanges, bd_reasons, impersonated_brands, parse_apnic_delegated
from tests.conftest import fixture_text

RANGES = BdIpRanges(["103.4.144.0/22", "114.130.0.0/16"])


def test_parse_apnic_keeps_only_bd_ipv4_allocations():
    cidrs = parse_apnic_delegated(fixture_text("apnic_sample.txt"))
    # 768 addresses is not a power of two: it needs two CIDRs.
    assert cidrs == ["103.4.144.0/22", "114.130.0.0/16", "202.4.96.0/23", "202.4.98.0/24"]


def test_range_membership():
    assert "103.4.145.10" in RANGES
    assert "103.4.148.0" not in RANGES
    assert "114.130.255.255" in RANGES
    assert "8.8.8.8" not in RANGES
    assert "garbage" not in RANGES


def test_impersonation():
    assert impersonated_brands("bkash-reward-bd.top") == ["bKash"]
    assert impersonated_brands("dutch-bangla-login.xyz") == ["Dutch-Bangla Bank"]
    # The genuine sites are never flagged as imitating themselves.
    assert impersonated_brands("www.bkash.com") == []
    assert impersonated_brands("paypal-account-check.com") == []


def test_reasons():
    assert bd_reasons("domain", "evil.com.bd", ranges=RANGES) == ["tld:.bd"]
    assert bd_reasons("url", "http://103.4.145.10:41234/Mozi.m", ranges=RANGES) == ["ip:bd-space"]
    assert bd_reasons("ipv4", "185.220.101.45", "BD", ranges=RANGES) == ["geo:BD"]
    assert bd_reasons("sha256", "a" * 64, ranges=RANGES) == []
