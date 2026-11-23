import json

import pytest
from fastapi.testclient import TestClient

from sentinel.api.main import app
from tests.test_ingest import load_all


@pytest.fixture
def client():
    load_all()
    with TestClient(app) as c:
        yield c


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_list_and_filter(client):
    page = client.get("/api/v1/indicators", params={"bd_only": True}).json()
    assert page["total"] > 0
    assert all(item["bd_relevant"] for item in page["items"])
    scores = [item["score"] for item in page["items"]]
    assert scores == sorted(scores, reverse=True)

    ips = client.get("/api/v1/indicators", params={"type": "ipv4", "source": "threatfox"}).json()
    assert [i["value"] for i in ips["items"]] == ["185.220.101.45"]


def test_lookup_refangs_input(client):
    hit = client.get("/api/v1/lookup", params={"value": "hxxps://nagad-verify-account[.]com/login"}).json()
    assert hit["found"] and hit["type"] == "url"
    miss = client.get("/api/v1/lookup", params={"value": "example.org"}).json()
    assert miss["found"] is False and miss["normalized"] == "example.org"
    junk = client.get("/api/v1/lookup", params={"value": "???"}).json()
    assert junk["found"] is False and junk["type"] is None


def test_stats(client):
    stats = client.get("/api/v1/stats").json()
    assert stats["total"] > 0 and stats["bd_relevant"] > 0
    assert set(stats["by_source"]) == {"feodotracker", "urlhaus", "threatfox", "openphish"}


def test_ip_feed_excludes_allowlisted_and_low_scores(client):
    response = client.get("/feeds/ip.txt")
    lines = response.text.split()
    assert "185.220.101.45" in lines and "103.4.145.10" in lines
    assert "8.8.8.8" not in lines        # allowlisted resolver
    assert "45.95.11.20" not in lines    # decayed below 50
    assert response.headers["x-indicator-count"] == str(len(lines))


def test_domain_feed_and_url_feed_allowlist_rules(client):
    domains = client.get("/feeds/domain.txt", params={"min_score": 0}).text.split()
    assert "github.com" not in domains and "nagad-verify-account.com" in domains
    # The exact malicious GitHub URL is still blockable.
    urls = client.get("/feeds/url.txt", params={"strip_scheme": True}).text.split()
    assert "raw.githubusercontent.com/someone/repo/main/stealer.ps1" in urls


def test_rpz(client):
    zone = client.get("/feeds/rpz.zone", params={"min_score": 0}).text
    assert "$TTL" in zone and "nagad-verify-account.com CNAME ." in zone
    assert "*.nagad-verify-account.com CNAME ." in zone and "github.com CNAME" not in zone


def test_stix_bundle(client):
    bundle = json.loads(client.get("/feeds/stix.json", params={"bd_only": True}).text)
    assert bundle["type"] == "bundle"
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert indicators and all(o["spec_version"] == "2.1" for o in indicators)
    patterns = {o["pattern"] for o in indicators}
    assert "[ipv4-addr:value = '103.4.145.10']" in patterns
    # Stable ids: the same indicator gets the same id on every export.
    again = json.loads(client.get("/feeds/stix.json", params={"bd_only": True}).text)
    assert {o["id"] for o in again["objects"]} == {o["id"] for o in bundle["objects"]}
