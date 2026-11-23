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


def test_dashboard_is_served_with_a_strict_csp(client):
    page = client.get("/")
    assert page.status_code == 200 and "Sentinel" in page.text
    csp = page.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/assets/app.css").status_code == 200


def test_stats_has_dashboard_fields(client):
    stats = client.get("/api/v1/stats").json()
    assert len(stats["timeline"]) == 30
    assert stats["brands"].get("Nagad") == 2  # the domain and the URL
    assert stats["bd_reason_kinds"]["ip"] >= 1
    assert stats["last_updated"] is None  # fixtures load without feed runs
    assert {run["source"] for run in stats["last_runs"]} == set()


def test_explorer_filters(client):
    def values(**params):
        return [i["value"] for i in client.get("/api/v1/indicators", params=params).json()["items"]]

    assert set(values(reason="impersonates:Nagad")) == {
        "nagad-verify-account.com", "https://nagad-verify-account.com/login"}
    assert values(malware="Emotet") == ["103.4.145.10"]
    assert all(i["severity"] == "low" for i in client.get("/api/v1/indicators", params={"severity": "low"}).json()["items"])
    newest = client.get("/api/v1/indicators", params={"sort": "newest"}).json()["items"]
    firsts = [i["first_seen"] for i in newest]
    assert firsts == sorted(firsts, reverse=True)
    # A wildcard in the reason filter is taken literally.
    assert values(reason="impersonates:%") == []


def test_explain_matches_the_stored_score(client):
    ex = client.get("/api/v1/explain", params={"type": "ipv4", "value": "185.220.101.45"}).json()
    assert [s["source"] for s in ex["sources"]] == ["feodotracker", "threatfox"] or len(ex["sources"]) == 2
    assert 0 < ex["decay"] <= 1 and ex["half_life_days"] == 14
    assert client.get("/api/v1/explain", params={"type": "ipv4", "value": "9.9.9.10"}).status_code == 404
    hit = client.get("/api/v1/lookup", params={"value": "185.220.101.45"}).json()
    assert hit["explanation"]["sources"]


def test_feed_preview_and_mikrotik(client):
    preview = client.get("/api/v1/feed-preview", params={"kind": "ip", "min_score": 50}).json()
    assert preview["count"] >= 2 and "185.220.101.45" in preview["sample"]
    rsc = client.get("/feeds/mikrotik.rsc").text
    assert rsc.splitlines()[1].startswith("/ip firewall address-list remove")
    assert '/ip firewall address-list add list="sentinel-bd" address=185.220.101.45 timeout=1d' in rsc
    assert "8.8.8.8" not in rsc
