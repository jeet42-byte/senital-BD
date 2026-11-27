import gzip
from datetime import datetime, timezone

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from sentinel import vulns
from sentinel.db import session_scope
from sentinel.indicators import IndicatorType as T
from sentinel.ingest import ingest_raw
from sentinel.models import Advisory, FeedRun, Indicator, Vulnerability
from tests.conftest import fixture_text

NOW = datetime(2026, 11, 27, tzinfo=timezone.utc)
EPSS_CSV = (
    "#model_version:v2025.03.14,score_date:2026-11-26T12:55:00+0000\n"
    "cve,epss,percentile\n"
    "CVE-2026-1001,0.91,0.999\n"
    "CVE-2024-3400,0.97,0.999\n"
    "CVE-2026-2002,0.75,0.99\n"
    "CVE-2020-0001,0.01,0.20\n"
)


def load_kev():
    with session_scope() as s:
        vulns.apply_kev(s, vulns.parse_kev(fixture_text("kev.json")))


def test_kev_is_applied_and_junk_ignored():
    load_kev()
    with session_scope() as s:
        v = s.get(Vulnerability, "CVE-2026-1001")
        assert v.in_kev and v.ransomware_use and v.vendor == "Fortinet"
        assert v.kev_due.date().isoformat() == "2026-12-11"
        assert s.get(Vulnerability, "CVE-2024-3400").ransomware_use is False
        assert len(s.scalars(select(Vulnerability)).all()) == 2


def test_epss_bulk_scores_and_adds_likely_next():
    load_kev()
    scores = vulns.parse_epss_csv(gzip.compress(EPSS_CSV.encode()))
    assert scores["CVE-2026-2002"] == (0.75, 0.99)
    with session_scope() as s:
        assert vulns.apply_epss(s, scores, bulk=True) == 1  # CVE-2026-2002 only (>= 0.5, not in KEV)
    with session_scope() as s:
        assert s.get(Vulnerability, "CVE-2026-1001").epss == 0.91
        likely = s.get(Vulnerability, "CVE-2026-2002")
        assert likely and not likely.in_kev
        assert s.get(Vulnerability, "CVE-2020-0001") is None


def test_priority_parts_add_up():
    v = Vulnerability(cve_id="CVE-X", in_kev=True, epss=0.91, ransomware_use=True, bd_advisories=1,
                      kev_added=datetime(2026, 11, 20, tzinfo=timezone.utc))
    parts = vulns.priority_parts(v, NOW)
    assert parts == {"exploited": 50, "epss": 36, "ransomware": 10, "bd_advisory": 15, "recent": 10}
    vulns.rescore(v, NOW)
    assert v.priority == 100  # capped


def test_cirt_links_and_advisory_parsing():
    links = vulns.advisory_links(fixture_text("cirt_listing.html"))
    assert links == [
        "https://www.cirt.gov.bd/alerts/critical-fortios-vulnerability-actively-exploited",
        "https://www.cirt.gov.bd/alerts/bkash-phishing-campaign-targeting-customers",
    ]
    adv = vulns.parse_advisory(links[1], fixture_text("cirt_advisory.html"))
    assert adv["title"] == "Phishing campaign targeting bKash customers"
    assert adv["published"].date().isoformat() == "2026-11-21"
    assert adv["cves"] == ["CVE-2025-9999", "CVE-2026-1001"]
    iocs = set(adv["iocs"])
    assert (T.URL, "https://bkash-reward-bd.top/login") in iocs
    assert (T.DOMAIN, "bkash-verify.xyz") in iocs and (T.IPV4, "45.95.11.20") in iocs
    assert (T.SHA256, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08") in iocs
    # Plain, non-defanged links are the advisory's own or legitimate sites.
    assert not any("cirt.gov.bd" in v or v.startswith("https://www.bkash.com") for _, v in iocs)


def test_advisories_flag_cves_and_become_bd_indicators():
    load_kev()
    adv = vulns.parse_advisory("https://www.cirt.gov.bd/alerts/x-y-z-advisory", fixture_text("cirt_advisory.html"))
    with session_scope() as s:
        new, raws = vulns.apply_advisories(s, [adv])
        ingest_raw(s, "bgd-cirt", raws)
    with session_scope() as s:
        assert new == 1 and s.get(Vulnerability, "CVE-2026-1001").bd_advisories == 1
        assert s.get(Vulnerability, "CVE-2025-9999").bd_advisories == 1  # not in KEV, still tracked
        ip = s.scalar(select(Indicator).where(Indicator.value == "45.95.11.20"))
        assert ip.bd_relevant and "cirt:BGD e-GOV CIRT" in ip.bd_reasons
        assert ip.sightings[0].reference.endswith("x-y-z-advisory")


def test_full_run_with_one_source_failing(monkeypatch):
    listing, detail = fixture_text("cirt_listing.html"), fixture_text("cirt_advisory.html")

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == vulns.KEV_URL:
            return httpx.Response(200, text=fixture_text("kev.json"))
        if url == vulns.EPSS_BULK_URL:
            return httpx.Response(503)  # bulk file down: the API fallback is used
        if url.startswith(vulns.EPSS_API_URL):
            return httpx.Response(200, json={"data": [{"cve": "CVE-2026-1001", "epss": "0.5", "percentile": "0.9"}]})
        if url.rstrip("/").endswith(("/alerts", "/news", "/bulletins")):
            return httpx.Response(200, text=listing)
        if "/alerts/" in url:
            return httpx.Response(200, text=detail)
        return httpx.Response(404)

    monkeypatch.setattr(vulns, "_client", lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(vulns.time, "sleep", lambda s: None)
    assert vulns.run({"kev", "epss", "cirt"}) == 0
    with session_scope() as s:
        runs = {r.source: r.ok for r in s.scalars(select(FeedRun))}
        assert runs == {"cisa-kev": True, "bgd-cirt": True, "epss": True}
        v = s.get(Vulnerability, "CVE-2026-1001")
        assert v.epss == 0.5 and v.bd_advisories == 2 and v.priority > 80
        assert len(s.scalars(select(Advisory)).all()) == 2


@pytest.fixture
def client():
    load_kev()
    with session_scope() as s:
        vulns.apply_epss(s, vulns.parse_epss_csv(EPSS_CSV.encode()), bulk=True)
        adv = vulns.parse_advisory("https://www.cirt.gov.bd/alerts/x-y-z-advisory", fixture_text("cirt_advisory.html"))
        vulns.apply_advisories(s, [adv])
        for v in s.scalars(select(Vulnerability)):
            vulns.rescore(v)
    from sentinel.api.main import app
    with TestClient(app) as c:
        yield c


def test_vulnerability_api_views(client):
    top = client.get("/api/v1/vulnerabilities").json()
    assert top["items"][0]["cve_id"] == "CVE-2026-1001"
    assert top["kev_total"] == 2 and top["ransomware_linked"] == 1 and top["in_bd_advisories"] == 2
    assert sum(top["items"][0]["priority_parts"].values()) >= top["items"][0]["priority"]
    likely = client.get("/api/v1/vulnerabilities", params={"view": "likely"}).json()["items"]
    assert [v["cve_id"] for v in likely][0] == "CVE-2026-2002"
    bd = {v["cve_id"] for v in client.get("/api/v1/vulnerabilities", params={"view": "bd"}).json()["items"]}
    assert bd == {"CVE-2026-1001", "CVE-2025-9999"}
    assert client.get("/api/v1/vulnerabilities", params={"q": "palo"}).json()["items"][0]["cve_id"] == "CVE-2024-3400"
    advisories = client.get("/api/v1/advisories").json()
    assert advisories[0]["cves"] == ["CVE-2025-9999", "CVE-2026-1001"]
