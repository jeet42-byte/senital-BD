import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from sentinel.bd import BdIpRanges, bd_reasons
from sentinel.collectors import COLLECTORS
from sentinel.db import session_scope
from sentinel.indicators import IndicatorType as T
from sentinel.indicators import guess_type, normalize
from sentinel.ingest import ingest_raw
from sentinel.models import Indicator
from tests.conftest import NOW, fixture_text
from tests.test_ingest import load_all


@pytest.mark.parametrize("raw,expected", [
    ("1.10.16.5/20", "1.10.16.0/20"),
    ("103.4.144.0/23", "103.4.144.0/23"),
    ("10.0.0.0/8", None),      # private
    ("0.0.0.0/2", None),       # far too broad
    ("1.2.3.4/33", None),
    ("1.2.3[.]0/24", "1.2.3.0/24"),
])
def test_cidr_normalisation(raw, expected):
    assert normalize(T.CIDR, raw) == expected


def test_cidr_is_recognised_in_lookups():
    assert guess_type("1.10.16.0/20") is T.CIDR
    assert guess_type("http://1.2.3.4/x") is T.URL


def test_bd_overlap_for_ranges():
    ranges = BdIpRanges(["103.4.144.0/22"])
    assert "ip:bd-space" in bd_reasons("cidr", "103.4.144.0/23", ranges=ranges)
    assert "ip:bd-space" in bd_reasons("cidr", "103.0.0.0/8", ranges=ranges)  # covers BD space
    assert bd_reasons("cidr", "1.10.16.0/20", ranges=ranges) == []


def test_collectors_parse_their_feeds():
    bl = list(COLLECTORS["blocklist.de"].parse(fixture_text("blocklistde.txt")))
    assert len(bl) == 5 and bl[0].threat_type == "bruteforce"
    cins = list(COLLECTORS["cins"].parse(fixture_text("cins.txt")))
    assert [r.value for r in cins] == ["198.18.0.1", "61.177.172.10"]
    drop = list(COLLECTORS["spamhaus-drop"].parse(fixture_text("spamhaus_drop.json")))
    assert len(drop) == 5 and drop[0].type is T.CIDR  # metadata line skipped
    assert drop[0].reference.endswith("SBL256894")
    text_form = list(COLLECTORS["spamhaus-drop"].parse("; Spamhaus DROP\n1.10.16.0/20 ; SBL256894\n"))
    assert text_form[0].value == "1.10.16.0/20"


def test_ingest_rejects_bad_values_and_corroborates_honeypot_style_ips():
    with session_scope() as s:
        stats = ingest_raw(s, "blocklist.de", COLLECTORS["blocklist.de"].parse(fixture_text("blocklistde.txt")), now=NOW)
        assert stats.rejected == 3  # IPv6, junk, private
        drop = ingest_raw(s, "spamhaus-drop", COLLECTORS["spamhaus-drop"].parse(fixture_text("spamhaus_drop.json")), now=NOW)
        assert drop.created == 3 and drop.rejected == 2
    load_all()
    with session_scope() as s:
        ip = s.scalar(select(Indicator).where(Indicator.value == "185.220.101.45"))
        assert {x.source for x in ip.sightings} >= {"blocklist.de", "feodotracker"}
        bd_range = s.scalar(select(Indicator).where(Indicator.value == "103.4.144.0/23"))
        assert bd_range.bd_relevant and bd_range.score == 100


@pytest.fixture
def client():
    load_all()
    with session_scope() as s:
        ingest_raw(s, "spamhaus-drop", COLLECTORS["spamhaus-drop"].parse(fixture_text("spamhaus_drop.json")), now=NOW)
    from sentinel.api.main import app
    with TestClient(app) as c:
        yield c


def test_ip_feed_includes_ranges_but_never_one_covering_public_dns(client):
    lines = client.get("/feeds/ip.txt").text.split()
    assert "1.10.16.0/20" in lines and "103.4.144.0/23" in lines
    assert "8.8.8.0/24" not in lines  # contains 8.8.8.8
    rsc = client.get("/feeds/mikrotik.rsc").text
    assert "address=1.10.16.0/20" in rsc


def test_lookup_reports_containing_ranges(client):
    hit = client.get("/api/v1/lookup", params={"value": "1.10.17.200"}).json()
    assert hit["found"] is False and hit["ranges"][0]["value"] == "1.10.16.0/20"
    known = client.get("/api/v1/lookup", params={"value": "103.4.145.10"}).json()
    assert known["found"] and known["ranges"][0]["value"] == "103.4.144.0/23"
    assert client.get("/api/v1/lookup", params={"value": "1.10.16.0/20"}).json()["found"]
