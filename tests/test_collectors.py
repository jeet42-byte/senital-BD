from sentinel.collectors import COLLECTORS
from sentinel.indicators import IndicatorType as T
from tests.conftest import fixture_text


def parse(name, fixture):
    return list(COLLECTORS[name].parse(fixture_text(fixture)))


def test_urlhaus():
    rows = parse("urlhaus", "urlhaus.csv")
    assert len(rows) == 6  # comments skipped; invalid values are dropped later, at ingest
    first = rows[0]
    assert first.type is T.URL and first.value == "http://103.4.145.10:41234/Mozi.m"
    assert first.tags == ["elf", "mozi"]
    assert first.last_seen is None  # online: live now
    offline = rows[2]
    assert offline.last_seen.isoformat() == "2026-11-21T00:00:00+00:00"


def test_feodo():
    rows = parse("feodotracker", "feodo.json")
    assert [r.value for r in rows] == ["185.220.101.45", "103.4.145.10", "45.95.11.20", "8.8.8.8"]
    assert rows[1].country == "BD" and rows[1].malware == "Emotet"
    assert "port:8080" in rows[1].tags
    assert rows[2].last_seen.date().isoformat() == "2026-09-15"


def test_threatfox():
    rows = parse("threatfox", "threatfox.json")
    kinds = {r.value: r.type for r in rows}
    assert kinds["185.220.101.45:443"] is T.IPV4
    assert kinds["nagad-verify-account.com"] is T.DOMAIN
    assert len(rows) == 4  # the unsupported ioc_type is skipped
    unknown = next(r for r in rows if r.value == "github.com")
    assert unknown.malware is None  # "Unknown malware" is not a family


def test_openphish():
    rows = parse("openphish", "openphish.txt")
    assert len(rows) == 4 and all(r.threat_type == "phishing" for r in rows)
