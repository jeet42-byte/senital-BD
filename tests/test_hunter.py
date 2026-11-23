import json

import httpx
import pytest
from sqlalchemy import select

from sentinel.allowlist import is_allowlisted_domain
from sentinel.collectors.base import FeedError
from sentinel.db import session_scope
from sentinel.hunter.crtsh import CrtShHunter
from sentinel.hunter.detect import analyze
from sentinel.hunter.stream import StreamHunter, domains_from_message
from sentinel.ingest import ingest_raw, run_collector
from sentinel.models import Indicator
from tests.conftest import NOW, fixture_text

CYRILLIC_A = "а"


@pytest.mark.parametrize(
    "name,technique,brand,indicator",
    [
        ("bkash-verify-account.top", "exact", "bKash", "bkash-verify-account.top"),
        ("*.bkash-reward.online", "exact", "bKash", "bkash-reward.online"),
        ("bkassh-login.com", "typosquat", "bKash", "bkassh-login.com"),
        ("bksh-login.com", "typosquat", "bKash", "bksh-login.com"),
        ("bkahs-offer.top", "typosquat", "bKash", "bkahs-offer.top"),
        ("bka5h.xyz", "digit-swap", "bKash", "bka5h.xyz"),
        ("nag4d-app.top", "digit-swap", "Nagad", "nag4d-app.top"),
        (f"bk{CYRILLIC_A}sh-login.com", "homoglyph", "bKash", None),
        ("bkash.com.secure-login.top", "subdomain", "bKash", "secure-login.top"),
        ("nagad-bonus.pages.dev", "exact", "Nagad", "nagad-bonus.pages.dev"),
        ("gramenphone-offer.shop", "typosquat", "Grameenphone", "gramenphone-offer.shop"),
        ("sonalibank-update.info", "exact", "Sonali Bank", "sonalibank-update.info"),
    ],
)
def test_lookalikes_are_reported(name, technique, brand, indicator):
    finding = analyze(name)
    assert finding is not None and finding.reportable, finding
    assert finding.technique == technique and finding.brand == brand
    if indicator:
        assert finding.indicator == indicator
    assert finding.reasons


@pytest.mark.parametrize(
    "name",
    [
        "bkash.com", "www.bkash.com", "merchant.bkash.com", "nagad.com.bd", "sonalibank.com.bd",
        "islamibankbd.com", "google.com", "paypal-login.com", "primebank.com.bd",
        # The owner's own login page is not a lookalike of anything.
        "login.primebank.com", "secure-login.teletalk-bd.com",
        # Real words and names one letter from a brand
        "ramnagar.com", "dhakanagar-login.top", "bikashroy.com", "akashtv.com", "prakash-traders.com",
    ],
)
def test_genuine_and_unrelated_names_are_not_flagged(name):
    finding = analyze(name)
    assert finding is None or not finding.reportable, finding


def test_weak_matches_stay_below_threshold():
    assert not analyze("bkashagent.com.bd").reportable  # .bd agent sites are often genuine
    assert not analyze("teletalkk.com").reportable


def test_user_platform_subdomains_are_blockable_but_platforms_are_not():
    assert not is_allowlisted_domain("nagad-bonus.pages.dev")
    assert is_allowlisted_domain("pages.dev") and is_allowlisted_domain("www.github.io")
    assert is_allowlisted_domain("raw.githubusercontent.com")  # shared: never block


def test_crtsh_parse_keeps_recent_lookalikes_only():
    raws = list(CrtShHunter().parse(fixture_text("crtsh.json"), now=NOW))
    values = sorted({r.value for r in raws})
    # The genuine bkash.com certificate, the 50-day-old one and the weak .bd
    # agent name are all left out.
    assert values == ["bkash-reward-bd.top", "dutch-bangla-ibanking.xyz", "nag4d-app.top"]
    nag = next(r for r in raws if r.value == "nag4d-app.top")
    assert nag.extra_reasons == ["impersonates:Nagad"]
    assert nag.reference == "https://crt.sh/?id=9000000002"
    assert "digits" in nag.note and nag.confidence >= 55


def test_crtsh_fetch_survives_one_failing_token_but_not_all():
    calls = []

    def handler(request):
        calls.append(request.url)
        if "nagad" in str(request.url):
            return httpx.Response(502)
        return httpx.Response(200, text=fixture_text("crtsh.json"))

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        text = CrtShHunter(["bkash", "nagad"], pause=0, retry_waits=(0,)).fetch(client)
    assert len(json.loads(text)) == 6
    assert "q=%25bkash%25" in str(calls[0]) and "exclude=expired" in str(calls[0])

    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(503))) as client:
        with pytest.raises(FeedError, match="every token"):
            CrtShHunter(["bkash", "nagad"], pause=0, retry_waits=(0,)).fetch(client)


def test_findings_become_scored_bd_indicators():
    with session_scope() as session:
        ingest_raw(session, "phishhunter", CrtShHunter().parse(fixture_text("crtsh.json"), now=NOW), now=NOW)
    with session_scope() as session:
        row = session.scalar(select(Indicator).where(Indicator.value == "nag4d-app.top"))
        assert row.bd_relevant and "impersonates:Nagad" in row.bd_reasons
        assert row.threat_type == "phishing_lookalike" and "digit-swap" in row.tags
        assert row.sightings[0].note and row.sightings[0].source == "phishhunter"
        # 0.65 reliability x its own risk score, plus the Bangladesh boost.
        expected = round(100 * 0.65 * row.sightings[0].confidence / 100) + 10
        assert abs(row.score - expected) <= 1


def test_run_collector_accepts_a_hunter_instance():
    run = run_collector(CrtShHunter(), text=fixture_text("crtsh.json"))
    assert run.ok and run.source == "phishhunter"


def test_stream_messages():
    full = json.dumps({"message_type": "certificate_update",
                       "data": {"leaf_cert": {"all_domains": ["bkash-login.top", "example.org"]}, "seen": 1795000000.0}})
    names, when = domains_from_message(full)
    assert names == ["bkash-login.top", "example.org"] and when.year == 2026
    assert domains_from_message(json.dumps({"message_type": "dns_entries", "data": ["a.com"]}))[0] == ["a.com"]
    assert domains_from_message("not json") == ([], None)
    assert domains_from_message(json.dumps({"message_type": "heartbeat"})) == ([], None)


def test_stream_hunter_batches_and_writes():
    hunter = StreamHunter()
    message = json.dumps({"message_type": "dns_entries",
                          "data": ["bkash-login.top", "www.bkash-login.top", "example.org", "bkash.com"]})
    assert hunter.handle(message) == 1  # one lookalike, deduplicated
    assert hunter.flush() == 1 and hunter.flush() == 0
    with session_scope() as session:
        assert session.scalar(select(Indicator).where(Indicator.value == "bkash-login.top")) is not None


def test_new_columns_are_added_to_an_existing_database(tmp_path):
    from sqlalchemy import create_engine, inspect, text

    from sentinel import db

    url = f"sqlite:///{tmp_path / 'old.db'}"
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text(
            "CREATE TABLE sighting (id INTEGER PRIMARY KEY, indicator_id INTEGER, source VARCHAR(32), "
            "first_seen DATETIME, last_seen DATETIME, confidence INTEGER, reference TEXT)"))
    db.init_db(url)
    assert "note" in {c["name"] for c in inspect(create_engine(url)).get_columns("sighting")}


def test_crtsh_retries_a_busy_answer():
    answers = iter([httpx.Response(429), httpx.Response(502), httpx.Response(200, text="[]")])
    with httpx.Client(transport=httpx.MockTransport(lambda r: next(answers))) as client:
        assert CrtShHunter(["bkash"], pause=0, retry_waits=(0, 0)).fetch(client) == "[]"


def test_backfill_window_is_configurable():
    old = list(CrtShHunter(lookback_days=90).parse(fixture_text("crtsh.json"), now=NOW))
    assert "bkash-login-verify.xyz" in {r.value for r in old}


def test_slow_fetch_holds_no_database_transaction(monkeypatch):
    """The download must finish before the database is touched."""
    from sentinel import db as dbmod

    events = []
    real_scope = dbmod.session_scope

    class SlowHunter(CrtShHunter):
        def fetch(self, client):
            events.append("fetch")
            return fixture_text("crtsh.json")

    def watched_scope():
        events.append("session")
        return real_scope()

    monkeypatch.setattr("sentinel.ingest.session_scope", watched_scope)
    run = run_collector(SlowHunter(), client=object())
    assert run.ok and events == ["fetch", "session"]


@pytest.mark.parametrize("name", ["hojatkashfi2.workers.dev", "primebaskets.store", "mytkash.com", "sonalibanker.org"])
def test_typos_inside_longer_words_are_ignored(name):
    finding = analyze(name)
    assert finding is None or not finding.reportable, finding


@pytest.mark.parametrize("name", ["bkassh24.top", "prime-bnak-login.top", "bkash1-login.xyz"])
def test_whole_word_typos_still_found(name):
    finding = analyze(name)
    assert finding and finding.reportable and finding.technique in ("typosquat", "exact")


def test_stream_does_not_retry_an_empty_flush_every_message():
    hunter = StreamHunter()
    before = hunter.last_flush
    assert hunter.flush() == 0 and hunter.last_flush >= before


def test_recheck_drops_findings_the_detector_now_rejects(capsys):
    from sentinel.collectors.base import RawIndicator
    from sentinel.hunter.__main__ import recheck
    from sentinel.indicators import IndicatorType

    with session_scope() as session:
        ingest_raw(session, "phishhunter", [
            RawIndicator(IndicatorType.DOMAIN, "primebaskets.store", "phishhunter", confidence=70),
            RawIndicator(IndicatorType.DOMAIN, "bkash-verify-login.top", "phishhunter", confidence=80),
        ])
        ingest_raw(session, "threatfox", [RawIndicator(IndicatorType.DOMAIN, "primebaskets.store", "threatfox", confidence=50)])
    from sentinel.hunter.__main__ import main as hunter_cli

    assert hunter_cli(["recheck", "--dry-run"]) == 0  # through the real command line
    assert "would be removed" in capsys.readouterr().out
    assert hunter_cli(["recheck"]) == 0
    with session_scope() as session:
        kept = session.scalar(select(Indicator).where(Indicator.value == "primebaskets.store"))
        assert [s.source for s in kept.sightings] == ["threatfox"]  # the feed's report stays
        assert session.scalar(select(Indicator).where(Indicator.value == "bkash-verify-login.top"))
    assert "1 kept, 1 removed" in capsys.readouterr().out
