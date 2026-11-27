from sqlalchemy import select

from sentinel.collectors import COLLECTORS
from sentinel.db import session_scope
from sentinel.ingest import ingest_raw, rescore_all, run_collector
from sentinel.models import FeedRun, Indicator
from tests.conftest import NOW, fixture_text


def load_all():
    for name, fixture in [
        ("feodotracker", "feodo.json"),
        ("urlhaus", "urlhaus.csv"),
        ("threatfox", "threatfox.json"),
        ("openphish", "openphish.txt"),
    ]:
        with session_scope() as session:
            ingest_raw(session, name, COLLECTORS[name].parse(fixture_text(fixture)), now=NOW)


def get(session, kind, value):
    return session.scalar(select(Indicator).where(Indicator.type == kind, Indicator.value == value))


def test_invalid_values_are_rejected():
    with session_scope() as session:
        stats = ingest_raw(session, "urlhaus", COLLECTORS["urlhaus"].parse(fixture_text("urlhaus.csv")), now=NOW)
    assert stats.fetched == 6 and stats.rejected == 2 and stats.created == 4


def test_reingest_is_idempotent():
    load_all()
    with session_scope() as session:
        before = len(session.scalars(select(Indicator)).all())
    load_all()
    with session_scope() as session:
        assert len(session.scalars(select(Indicator)).all()) == before


def test_corroboration_across_feeds():
    load_all()
    with session_scope() as session:
        ip = get(session, "ipv4", "185.220.101.45")
        assert sorted(s.source for s in ip.sightings) == ["feodotracker", "threatfox"]
        assert ip.score == 98 and ip.severity == "high"
        assert ip.malware == "QakBot"

        # Defanged in OpenPhish, a plain domain in ThreatFox: same host, two rows
        # of different types, both tagged as Nagad impersonation.
        domain = get(session, "domain", "nagad-verify-account.com")
        assert "impersonates:Nagad" in domain.bd_reasons
        url = get(session, "url", "https://nagad-verify-account.com/login")
        assert url is not None and url.bd_relevant


def test_bd_relevance_from_ranges_and_geo():
    load_all()
    with session_scope() as session:
        c2 = get(session, "ipv4", "103.4.145.10")
        assert c2.bd_reasons == ["geo:BD", "ip:bd-space"]
        assert c2.score == 100
        assert not get(session, "url", "http://evil-loader.ru/payload.exe").bd_relevant


def test_offline_indicators_decay():
    load_all()
    with session_scope() as session:
        stale = get(session, "ipv4", "45.95.11.20")  # last online 2026-09-15
        assert stale.score < 5 and stale.severity == "low"


def test_rescore_all_applies_decay_over_time():
    load_all()
    from datetime import timedelta

    with session_scope() as session:
        assert rescore_all(session, now=NOW + timedelta(days=60)) > 0
    with session_scope() as session:
        assert get(session, "ipv4", "185.220.101.45").score < 10
        # Hashes keep their score.
        sha = get(session, "sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert sha.score == 40


def test_run_collector_records_failures_without_raising():
    run = run_collector("feodotracker", text="{ not json")
    assert run.ok is False and "JSONDecodeError" in run.error
    run = run_collector("openphish", text=fixture_text("openphish.txt"))
    assert run.ok and run.created == 4
    with session_scope() as session:
        assert len(session.scalars(select(FeedRun)).all()) == 2


def test_a_clash_with_another_writer_is_retried(monkeypatch):
    """The honeypot shipper can insert the same IP between our lookup and
    our insert; the collector must retry, not fail the whole feed."""
    import sentinel.ingest as ingest_module
    from sentinel.collectors.base import RawIndicator
    from sentinel.indicators import IndicatorType

    real_load = ingest_module._load_existing
    lookups = []

    def lookup_then_someone_else_inserts(session, keys):
        found = real_load(session, keys)
        lookups.append(len(found))
        if len(lookups) == 1:  # the other writer slips in right after our first lookup
            with session_scope() as other:
                ingest_module.ingest_raw(other, "honeypot", [
                    RawIndicator(IndicatorType.IPV4, "185.220.101.45", "honeypot", confidence=60)])
        return found

    monkeypatch.setattr(ingest_module, "_load_existing", lookup_then_someone_else_inserts)
    run = run_collector("feodotracker", text=fixture_text("feodo.json"))
    assert run.ok, run.error
    assert lookups[0] == 0 and lookups[-1] >= 1  # second attempt found the row
    with session_scope() as session:
        ip = session.scalar(select(Indicator).where(Indicator.value == "185.220.101.45"))
        assert {s.source for s in ip.sightings} == {"honeypot", "feodotracker"}


def test_database_errors_are_stored_as_one_line(monkeypatch):
    import sentinel.ingest as ingest_module

    def boom(*args, **kwargs):
        raise RuntimeError("first line\n" + "SQL " * 5000)

    monkeypatch.setattr(ingest_module, "ingest_raw", boom)
    run = run_collector("openphish", text=fixture_text("openphish.txt"))
    assert not run.ok and run.error == "RuntimeError: first line"
