"""Ingest pipeline: fetch -> parse -> normalise -> dedupe -> upsert -> score.

    python -m sentinel.ingest                        # every feed
    python -m sentinel.ingest --source urlhaus       # one feed
    python -m sentinel.ingest --from-file urlhaus=saved.csv   # offline
    python -m sentinel.ingest --rescore-only         # re-apply decay

Re-running is safe: an indicator already stored is updated, never duplicated,
and a feed reporting it again only refreshes that feed's sighting.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from sentinel.bd import bd_reasons
from sentinel.collectors import COLLECTORS, RawIndicator
from sentinel.collectors.base import FeedError
from sentinel.config import get_settings
from sentinel.db import init_db, session_scope
from sentinel.indicators import IndicatorType, normalize
from sentinel.models import FeedRun, Indicator, Sighting
from sentinel.scoring import Evidence, as_utc, compute_score, severity

log = logging.getLogger("sentinel.ingest")

CHUNK = 500


@dataclass
class IngestStats:
    fetched: int = 0
    rejected: int = 0
    created: int = 0
    updated: int = 0


def _clip(value: str | None, length: int) -> str | None:
    return value[:length] if value else value


def _merge(raws: Iterable[RawIndicator], now: datetime, stats: IngestStats) -> dict[tuple[str, str], RawIndicator]:
    """Normalise, drop invalid values, and fold duplicates within one feed."""
    merged: dict[tuple[str, str], RawIndicator] = {}
    for raw in raws:
        stats.fetched += 1
        value = normalize(raw.type, raw.value)
        if value is None:
            stats.rejected += 1
            continue
        # Listed in the feed right now and no date given: it is live now.
        last_seen = min(as_utc(raw.last_seen), now) if raw.last_seen else now
        first_seen = min(as_utc(raw.first_seen), last_seen) if raw.first_seen else last_seen
        key = (IndicatorType(raw.type).value, value)
        current = merged.get(key)
        if current is None:
            raw.value, raw.first_seen, raw.last_seen = value, first_seen, last_seen
            merged[key] = raw
            continue
        current.first_seen = min(current.first_seen, first_seen)
        current.last_seen = max(current.last_seen, last_seen)
        current.tags = sorted(set(current.tags) | set(raw.tags))
        if raw.confidence is not None:
            current.confidence = max(current.confidence or 0, raw.confidence)
        current.malware = current.malware or raw.malware
        current.country = current.country or raw.country
    return merged


def _load_existing(session: Session, keys: list[tuple[str, str]]) -> dict[tuple[str, str], Indicator]:
    found: dict[tuple[str, str], Indicator] = {}
    by_type: dict[str, list[str]] = {}
    for kind, value in keys:
        by_type.setdefault(kind, []).append(value)
    for kind, values in by_type.items():
        for i in range(0, len(values), CHUNK):
            rows = session.scalars(
                select(Indicator).where(Indicator.type == kind, Indicator.value.in_(values[i : i + CHUNK]))
            )
            for row in rows:
                found[(row.type, row.value)] = row
    return found


def rescore(indicator: Indicator, now: datetime | None = None) -> None:
    evidence = [Evidence(s.source, s.confidence) for s in indicator.sightings]
    indicator.score = compute_score(
        indicator.type, evidence, indicator.last_seen, indicator.bd_relevant, now
    )
    indicator.severity = severity(indicator.score)


def ingest_raw(
    session: Session, source: str, raws: Iterable[RawIndicator], now: datetime | None = None
) -> IngestStats:
    now = now or datetime.now(timezone.utc)
    stats = IngestStats()
    merged = _merge(raws, now, stats)
    existing = _load_existing(session, list(merged))

    for key, raw in merged.items():
        kind, value = key
        indicator = existing.get(key)
        if indicator is None:
            indicator = Indicator(
                type=kind, value=value, first_seen=raw.first_seen, last_seen=raw.last_seen,
                tags=[], bd_reasons=[],
            )
            session.add(indicator)
            stats.created += 1
        else:
            indicator.first_seen = min(as_utc(indicator.first_seen), raw.first_seen)
            indicator.last_seen = max(as_utc(indicator.last_seen), raw.last_seen)
            stats.updated += 1

        indicator.tags = sorted(set(indicator.tags or []) | set(raw.tags))
        indicator.threat_type = indicator.threat_type or _clip(raw.threat_type, 64)
        indicator.malware = indicator.malware or _clip(raw.malware, 128)
        reasons = set(indicator.bd_reasons or []) | set(bd_reasons(kind, value, raw.country))
        indicator.bd_reasons = sorted(reasons)
        indicator.bd_relevant = bool(reasons)

        sighting = next((s for s in indicator.sightings if s.source == source), None)
        if sighting is None:
            indicator.sightings.append(
                Sighting(
                    source=source, first_seen=raw.first_seen, last_seen=raw.last_seen,
                    confidence=raw.confidence, reference=raw.reference,
                )
            )
        else:
            sighting.first_seen = min(as_utc(sighting.first_seen), raw.first_seen)
            sighting.last_seen = max(as_utc(sighting.last_seen), raw.last_seen)
            sighting.confidence = raw.confidence if raw.confidence is not None else sighting.confidence
            sighting.reference = raw.reference or sighting.reference

        rescore(indicator, now)

    session.flush()
    return stats


def rescore_all(session: Session, now: datetime | None = None) -> int:
    """Re-apply decay to every indicator, so stale ones sink out of the feeds."""
    now = now or datetime.now(timezone.utc)
    count = 0
    for indicator in session.scalars(select(Indicator).execution_options(yield_per=CHUNK)):
        rescore(indicator, now)
        count += 1
    return count


def run_collector(name: str, client: httpx.Client | None = None, text: str | None = None) -> FeedRun:
    """Run one collector and record the outcome. Never raises for feed errors."""
    collector = COLLECTORS[name]
    with session_scope() as session:
        run = FeedRun(source=name)
        session.add(run)
        session.flush()
        try:
            if text is None:
                assert client is not None
                text = collector.fetch(client)
            stats = ingest_raw(session, name, collector.parse(text))
            run.fetched, run.rejected = stats.fetched, stats.rejected
            run.created, run.updated = stats.created, stats.updated
            run.ok = True
        except Exception as exc:  # one broken feed must not stop the others
            session.rollback()
            if isinstance(exc, FeedError):
                message = str(exc)  # already free of secrets; no traceback needed
            else:
                message = collector.redact(f"{type(exc).__name__}: {exc}")
                log.error("%s failed: %s", name, message, exc_info=True)
            run = FeedRun(source=name, ok=False, error=message[:2000])
            session.add(run)
        run.finished_at = datetime.now(timezone.utc)
    log.info(
        "%-13s ok=%s fetched=%d rejected=%d new=%d updated=%d %s",
        name, run.ok, run.fetched, run.rejected, run.created, run.updated, run.error or "",
    )
    return run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect threat feeds into Sentinel-BD")
    parser.add_argument("--source", action="append", choices=sorted(COLLECTORS),
                        help="feed to collect (repeatable; default: all)")
    parser.add_argument("--from-file", action="append", default=[], metavar="SOURCE=PATH",
                        help="parse a saved feed file instead of downloading")
    parser.add_argument("--rescore-only", action="store_true", help="only re-apply score decay")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    # httpx logs every request URL at INFO, and abuse.ch URLs contain the key.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    init_db()

    if args.rescore_only:
        with session_scope() as session:
            log.info("rescored %d indicators", rescore_all(session))
        return 0

    runs: list[FeedRun] = []
    if args.from_file:
        for item in args.from_file:
            name, _, path = item.partition("=")
            if name not in COLLECTORS or not path:
                parser.error(f"--from-file expects SOURCE=PATH with SOURCE in {sorted(COLLECTORS)}")
            runs.append(run_collector(name, text=Path(path).read_text(encoding="utf-8")))
    else:
        settings = get_settings()
        with httpx.Client(timeout=settings.HTTP_TIMEOUT_SECONDS, follow_redirects=True) as client:
            for name in args.source or sorted(COLLECTORS):
                runs.append(run_collector(name, client=client))

    with session_scope() as session:
        rescore_all(session)

    # Fail the job only when every feed failed, so one outage is not an alarm.
    return 0 if any(run.ok for run in runs) else 1


if __name__ == "__main__":
    sys.exit(main())
