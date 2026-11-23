"""Sentinel-BD: dashboard, public API and blocklist feeds in one app.

Read-only: data only enters through the ingest job.

    uvicorn sentinel.api.main:app --reload

  GET /                           the dashboard
  GET /health
  GET /api/v1/indicators          search, filter, sort
  GET /api/v1/lookup?value=...    "is this IP / domain / URL / hash known bad?"
  GET /api/v1/explain?type=&value=  how an indicator's score was worked out
  GET /api/v1/stats               counts, 30-day timeline, impersonated brands
  GET /api/v1/feed-preview        size of a feed before you subscribe to it
  GET /api/v1/feed-runs           pipeline health
  GET /api/v1/honeypot            what attackers did on Sentinel-BD's own sensors
  GET /feeds/{ip|domain|url|hash}.txt   blocklists for firewalls
  GET /feeds/rpz.zone             DNS firewall zone
  GET /feeds/mikrotik.rsc         RouterOS address-list script
  GET /feeds/stix.json            STIX 2.1 bundle
"""

from __future__ import annotations

from collections import Counter
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import String, cast, func, select
from sqlalchemy.orm import Session

from sentinel import __version__
from sentinel.api.schemas import (
    FeedPreview,
    FeedRunOut,
    HoneypotStats,
    IndicatorOut,
    IndicatorPage,
    LookupResult,
    Ranked,
    ScoreExplanation,
    Stats,
    TimelinePoint,
)
from sentinel.db import get_session, init_db
from sentinel.exporters import (
    FEED_TYPES,
    GENERATOR,
    select_indicators,
    to_mikrotik,
    to_plain_text,
    to_rpz,
    to_stix_bundle,
)
from sentinel.indicators import IndicatorType, guess_type, normalize
from sentinel.models import FeedRun, HoneypotDaily, Indicator, Sighting
from sentinel.scoring import Evidence, explain_score

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
TIMELINE_DAYS = 30

# The dashboard shows attacker-controlled strings (URLs, domains). Everything
# is rendered as text, and this policy is the second line of defence: no
# inline script, no third-party code, no framing.
DASHBOARD_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'"
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Sentinel-BD",
    version=__version__,
    description="Bangladesh-focused open threat intelligence: indicators, scores and blocklist feeds.",
    lifespan=lifespan,
)
# Public, read-only data: any origin may GET it. No cookies, no writes.
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET"], allow_headers=["*"])
app.mount("/assets", StaticFiles(directory=WEB_DIR / "assets"), name="assets")

SessionDep = Annotated[Session, Depends(get_session)]
MinScore = Annotated[int, Query(ge=0, le=100, description="Only indicators scoring at least this")]


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(
        WEB_DIR / "index.html",
        headers={
            "Content-Security-Policy": DASHBOARD_CSP,
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-cache",
        },
    )


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


def _day_bounds(day: date) -> tuple[datetime, datetime]:
    start = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
    return start, start + timedelta(days=1)


@app.get("/api/v1/indicators", response_model=IndicatorPage)
def list_indicators(
    session: SessionDep,
    type: IndicatorType | None = None,
    min_score: MinScore = 0,
    bd_only: bool = False,
    source: str | None = None,
    severity: Literal["high", "medium", "low"] | None = None,
    malware: Annotated[str | None, Query(max_length=128)] = None,
    reason: Annotated[str | None, Query(max_length=64, description="e.g. impersonates:bKash")] = None,
    day: Annotated[date | None, Query(description="First seen on this UTC day")] = None,
    q: Annotated[str | None, Query(max_length=200, description="Substring of the value")] = None,
    sort: Literal["score", "newest"] = "score",
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> IndicatorPage:
    query = select(Indicator).where(Indicator.score >= min_score)
    if type:
        query = query.where(Indicator.type == type.value)
    if bd_only:
        query = query.where(Indicator.bd_relevant.is_(True))
    if source:
        query = query.where(Indicator.sightings.any(Sighting.source == source))
    if severity:
        query = query.where(Indicator.severity == severity)
    if malware:
        query = query.where(Indicator.malware == malware)
    if reason:
        # Reasons are a JSON list; match the quoted element in its text form,
        # which works the same on SQLite and PostgreSQL.
        query = query.where(cast(Indicator.bd_reasons, String).contains(f'"{reason}"', autoescape=True))
    if day:
        start, end = _day_bounds(day)
        query = query.where(Indicator.first_seen >= start, Indicator.first_seen < end)
    if q:
        query = query.where(Indicator.value.contains(q.strip().lower(), autoescape=True))

    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    order = (
        (Indicator.first_seen.desc(), Indicator.id.desc())
        if sort == "newest"
        else (Indicator.score.desc(), Indicator.last_seen.desc(), Indicator.id.desc())
    )
    rows = session.scalars(query.order_by(*order).limit(limit).offset(offset)).all()
    return IndicatorPage(
        total=total, limit=limit, offset=offset,
        items=[IndicatorOut.model_validate(row) for row in rows],
    )


def _find(session: Session, kind: IndicatorType, value: str) -> tuple[str | None, Indicator | None]:
    normalized = normalize(kind, value)
    if normalized is None:
        return None, None
    return normalized, session.scalar(
        select(Indicator).where(Indicator.type == kind.value, Indicator.value == normalized)
    )


def _explain(indicator: Indicator) -> ScoreExplanation:
    evidence = [Evidence(s.source, s.confidence) for s in indicator.sightings]
    return ScoreExplanation(
        **explain_score(indicator.type, evidence, indicator.last_seen, indicator.bd_relevant)
    )


@app.get("/api/v1/lookup", response_model=LookupResult)
def lookup(
    session: SessionDep,
    value: Annotated[str, Query(min_length=1, max_length=2048)],
    type: IndicatorType | None = None,
) -> LookupResult:
    kind = type or guess_type(value)
    if kind is None:
        return LookupResult(query=value, type=None, normalized=None, found=False)
    normalized, indicator = _find(session, kind, value)
    return LookupResult(
        query=value,
        type=kind.value,
        normalized=normalized,
        found=indicator is not None,
        indicator=IndicatorOut.model_validate(indicator) if indicator else None,
        explanation=_explain(indicator) if indicator else None,
    )


@app.get("/api/v1/explain", response_model=ScoreExplanation)
def explain(
    session: SessionDep,
    type: IndicatorType,
    value: Annotated[str, Query(min_length=1, max_length=2048)],
) -> ScoreExplanation:
    _, indicator = _find(session, type, value)
    if indicator is None:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return _explain(indicator)


@app.get("/api/v1/stats", response_model=Stats)
def stats(session: SessionDep) -> Stats:
    now = datetime.now(timezone.utc)

    def grouped(column) -> dict[str, int]:
        rows = session.execute(select(column, func.count()).group_by(column))
        return {str(key): count for key, count in rows if key is not None}

    top_malware = dict(
        session.execute(
            select(Indicator.malware, func.count())
            .where(Indicator.malware.is_not(None))
            .group_by(Indicator.malware)
            .order_by(func.count().desc(), Indicator.malware)
            .limit(12)
        ).all()
    )

    # New indicators per UTC day, zero-filled so the chart has no gaps.
    first_day = now.date() - timedelta(days=TIMELINE_DAYS - 1)
    start, _ = _day_bounds(first_day)
    day_column = func.date(Indicator.first_seen)
    per_day = {
        str(day)[:10]: count
        for day, count in session.execute(
            select(day_column, func.count()).where(Indicator.first_seen >= start).group_by(day_column)
        )
    }
    timeline = [
        TimelinePoint(day=d.isoformat(), count=per_day.get(d.isoformat(), 0))
        for d in (first_day + timedelta(days=i) for i in range(TIMELINE_DAYS))
    ]

    # Which Bangladeshi brands attackers imitate. Reasons are a JSON list, so
    # they are counted here rather than in SQL; only BD-relevant rows load.
    brands: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    for (row_reasons,) in session.execute(
        select(Indicator.bd_reasons).where(Indicator.bd_relevant.is_(True))
    ):
        for reason in row_reasons or []:
            reasons[reason.split(":", 1)[0]] += 1
            if reason.startswith("impersonates:"):
                brands[reason.split(":", 1)[1]] += 1

    runs = session.scalars(select(FeedRun).order_by(FeedRun.started_at.desc()).limit(40)).all()
    latest_per_source: dict[str, FeedRun] = {}
    for run in runs:
        latest_per_source.setdefault(run.source, run)
    last_ok = session.scalar(select(func.max(FeedRun.finished_at)).where(FeedRun.ok.is_(True)))

    return Stats(
        total=session.scalar(select(func.count(Indicator.id))) or 0,
        bd_relevant=session.scalar(select(func.count(Indicator.id)).where(Indicator.bd_relevant.is_(True))) or 0,
        new_24h=session.scalar(
            select(func.count(Indicator.id)).where(Indicator.first_seen >= now - timedelta(hours=24))
        ) or 0,
        by_type=grouped(Indicator.type),
        by_severity=grouped(Indicator.severity),
        by_source=grouped(Sighting.source),
        top_malware=top_malware,
        brands=dict(brands.most_common()),
        bd_reason_kinds=dict(reasons.most_common()),
        timeline=timeline,
        last_updated=last_ok,
        last_runs=[FeedRunOut.model_validate(run) for run in latest_per_source.values()],
    )


@app.get("/api/v1/feed-preview", response_model=FeedPreview)
def feed_preview(
    session: SessionDep,
    kind: Literal["ip", "domain", "url", "hash"],
    min_score: MinScore = 50,
    bd_only: bool = False,
) -> FeedPreview:
    """How big a feed would be (before allowlist filtering), with a few samples."""
    types = [t.value for t in FEED_TYPES[kind]]
    query = select(Indicator.id).where(Indicator.type.in_(types), Indicator.score >= min_score)
    if bd_only:
        query = query.where(Indicator.bd_relevant.is_(True))
    count = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    sample = select_indicators(session, FEED_TYPES[kind], min_score, bd_only, limit=5)
    return FeedPreview(kind=kind, count=count, sample=[row.value for row in sample])


@app.get("/api/v1/honeypot", response_model=HoneypotStats)
def honeypot(
    session: SessionDep,
    days: Annotated[int, Query(ge=1, le=90)] = 30,
) -> HoneypotStats:
    today = datetime.now(timezone.utc).date()
    first = (today - timedelta(days=days - 1)).isoformat()
    rows = session.execute(
        select(HoneypotDaily.day, HoneypotDaily.kind, HoneypotDaily.value, HoneypotDaily.count)
        .where(HoneypotDaily.day >= first)
    ).all()

    per_kind: dict[str, Counter[str]] = {}
    per_day: Counter[str] = Counter()
    for day, kind, value, count in rows:
        per_kind.setdefault(kind, Counter())[value] += count
        if kind == "session":
            per_day[day] += count

    def top(kind: str, n: int = 10) -> list[Ranked]:
        return [Ranked(value=v, count=c) for v, c in per_kind.get(kind, Counter()).most_common(n)]

    last = session.scalar(
        select(func.max(FeedRun.finished_at)).where(FeedRun.source == "honeypot", FeedRun.ok.is_(True))
    )
    return HoneypotStats(
        days=days,
        sessions=sum(per_kind.get("session", Counter()).values()),
        login_attempts=sum(per_kind.get("password", Counter()).values()),
        attackers=len(per_kind.get("attacker", Counter())),
        last_report=last,
        timeline=[
            TimelinePoint(day=d.isoformat(), count=per_day.get(d.isoformat(), 0))
            for d in (today - timedelta(days=days - 1 - i) for i in range(days))
        ],
        protocols=dict(per_kind.get("protocol", Counter())),
        usernames=top("username"),
        passwords=top("password"),
        commands=top("command", 8),
        top_attackers=top("attacker", 8),
    )


@app.get("/api/v1/feed-runs", response_model=list[FeedRunOut])
def feed_runs(
    session: SessionDep,
    source: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[FeedRunOut]:
    query = select(FeedRun).order_by(FeedRun.started_at.desc()).limit(limit)
    if source:
        query = query.where(FeedRun.source == source)
    return [FeedRunOut.model_validate(run) for run in session.scalars(query)]


def _feed_headers(count: int) -> dict[str, str]:
    return {
        "X-Generator": GENERATOR,
        "X-Indicator-Count": str(count),
        "X-Generated-At": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        # Firewalls poll every few minutes; a short cache keeps the API cheap.
        "Cache-Control": "public, max-age=300",
    }


@app.get("/feeds/{kind}.txt", response_class=PlainTextResponse)
def plain_feed(
    session: SessionDep,
    kind: Literal["ip", "domain", "url", "hash"],
    min_score: MinScore = 50,
    bd_only: bool = False,
    strip_scheme: Annotated[bool, Query(description="For Palo Alto URL lists: host/path only")] = False,
    limit: Annotated[int | None, Query(ge=1)] = None,
) -> PlainTextResponse:
    rows = select_indicators(session, FEED_TYPES[kind], min_score, bd_only, limit)
    return PlainTextResponse(to_plain_text(rows, strip_scheme), headers=_feed_headers(len(rows)))


@app.get("/feeds/rpz.zone", response_class=PlainTextResponse)
def rpz_feed(
    session: SessionDep,
    min_score: MinScore = 50,
    bd_only: bool = False,
    limit: Annotated[int | None, Query(ge=1)] = None,
) -> PlainTextResponse:
    rows = select_indicators(session, FEED_TYPES["domain"], min_score, bd_only, limit)
    return PlainTextResponse(to_rpz(rows), headers=_feed_headers(len(rows)))


@app.get("/feeds/mikrotik.rsc", response_class=PlainTextResponse)
def mikrotik_feed(
    session: SessionDep,
    min_score: MinScore = 50,
    bd_only: bool = False,
    limit: Annotated[int | None, Query(ge=1)] = None,
) -> PlainTextResponse:
    rows = select_indicators(session, FEED_TYPES["ip"], min_score, bd_only, limit)
    return PlainTextResponse(to_mikrotik(rows), headers=_feed_headers(len(rows)))


@app.get("/feeds/stix.json")
def stix_feed(
    session: SessionDep,
    min_score: MinScore = 50,
    bd_only: bool = False,
    type: IndicatorType | None = None,
    limit: Annotated[int | None, Query(ge=1)] = 5000,
) -> Response:
    types = (type,) if type else tuple(IndicatorType)
    rows = select_indicators(session, types, min_score, bd_only, limit, with_sightings=True)
    return Response(
        to_stix_bundle(rows), media_type="application/stix+json;version=2.1",
        headers=_feed_headers(len(rows)),
    )
