"""Sentinel-BD public API. Read-only: data only enters through the ingest job.

    uvicorn sentinel.api.main:app --reload

  GET /health
  GET /api/v1/indicators          search and filter
  GET /api/v1/lookup?value=...    "is this IP / domain / URL / hash known bad?"
  GET /api/v1/stats               counts for the dashboard
  GET /api/v1/feed-runs           pipeline health
  GET /feeds/{ip|domain|url|hash}.txt   blocklists for firewalls
  GET /feeds/rpz.zone             DNS firewall zone
  GET /feeds/stix.json            STIX 2.1 bundle
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from sentinel import __version__
from sentinel.api.schemas import FeedRunOut, IndicatorOut, IndicatorPage, LookupResult, Stats
from sentinel.db import get_session, init_db
from sentinel.exporters import (
    FEED_TYPES,
    GENERATOR,
    select_indicators,
    to_plain_text,
    to_rpz,
    to_stix_bundle,
)
from sentinel.indicators import IndicatorType, guess_type, normalize
from sentinel.models import FeedRun, Indicator, Sighting


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

SessionDep = Annotated[Session, Depends(get_session)]
MinScore = Annotated[int, Query(ge=0, le=100, description="Only indicators scoring at least this")]


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


@app.get("/api/v1/indicators", response_model=IndicatorPage)
def list_indicators(
    session: SessionDep,
    type: IndicatorType | None = None,
    min_score: MinScore = 0,
    bd_only: bool = False,
    source: str | None = None,
    q: Annotated[str | None, Query(max_length=200, description="Substring of the value")] = None,
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
    if q:
        query = query.where(Indicator.value.contains(q.lower(), autoescape=True))

    total = session.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = session.scalars(
        query.order_by(Indicator.score.desc(), Indicator.last_seen.desc()).limit(limit).offset(offset)
    ).all()
    return IndicatorPage(
        total=total, limit=limit, offset=offset,
        items=[IndicatorOut.model_validate(row) for row in rows],
    )


@app.get("/api/v1/lookup", response_model=LookupResult)
def lookup(
    session: SessionDep,
    value: Annotated[str, Query(min_length=1, max_length=2048)],
    type: IndicatorType | None = None,
) -> LookupResult:
    kind = type or guess_type(value)
    normalized = normalize(kind, value) if kind else None
    if kind is None or normalized is None:
        return LookupResult(query=value, type=kind.value if kind else None, normalized=None, found=False)

    indicator = session.scalar(
        select(Indicator).where(Indicator.type == kind.value, Indicator.value == normalized)
    )
    return LookupResult(
        query=value,
        type=kind.value,
        normalized=normalized,
        found=indicator is not None,
        indicator=IndicatorOut.model_validate(indicator) if indicator else None,
    )


@app.get("/api/v1/stats", response_model=Stats)
def stats(session: SessionDep) -> Stats:
    def grouped(column, *where) -> dict[str, int]:
        query = select(column, func.count()).group_by(column)
        for clause in where:
            query = query.where(clause)
        return {str(key): count for key, count in session.execute(query) if key is not None}

    top_malware = dict(
        session.execute(
            select(Indicator.malware, func.count())
            .where(Indicator.malware.is_not(None))
            .group_by(Indicator.malware)
            .order_by(func.count().desc())
            .limit(10)
        ).all()
    )
    runs = session.scalars(select(FeedRun).order_by(FeedRun.started_at.desc()).limit(10)).all()
    return Stats(
        total=session.scalar(select(func.count(Indicator.id))) or 0,
        bd_relevant=session.scalar(select(func.count(Indicator.id)).where(Indicator.bd_relevant.is_(True))) or 0,
        by_type=grouped(Indicator.type),
        by_severity=grouped(Indicator.severity),
        by_source=grouped(Sighting.source),
        top_malware=top_malware,
        last_runs=[FeedRunOut.model_validate(run) for run in runs],
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


@app.get("/feeds/stix.json")
def stix_feed(
    session: SessionDep,
    min_score: MinScore = 50,
    bd_only: bool = False,
    type: IndicatorType | None = None,
    limit: Annotated[int | None, Query(ge=1)] = 5000,
) -> Response:
    types = (type,) if type else tuple(IndicatorType)
    rows = select_indicators(session, types, min_score, bd_only, limit)
    return Response(
        to_stix_bundle(rows), media_type="application/stix+json;version=2.1",
        headers=_feed_headers(len(rows)),
    )
