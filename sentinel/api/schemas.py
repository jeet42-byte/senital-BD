"""Response models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SightingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source: str
    first_seen: datetime
    last_seen: datetime
    confidence: int | None
    reference: str | None


class IndicatorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    type: str
    value: str
    score: int
    severity: str
    first_seen: datetime
    last_seen: datetime
    bd_relevant: bool
    bd_reasons: list[str]
    threat_type: str | None
    malware: str | None
    tags: list[str]
    sightings: list[SightingOut]


class IndicatorPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[IndicatorOut]


class LookupResult(BaseModel):
    query: str
    type: str | None
    normalized: str | None
    found: bool
    indicator: IndicatorOut | None = None


class FeedRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source: str
    started_at: datetime
    finished_at: datetime | None
    ok: bool
    fetched: int
    rejected: int
    created: int
    updated: int
    error: str | None


class Stats(BaseModel):
    total: int
    bd_relevant: int
    by_type: dict[str, int]
    by_severity: dict[str, int]
    by_source: dict[str, int]
    top_malware: dict[str, int]
    last_runs: list[FeedRunOut]
