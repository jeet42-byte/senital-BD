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
    note: str | None = None


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


class SourceContribution(BaseModel):
    source: str
    reliability: float
    confidence: int | None
    weight: float


class ScoreExplanation(BaseModel):
    sources: list[SourceContribution]
    combined: float
    age_days: float
    half_life_days: float | None
    decay: float
    bd_boost: int
    score: int
    severity: str


class LookupResult(BaseModel):
    query: str
    type: str | None
    normalized: str | None
    found: bool
    indicator: IndicatorOut | None = None
    explanation: ScoreExplanation | None = None


class TimelinePoint(BaseModel):
    day: str
    count: int


class FeedPreview(BaseModel):
    kind: str
    count: int
    sample: list[str]


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


class GraphNode(BaseModel):
    id: int
    type: str
    value: str
    score: int
    severity: str
    bd_relevant: bool
    malware: str | None
    sources: list[str]


class GraphEdge(BaseModel):
    src: int
    dst: int
    kind: str
    origin: str
    last_seen: datetime


class Graph(BaseModel):
    center: int
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    truncated: bool
    resolutions: list[str]   # every IP the domain resolved to (center only)


class Correlation(BaseModel):
    kind: str
    src: GraphNode
    dst: GraphNode
    last_seen: datetime
    cross_source: bool
    own_sensor: bool


class Ranked(BaseModel):
    value: str
    count: int


class HoneypotStats(BaseModel):
    days: int
    sessions: int
    login_attempts: int
    attackers: int
    last_report: datetime | None
    timeline: list[TimelinePoint]
    protocols: dict[str, int]
    usernames: list[Ranked]
    passwords: list[Ranked]
    commands: list[Ranked]
    top_attackers: list[Ranked]


class Stats(BaseModel):
    total: int
    bd_relevant: int
    new_24h: int
    by_type: dict[str, int]
    by_severity: dict[str, int]
    by_source: dict[str, int]
    top_malware: dict[str, int]
    brands: dict[str, int]
    bd_reason_kinds: dict[str, int]
    timeline: list[TimelinePoint]
    relations: dict[str, int] = {}
    last_updated: datetime | None
    last_runs: list[FeedRunOut]
