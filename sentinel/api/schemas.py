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
    # For an IP: listed network ranges (e.g. Spamhaus DROP) that contain it.
    ranges: list[IndicatorOut] = []


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


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    cve_id: str
    vendor: str | None
    product: str | None
    name: str | None
    description: str | None
    in_kev: bool
    kev_added: datetime | None
    kev_due: datetime | None
    ransomware_use: bool
    epss: float | None
    epss_percentile: float | None
    bd_advisories: int
    priority: int
    priority_parts: dict[str, int] = {}
    indicator_count: int = 0


class VulnerabilityPage(BaseModel):
    total: int
    kev_total: int
    kev_last_30_days: int
    ransomware_linked: int
    in_bd_advisories: int
    items: list[VulnerabilityOut]


class AdvisoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    url: str
    title: str
    published: datetime | None
    cves: list[str]
    indicator_count: int


class Ranked(BaseModel):
    value: str
    count: int


class VictimOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    victim: str
    group: str
    country: str | None
    sector: str | None
    attack_date: datetime | None


class RansomwareStats(BaseModel):
    days: int
    total: int
    south_asia: int
    bangladesh: int
    groups: list[Ranked]               # most active gangs worldwide
    south_asia_groups: list[Ranked]    # gangs hitting South Asia
    countries: dict[str, int]          # South Asian country -> victims
    sectors: list[Ranked]              # sectors hit in South Asia
    recent: list[VictimOut]            # latest South Asian victims
    last_update: datetime | None


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
