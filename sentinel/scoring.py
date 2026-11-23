"""Confidence scoring, 0-100.

  1. Each source has a reliability (how often its reports turn out right).
     A source's own confidence, when it gives one, scales that.
  2. Sources are combined with noisy-OR: the chance that *every* source is
     wrong shrinks with each independent source that agrees,
         p = 1 - prod(1 - r_i)
     so one feed at 0.85 scores 85, and a second feed at 0.75 lifts it to 96.
  3. Old indicators decay: attackers rotate IPs within days, domains within
     weeks. A file hash never stops identifying the same file, so it does
     not decay.
  4. Bangladesh relevance adds a fixed boost, because this platform's users
     care most about what is aimed at Bangladesh.

The weights are starting points, meant to be tuned against real data.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

from sentinel.indicators import IndicatorType

SOURCE_RELIABILITY: dict[str, float] = {
    "feodotracker": 0.90,  # botnet C2s, manually verified
    "urlhaus": 0.85,
    "threatfox": 0.80,     # community submissions; also gives its own confidence
    "openphish": 0.75,
}
DEFAULT_RELIABILITY = 0.50

HALF_LIFE_DAYS: dict[IndicatorType, float | None] = {
    IndicatorType.IPV4: 14,
    IndicatorType.URL: 30,
    IndicatorType.DOMAIN: 45,
    IndicatorType.MD5: None,
    IndicatorType.SHA1: None,
    IndicatorType.SHA256: None,
}

BD_BOOST = 10


@dataclass(frozen=True)
class Evidence:
    source: str
    confidence: int | None = None  # the source's own 0-100, if any


def source_weight(evidence: Evidence) -> float:
    weight = SOURCE_RELIABILITY.get(evidence.source, DEFAULT_RELIABILITY)
    if evidence.confidence is not None:
        weight *= max(0, min(100, evidence.confidence)) / 100
    return weight


def compute_score(
    kind: IndicatorType | str,
    evidence: Iterable[Evidence],
    last_seen: datetime,
    bd_relevant: bool,
    now: datetime | None = None,
) -> int:
    kind = IndicatorType(kind)
    now = now or datetime.now(timezone.utc)

    all_wrong = 1.0
    for item in evidence:
        all_wrong *= 1 - source_weight(item)
    probability = 1 - all_wrong

    half_life = HALF_LIFE_DAYS[kind]
    if half_life:
        age_days = max(0.0, (now - as_utc(last_seen)).total_seconds() / 86400)
        probability *= 0.5 ** (age_days / half_life)

    score = 100 * probability + (BD_BOOST if bd_relevant and probability > 0 else 0)
    return int(round(max(0, min(100, score))))


def severity(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def as_utc(value: datetime) -> datetime:
    """SQLite hands back naive datetimes; everything here is UTC."""
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
