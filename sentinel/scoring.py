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
    # Lookalike names found by Sentinel-BD itself. A name alone is a
    # suspicion, not proof, so its weight is modest; its own 0-100 risk score
    # scales it further, and a feed confirming the domain lifts the total.
    "phishhunter": 0.65,
    # Sentinel-BD's own sensors: a completed TCP session that tried to log in
    # is first-hand evidence. The session's behaviour scales it further.
    "honeypot": 0.90,
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


def explain_score(
    kind: IndicatorType | str,
    evidence: Iterable[Evidence],
    last_seen: datetime,
    bd_relevant: bool,
    now: datetime | None = None,
) -> dict:
    """Every step of the score, so the dashboard can show why it is what it is."""
    kind = IndicatorType(kind)
    now = now or datetime.now(timezone.utc)

    sources = []
    all_wrong = 1.0
    for item in evidence:
        weight = source_weight(item)
        all_wrong *= 1 - weight
        sources.append(
            {
                "source": item.source,
                "reliability": SOURCE_RELIABILITY.get(item.source, DEFAULT_RELIABILITY),
                "confidence": item.confidence,
                "weight": round(weight, 4),
            }
        )
    combined = 1 - all_wrong

    half_life = HALF_LIFE_DAYS[kind]
    age_days = max(0.0, (now - as_utc(last_seen)).total_seconds() / 86400)
    decay = 0.5 ** (age_days / half_life) if half_life else 1.0
    probability = combined * decay

    boost = BD_BOOST if bd_relevant and probability > 0 else 0
    score = int(round(max(0, min(100, 100 * probability + boost))))
    return {
        "sources": sources,
        "combined": round(combined, 4),
        "age_days": round(age_days, 2),
        "half_life_days": half_life,
        "decay": round(decay, 4),
        "bd_boost": boost,
        "score": score,
        "severity": severity(score),
    }


def compute_score(
    kind: IndicatorType | str,
    evidence: Iterable[Evidence],
    last_seen: datetime,
    bd_relevant: bool,
    now: datetime | None = None,
) -> int:
    return explain_score(kind, evidence, last_seen, bd_relevant, now)["score"]


def severity(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def as_utc(value: datetime) -> datetime:
    """SQLite hands back naive datetimes; everything here is UTC."""
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
