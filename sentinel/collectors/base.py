"""Shared collector machinery.

A collector does two things: fetch a feed's raw text, and parse it into
RawIndicator records. Parsing is kept separate from fetching so tests (and
offline runs) can feed it saved files.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

from sentinel.config import get_settings
from sentinel.indicators import IndicatorType


@dataclass
class RawIndicator:
    """One report of one indicator by one feed, before normalisation."""

    type: IndicatorType
    value: str
    source: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    confidence: int | None = None
    threat_type: str | None = None
    malware: str | None = None
    tags: list[str] = field(default_factory=list)
    reference: str | None = None
    country: str | None = None


class Collector:
    name: str = ""
    url: str = ""
    sends_abusech_key: bool = False

    def headers(self) -> dict[str, str]:
        settings = get_settings()
        headers = {"User-Agent": settings.USER_AGENT}
        if self.sends_abusech_key and settings.ABUSECH_AUTH_KEY:
            headers["Auth-Key"] = settings.ABUSECH_AUTH_KEY
        return headers

    def fetch(self, client: httpx.Client) -> str:
        response = client.get(self.url, headers=self.headers())
        response.raise_for_status()
        return response.text

    def parse(self, text: str) -> Iterable[RawIndicator]:
        raise NotImplementedError


def parse_time(value: str | None) -> datetime | None:
    """Feed timestamps: '2026-11-23 10:15:03', '2026-11-23' or ISO 8601; all UTC."""
    if not value:
        return None
    value = value.strip().replace(" UTC", "").replace("Z", "+00:00")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def split_tags(value: str | list | None) -> list[str]:
    if not value:
        return []
    items = value if isinstance(value, list) else str(value).split(",")
    return sorted({str(item).strip().lower() for item in items if str(item).strip() and str(item).strip().lower() != "none"})
