"""Shared collector machinery.

A collector does two things: fetch a feed's raw text, and parse it into
RawIndicator records. Parsing is kept separate from fetching so tests (and
offline runs) can feed it saved files.
"""

from __future__ import annotations

import io
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import quote

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
    # Bangladesh reasons the source already knows (e.g. a fuzzy brand match
    # that plain substring tagging would miss), and a human-readable note.
    extra_reasons: list[str] = field(default_factory=list)
    note: str | None = None


class FeedError(Exception):
    """A feed could not be fetched. The message never contains a secret."""


class Collector:
    name: str = ""
    # May contain "{auth_key}": abuse.ch's keyed exports take the key in the
    # URL path, and answer 404 when it is sent as a header instead.
    url: str = ""
    sends_abusech_key: bool = False

    @property
    def needs_key_in_path(self) -> bool:
        return "{auth_key}" in self.url

    def headers(self) -> dict[str, str]:
        settings = get_settings()
        headers = {"User-Agent": settings.USER_AGENT}
        if self.sends_abusech_key and settings.ABUSECH_AUTH_KEY:
            headers["Auth-Key"] = settings.ABUSECH_AUTH_KEY
        return headers

    def build_url(self) -> str:
        if not self.needs_key_in_path:
            return self.url
        key = get_settings().ABUSECH_AUTH_KEY
        if not key:
            raise FeedError(f"{self.name} needs ABUSECH_AUTH_KEY (free at https://auth.abuse.ch)")
        # Quoted so a key containing / ? # % cannot change the path.
        return self.url.format(auth_key=quote(key, safe=""))

    def redact(self, text: str) -> str:
        """Remove the key from anything that may be logged or stored."""
        key = get_settings().ABUSECH_AUTH_KEY
        if key:
            text = text.replace(quote(key, safe=""), "<AUTH-KEY>").replace(key, "<AUTH-KEY>")
        return text

    def fetch(self, client: httpx.Client) -> str:
        url = self.build_url()
        try:
            response = client.get(url, headers=self.headers())
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            hint = " (check ABUSECH_AUTH_KEY)" if exc.response.status_code in (401, 403) else ""
            raise FeedError(
                f"{self.name}: HTTP {exc.response.status_code} from {self.redact(url)}{hint}"
            ) from None
        except httpx.HTTPError as exc:
            raise FeedError(f"{self.name}: {type(exc).__name__}: {self.redact(str(exc))}") from None
        return decode_body(response.content)

    def parse(self, text: str) -> Iterable[RawIndicator]:
        raise NotImplementedError


def decode_body(content: bytes) -> str:
    """Feed text; some abuse.ch exports are served as a one-file ZIP."""
    if content[:4] == b"PK\x03\x04":
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names = [n for n in archive.namelist() if not n.endswith("/")]
            if not names:
                raise FeedError("feed returned an empty ZIP archive")
            content = archive.read(names[0])
    return content.decode("utf-8", errors="replace")


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
