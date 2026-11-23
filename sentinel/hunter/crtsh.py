"""crt.sh poller: newly issued TLS certificates that name a Bangladeshi brand.

Every public TLS certificate is logged in Certificate Transparency logs, and
crt.sh lets anyone search them. A phishing site needs a certificate for the
browser padlock, so a lookalike domain usually appears here within minutes
of being set up, often before the first victim is sent a link.

For each brand token this asks crt.sh for unexpired certificates containing
it, keeps those logged in the last LOOKBACK_DAYS, runs every name through the
lookalike detector, and reports the ones that score high enough.

crt.sh is a free community service and can be slow; queries are sequential,
spaced out, and a failure on one token does not stop the others.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import httpx

from sentinel.collectors.base import Collector, FeedError, RawIndicator, parse_time
from sentinel.hunter.detect import SEARCH_TOKENS, analyze
from sentinel.indicators import IndicatorType

log = logging.getLogger(__name__)

LOOKBACK_DAYS = 7
PAUSE_SECONDS = 3.0


class CrtShHunter(Collector):
    name = "phishhunter"
    url = "https://crt.sh/"

    def __init__(self, tokens: Iterable[str] = SEARCH_TOKENS, pause: float = PAUSE_SECONDS):
        self.tokens = tuple(tokens)
        self.pause = pause

    def query_url(self, token: str) -> str:
        return f"https://crt.sh/?q={quote('%' + token + '%')}&output=json&exclude=expired&deduplicate=Y"

    def fetch(self, client: httpx.Client) -> str:
        """All matching certificate entries, as one JSON list."""
        entries: list[dict] = []
        failures: list[str] = []
        for i, token in enumerate(self.tokens):
            if i:
                time.sleep(self.pause)
            try:
                response = client.get(self.query_url(token), headers=self.headers(), timeout=120)
                response.raise_for_status()
                batch = response.json() if response.text.strip() else []
                entries.extend(batch)
                log.info("crt.sh %-12s %d certificates", token, len(batch))
            except (httpx.HTTPError, ValueError) as exc:
                failures.append(token)
                log.warning("crt.sh %-12s failed: %s", token, type(exc).__name__)
        if failures and len(failures) == len(self.tokens):
            raise FeedError(f"crt.sh failed for every token ({', '.join(failures)})")
        return json.dumps(entries)

    def parse(self, text: str, now: datetime | None = None) -> Iterable[RawIndicator]:
        now = now or datetime.now(timezone.utc)
        cutoff = now - timedelta(days=LOOKBACK_DAYS)
        for entry in json.loads(text):
            logged = parse_time(entry.get("entry_timestamp", "")[:19].replace("T", " ")) or parse_time(entry.get("not_before"))
            if logged and logged < cutoff:
                continue
            names = {n.strip() for n in f"{entry.get('common_name', '')}\n{entry.get('name_value', '')}".splitlines()}
            for name in names:
                finding = analyze(name) if name else None
                if finding is None or not finding.reportable:
                    continue
                yield finding_to_raw(finding, self.name, first_seen=logged,
                                     reference=f"https://crt.sh/?id={entry['id']}" if entry.get("id") else None)


def finding_to_raw(finding, source: str, first_seen: datetime | None = None, reference: str | None = None) -> RawIndicator:
    return RawIndicator(
        type=IndicatorType.DOMAIN,
        value=finding.indicator,
        source=source,
        first_seen=first_seen,
        confidence=finding.score,
        threat_type="phishing_lookalike",
        tags=["lookalike", finding.technique],
        reference=reference,
        extra_reasons=[f"impersonates:{finding.brand}"],
        note="; ".join(finding.reasons),
    )
