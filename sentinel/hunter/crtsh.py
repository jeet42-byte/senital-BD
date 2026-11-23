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
RETRY_WAITS = (10.0, 30.0)


class CrtShHunter(Collector):
    name = "phishhunter"
    url = "https://crt.sh/"

    def __init__(
        self,
        tokens: Iterable[str] = SEARCH_TOKENS,
        pause: float = PAUSE_SECONDS,
        lookback_days: int = LOOKBACK_DAYS,
        retry_waits: tuple[float, ...] = RETRY_WAITS,
    ):
        self.tokens = tuple(tokens)
        self.pause = pause
        self.lookback_days = lookback_days
        self.retry_waits = retry_waits

    def query_url(self, token: str) -> str:
        return f"https://crt.sh/?q={quote('%' + token + '%')}&output=json&exclude=expired&deduplicate=Y"

    def fetch(self, client: httpx.Client) -> str:
        """All matching certificate entries, as one JSON list."""
        entries: list[dict] = []
        failures: list[str] = []
        for i, token in enumerate(self.tokens):
            if i:
                time.sleep(self.pause)
            batch = self._query(client, token)
            if batch is None:
                failures.append(token)
            else:
                entries.extend(batch)
        if failures:
            log.warning("crt.sh gave no answer for: %s", ", ".join(failures))
        if len(failures) == len(self.tokens):
            raise FeedError(f"crt.sh failed for every token ({', '.join(failures)})")
        return json.dumps(entries)

    def _query(self, client: httpx.Client, token: str) -> list[dict] | None:
        """One token, retried: crt.sh often answers 429/5xx when busy."""
        for attempt, wait in enumerate((*self.retry_waits, None), start=1):
            try:
                response = client.get(self.query_url(token), headers=self.headers(), timeout=120)
                if response.status_code == 200:
                    batch = response.json() if response.text.strip() else []
                    log.info("crt.sh %-12s %d certificates", token, len(batch))
                    return batch
                problem = f"HTTP {response.status_code}"
            except (httpx.HTTPError, ValueError) as exc:
                problem = type(exc).__name__
            if wait is None:
                log.warning("crt.sh %-12s gave up after %d attempts (%s)", token, attempt, problem)
                return None
            log.info("crt.sh %-12s %s, retrying in %ss", token, problem, wait)
            time.sleep(wait)
        return None

    def parse(self, text: str, now: datetime | None = None) -> Iterable[RawIndicator]:
        now = now or datetime.now(timezone.utc)
        cutoff = now - timedelta(days=self.lookback_days)
        entries = json.loads(text)
        in_window = names_checked = near_misses = reported = 0
        for entry in entries:
            logged = parse_time(entry.get("entry_timestamp", "")[:19].replace("T", " ")) or parse_time(entry.get("not_before"))
            if logged and logged < cutoff:
                continue
            in_window += 1
            names = {n.strip() for n in f"{entry.get('common_name', '')}\n{entry.get('name_value', '')}".splitlines()}
            for name in names:
                if not name:
                    continue
                names_checked += 1
                finding = analyze(name)
                if finding is None:
                    continue
                if not finding.reportable:
                    near_misses += 1
                    continue
                reported += 1
                yield finding_to_raw(finding, self.name, first_seen=logged,
                                     reference=f"https://crt.sh/?id={entry['id']}" if entry.get("id") else None)
        log.info(
            "crt.sh: %d certificates, %d in the last %d days, %d names checked, "
            "%d lookalikes reported, %d below threshold",
            len(entries), in_window, self.lookback_days, names_checked, reported, near_misses,
        )


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
