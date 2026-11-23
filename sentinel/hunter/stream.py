"""Live mode: watch every new TLS certificate as it is logged.

Runs continuously on a server (the Phase 3 VM), reading a CertStream
websocket - normally a self-hosted certstream-server-go next to it - and
checking every certificate name with the lookalike detector. Findings are
written to the database in batches.

    python -m sentinel.hunter stream --url ws://127.0.0.1:8080/domains-only

Both CertStream message shapes are understood:
  full:          {"message_type": "certificate_update",
                  "data": {"leaf_cert": {"all_domains": [...]}, "seen": 1700000000.0}}
  domains-only:  {"message_type": "dns_entries", "data": [...]}
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone

from sentinel.db import init_db, session_scope
from sentinel.hunter.crtsh import finding_to_raw
from sentinel.hunter.detect import analyze

log = logging.getLogger(__name__)

SOURCE = "phishhunter"
FLUSH_SECONDS = 60


def domains_from_message(raw: str | bytes) -> tuple[list[str], datetime | None]:
    try:
        message = json.loads(raw)
    except (ValueError, TypeError):
        return [], None
    kind = message.get("message_type")
    data = message.get("data")
    if kind == "dns_entries" and isinstance(data, list):
        return [d for d in data if isinstance(d, str)], None
    if kind == "certificate_update" and isinstance(data, dict):
        leaf = data.get("leaf_cert") or {}
        seen = data.get("seen")
        when = datetime.fromtimestamp(seen, timezone.utc) if isinstance(seen, (int, float)) else None
        return [d for d in leaf.get("all_domains") or [] if isinstance(d, str)], when
    return [], None


class StreamHunter:
    def __init__(self):
        self.pending: dict[str, object] = {}
        self.seen_names = 0
        self.last_flush = time.monotonic()

    def handle(self, raw: str | bytes) -> int:
        """Check one message; returns how many new findings it produced."""
        names, when = domains_from_message(raw)
        found = 0
        for name in names:
            self.seen_names += 1
            finding = analyze(name)
            if finding and finding.reportable and finding.indicator not in self.pending:
                self.pending[finding.indicator] = finding_to_raw(finding, SOURCE, first_seen=when)
                found += 1
                log.info("lookalike %s (%s, %s, score %d)", finding.indicator, finding.brand,
                         finding.technique, finding.score)
        return found

    def flush(self) -> int:
        from sentinel.ingest import ingest_raw

        if not self.pending:
            return 0
        batch = list(self.pending.values())
        with session_scope() as session:
            ingest_raw(session, SOURCE, batch)
        self.pending.clear()
        self.last_flush = time.monotonic()
        return len(batch)


async def run(url: str) -> None:
    import websockets

    init_db()
    hunter = StreamHunter()
    backoff = 1
    while True:
        try:
            async with websockets.connect(url, max_size=2**22, ping_interval=20) as socket:
                log.info("connected to %s", url)
                backoff = 1
                async for message in socket:
                    hunter.handle(message)
                    if time.monotonic() - hunter.last_flush >= FLUSH_SECONDS:
                        written = hunter.flush()
                        log.info("checked %d names, wrote %d lookalikes", hunter.seen_names, written)
        except (OSError, asyncio.TimeoutError, Exception) as exc:  # keep running through outages
            log.warning("stream error (%s); reconnecting in %ds", type(exc).__name__, backoff)
            hunter.flush()
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60)
