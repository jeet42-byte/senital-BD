"""Ship new Cowrie log lines to the database, a few minutes at a time.

Runs on the honeypot server from a systemd timer:

    python -m sentinel.honeypot ship --log-dir /var/lib/sentinel-bd/cowrie/log

It remembers how far it has read in each log file (by inode, so Cowrie's
daily rotation does not cause lines to be read twice or skipped), turns the
new lines into indicators and daily statistics, and writes both.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from sentinel.db import init_db, session_scope
from sentinel.honeypot.cowrie import SOURCE, DailyStats, indicators_from_sessions, sessions_from_lines
from sentinel.models import FeedRun, HoneypotDaily

log = logging.getLogger(__name__)

# Never read more than this per file per run, so a backlog is worked off
# over several runs instead of in one huge transaction.
MAX_BYTES_PER_RUN = 20 * 1024 * 1024


def read_new_lines(log_dir: Path, state_file: Path) -> tuple[list[str], dict]:
    """New complete lines from cowrie.json*, and the state to save afterwards."""
    try:
        state = json.loads(state_file.read_text())
    except (OSError, ValueError):
        state = {}
    new_state: dict[str, int] = {}
    lines: list[str] = []
    for path in sorted(log_dir.glob("cowrie.json*")):
        try:
            stat = path.stat()
        except OSError:
            continue
        key = str(stat.st_ino)
        offset = int(state.get(key, 0))
        if offset > stat.st_size:  # truncated or replaced
            offset = 0
        if offset < stat.st_size:
            with path.open("rb") as handle:
                handle.seek(offset)
                chunk = handle.read(MAX_BYTES_PER_RUN)
            # Only consume up to the last newline; a half-written line waits.
            end = chunk.rfind(b"\n") + 1
            lines.extend(chunk[:end].decode("utf-8", errors="replace").splitlines())
            offset += end
        new_state[key] = offset
    return lines, new_state


def write_stats(session, stats: DailyStats) -> int:
    rows = stats.rows()
    for day, kind, value, count in rows:
        existing = session.scalar(
            select(HoneypotDaily).where(
                HoneypotDaily.day == day, HoneypotDaily.kind == kind, HoneypotDaily.value == value
            )
        )
        if existing:
            existing.count += count
        else:
            session.add(HoneypotDaily(day=day, kind=kind, value=value, count=count))
    return len(rows)


def link_sessions(db, sessions) -> int:
    """attacker IP -downloaded-> URL -delivers-> file hash."""
    from sentinel.correlate import find, link
    from sentinel.indicators import IndicatorType, normalize

    created = 0
    for s in sessions:
        attacker = find(db, IndicatorType.IPV4.value, s.src_ip) if s.tried_login else None
        for url, sha in s.downloads:
            url_row = find(db, IndicatorType.URL.value, normalize(IndicatorType.URL, url) or "")
            if url_row is None:
                continue
            if attacker is not None:
                created += link(db, attacker, url_row, "downloaded", SOURCE, s.ended)
            sha_value = normalize(IndicatorType.SHA256, sha or "")
            file_row = find(db, IndicatorType.SHA256.value, sha_value) if sha_value else None
            if file_row is not None:
                created += link(db, url_row, file_row, "delivers", SOURCE, s.ended)
    return created


def ship(log_dir: Path, state_file: Path) -> FeedRun:
    from sentinel.ingest import ingest_raw, rescore

    lines, new_state = read_new_lines(log_dir, state_file)
    sessions = sessions_from_lines(lines)
    raws = indicators_from_sessions(sessions)
    started = datetime.now(timezone.utc)
    with session_scope() as db:
        run = FeedRun(source=SOURCE, started_at=started)
        stats = ingest_raw(db, SOURCE, raws)
        write_stats(db, DailyStats().add(sessions))
        link_sessions(db, sessions)
        run.fetched, run.rejected = stats.fetched, stats.rejected
        run.created, run.updated = stats.created, stats.updated
        run.ok = True
        run.finished_at = datetime.now(timezone.utc)
        db.add(run)
    # Saved only after the database commit: a failed write is retried next run.
    state_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = state_file.with_suffix(".tmp")
    tmp.write_text(json.dumps(new_state))
    os.replace(tmp, state_file)
    log.info("read %d lines, %d sessions, %d indicators (%d new)",
             len(lines), len(sessions), len(raws), run.created)
    return run


def main(log_dir: str, state_file: str) -> int:
    init_db()
    run = ship(Path(log_dir), Path(state_file))
    return 0 if run.ok else 1
