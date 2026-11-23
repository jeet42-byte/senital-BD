"""Cowrie honeypot logs -> Sentinel-BD indicators and statistics.

Cowrie writes one JSON object per line (cowrie.json). Events are grouped by
session, and each session becomes evidence about the attacker:

  cowrie.session.connect        the attacker's IP (src_ip) and protocol
  cowrie.login.failed/.success  username and password tried
  cowrie.command.input          what they typed once "logged in"
  cowrie.session.file_download  malware they fetched: URL and SHA-256

Indicators produced (source "honeypot"):

  attacker IP   confidence by behaviour: tried logins 60, got a shell and ran
                commands 80, downloaded something 95
  download URL  confidence 90
  file SHA-256  confidence 95 (the file is in hand)

A port scan that never tries to log in is not reported: it is background
noise every internet host sees, and blocking it achieves nothing.

Statistics (top usernames, passwords, commands, attacks per day) are
aggregated per day for the dashboard; individual sessions are not stored.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sentinel.collectors.base import RawIndicator, parse_time
from sentinel.indicators import IndicatorType, normalize

SOURCE = "honeypot"
MAX_TEXT = 200  # attacker-typed text is truncated before it is stored


@dataclass
class Session:
    session: str
    src_ip: str = ""
    protocol: str = "ssh"
    started: datetime | None = None
    ended: datetime | None = None
    usernames: list[str] = field(default_factory=list)
    passwords: list[str] = field(default_factory=list)
    logged_in: bool = False
    commands: list[str] = field(default_factory=list)
    downloads: list[tuple[str, str]] = field(default_factory=list)  # (url, sha256)
    client: str | None = None

    @property
    def tried_login(self) -> bool:
        return bool(self.usernames)

    @property
    def confidence(self) -> int:
        if self.downloads:
            return 95
        if self.logged_in and self.commands:
            return 80
        return 60

    def summary(self) -> str:
        parts = [f"{self.protocol}: {len(self.usernames)} login attempt(s)"]
        if self.logged_in:
            parts.append(f"{len(self.commands)} command(s)")
        if self.downloads:
            parts.append(f"{len(self.downloads)} download(s)")
        if self.client:
            parts.append(f"client {self.client}")
        return ", ".join(parts)


def _clip(text: object) -> str:
    return str(text)[:MAX_TEXT]


def sessions_from_lines(lines: Iterable[str]) -> list[Session]:
    """Group Cowrie JSON lines into sessions. Bad lines are skipped."""
    sessions: dict[str, Session] = {}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict) or "session" not in event:
            continue
        sid = str(event["session"])
        s = sessions.setdefault(sid, Session(session=sid))
        when = parse_time(str(event.get("timestamp", "")).replace("T", " ")[:19])
        if when:
            s.started = min(s.started, when) if s.started else when
            s.ended = max(s.ended, when) if s.ended else when
        if event.get("src_ip") and not s.src_ip:
            s.src_ip = str(event["src_ip"])
        kind = event.get("eventid", "")
        if event.get("protocol"):
            s.protocol = str(event["protocol"])
        if kind in ("cowrie.login.failed", "cowrie.login.success"):
            s.usernames.append(_clip(event.get("username", "")))
            s.passwords.append(_clip(event.get("password", "")))
            s.logged_in |= kind == "cowrie.login.success"
        elif kind == "cowrie.command.input":
            s.commands.append(_clip(event.get("input", "")))
        elif kind == "cowrie.session.file_download" and event.get("url"):
            s.downloads.append((str(event["url"]), str(event.get("shasum", ""))))
        elif kind == "cowrie.client.version":
            s.client = _clip(event.get("version", ""))
    return [s for s in sessions.values() if s.src_ip]


def indicators_from_sessions(sessions: Iterable[Session]) -> list[RawIndicator]:
    raws: list[RawIndicator] = []
    for s in sessions:
        if not s.tried_login:
            continue
        tags = ["honeypot", s.protocol, "bruteforce"]
        if s.logged_in:
            tags.append("interactive")
        if s.downloads:
            tags.append("dropper")
        raws.append(RawIndicator(
            type=IndicatorType.IPV4, value=s.src_ip, source=SOURCE,
            first_seen=s.started, last_seen=s.ended, confidence=s.confidence,
            threat_type="honeypot_attacker", tags=tags, note=s.summary(),
        ))
        for url, sha in s.downloads:
            raws.append(RawIndicator(
                type=IndicatorType.URL, value=url, source=SOURCE,
                first_seen=s.started, last_seen=s.ended, confidence=90,
                threat_type="malware_download", tags=["honeypot", "dropper"],
                note=f"Fetched by {s.src_ip} on the {s.protocol} honeypot",
            ))
            if sha and normalize(IndicatorType.SHA256, sha):
                raws.append(RawIndicator(
                    type=IndicatorType.SHA256, value=sha, source=SOURCE,
                    first_seen=s.started, last_seen=s.ended, confidence=95,
                    threat_type="payload", tags=["honeypot", "captured"],
                    note=f"Captured from {url[:120]}",
                ))
    return raws


@dataclass
class DailyStats:
    """day -> kind -> value -> count. Kinds: session, attacker, username,
    password, command, protocol."""

    counts: dict[str, dict[str, Counter]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(Counter)))

    def add(self, sessions: Iterable[Session]) -> DailyStats:
        for s in sessions:
            day = (s.started or datetime.now(timezone.utc)).date().isoformat()
            bucket = self.counts[day]
            bucket["session"]["all"] += 1
            bucket["protocol"][s.protocol] += 1
            if s.tried_login:
                bucket["attacker"][s.src_ip] += 1
            bucket["username"].update(u for u in s.usernames if u)
            bucket["password"].update(p for p in s.passwords if p)
            bucket["command"].update(c for c in s.commands if c)
        return self

    def rows(self, top: int = 50) -> list[tuple[str, str, str, int]]:
        """(day, kind, value, count), keeping only the top values per kind."""
        out = []
        for day, kinds in self.counts.items():
            for kind, counter in kinds.items():
                for value, count in counter.most_common(top):
                    out.append((day, kind, value, count))
        return out
