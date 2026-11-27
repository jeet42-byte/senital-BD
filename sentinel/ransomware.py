"""Ransomware victim tracking, focused on Bangladesh and South Asia.

    python -m sentinel.ransomware

Ransomware gangs announce victims on their leak sites to pressure them into
paying. ransomware.live collects those public announcements; Sentinel-BD
keeps the metadata (organisation name, gang, country, sector, date) to show
which gangs are active and who in Bangladesh and South Asia is being hit.

Victims are not attackers: nothing here ever becomes an indicator or enters
a blocklist, and no leaked data or post text is stored.
"""

from __future__ import annotations

import hashlib
import logging
import sys
from collections.abc import Iterable
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from sentinel.collectors.base import parse_time
from sentinel.config import get_settings
from sentinel.db import init_db, session_scope
from sentinel.models import FeedRun, RansomwareVictim

log = logging.getLogger("sentinel.ransomware")

RECENT_URL = "https://api.ransomware.live/v2/recentvictims"
SOUTH_ASIA = {"BD": "Bangladesh", "IN": "India", "PK": "Pakistan", "LK": "Sri Lanka", "NP": "Nepal",
              "BT": "Bhutan", "MV": "Maldives", "AF": "Afghanistan"}


def _first(entry: dict, *keys: str) -> str | None:
    for key in keys:
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def parse_victims(payload: object) -> list[dict]:
    """Normalise ransomware.live records. Field names differ between API
    versions (victim / post_title, group / group_name...), so each field is
    read from whichever name is present."""
    entries = payload if isinstance(payload, list) else (payload or {}).get("victims", []) if isinstance(payload, dict) else []
    victims = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = _first(entry, "victim", "post_title", "name")
        group = _first(entry, "group", "group_name")
        if not name or not group:
            continue
        country = (_first(entry, "country") or "").upper()[:2] or None
        attacked = parse_time(_first(entry, "attackdate", "published", "date"))
        discovered = parse_time(_first(entry, "discovered")) or attacked
        victims.append({
            "victim": name[:300],
            "group": group[:100].lower(),
            "country": country if country and country.isalpha() else None,
            "sector": (_first(entry, "activity", "sector") or "")[:120] or None,
            "website": (_first(entry, "domain", "website") or "")[:255] or None,
            "attack_date": attacked or discovered,
            "discovered": discovered,
        })
    return victims


def _key(v: dict) -> str:
    day = v["attack_date"].date().isoformat() if v["attack_date"] else ""
    return hashlib.sha1(f"{v['group']}|{v['victim'].lower()}|{day}".encode()).hexdigest()


def store(session: Session, victims: Iterable[dict]) -> tuple[int, int]:
    """Returns (new victims, of which in South Asia)."""
    new = new_sa = 0
    for v in victims:
        key = _key(v)
        if session.scalar(select(RansomwareVictim.id).where(RansomwareVictim.key == key)):
            continue
        session.add(RansomwareVictim(
            key=key, victim=v["victim"], group=v["group"], country=v["country"], sector=v["sector"],
            website=v["website"], attack_date=v["attack_date"], discovered=v["discovered"],
            south_asia=v["country"] in SOUTH_ASIA,
        ))
        new += 1
        new_sa += v["country"] in SOUTH_ASIA
    session.flush()
    return new, new_sa


def run(client: httpx.Client | None = None) -> int:
    own = client is None
    client = client or httpx.Client(timeout=60, follow_redirects=True,
                                    headers={"User-Agent": get_settings().USER_AGENT, "Accept": "application/json"})
    started = datetime.now(timezone.utc)
    try:
        response = client.get(RECENT_URL)
        response.raise_for_status()
        victims = parse_victims(response.json())
        with session_scope() as session:
            new, new_sa = store(session, victims)
            session.add(FeedRun(source="ransomware.live", started_at=started, finished_at=datetime.now(timezone.utc),
                                ok=True, fetched=len(victims), created=new))
        log.info("ransomware.live: %d victims, %d new (%d in South Asia)", len(victims), new, new_sa)
        return 0
    except Exception as exc:  # noqa: BLE001 - recorded on the dashboard's pipeline panel
        log.error("ransomware.live failed: %s", exc)
        with session_scope() as session:
            session.add(FeedRun(source="ransomware.live", started_at=started, finished_at=datetime.now(timezone.utc),
                                ok=False, error=f"{type(exc).__name__}: {str(exc)[:300]}"))
        return 1
    finally:
        if own:
            client.close()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    init_db()
    return run()


if __name__ == "__main__":
    sys.exit(main())
