"""Phishing hunter command line.

    python -m sentinel.hunter crtsh                  # search certificate logs once
    python -m sentinel.hunter crtsh --tokens bkash nagad --days 90   # backfill
    python -m sentinel.hunter check bkash-verify.top nag4d.app   # try the detector
    python -m sentinel.hunter stream --url ws://127.0.0.1:8080/domains-only
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

import httpx

from sentinel.config import get_settings
from sentinel.db import init_db
from sentinel.hunter.crtsh import CrtShHunter
from sentinel.hunter.detect import SEARCH_TOKENS, analyze


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sentinel.hunter")
    commands = parser.add_subparsers(dest="command", required=True)
    crtsh = commands.add_parser("crtsh", help="search certificate logs for lookalike domains")
    crtsh.add_argument("--tokens", nargs="+", default=list(SEARCH_TOKENS))
    crtsh.add_argument("--days", type=int, default=7, help="how far back to look (default 7)")
    check = commands.add_parser("check", help="run the detector on names you type")
    check.add_argument("names", nargs="+")
    recheck = commands.add_parser("recheck", help="drop earlier hunter findings that no longer pass the detector")
    recheck.add_argument("--dry-run", action="store_true")
    stream = commands.add_parser("stream", help="watch a CertStream websocket continuously")
    stream.add_argument("--url", default="ws://127.0.0.1:8080/domains-only")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)

    if args.command == "check":
        for name in args.names:
            finding = analyze(name)
            if finding is None:
                print(f"{name}: no brand imitation")
            else:
                verdict = "REPORT" if finding.reportable else "below threshold"
                print(f"{name}: {finding.score} {verdict} - imitates {finding.brand} ({finding.technique})")
                for reason in finding.reasons:
                    print(f"    {reason}")
        return 0

    if args.command == "recheck":
        return recheck(dry_run=args.dry_run)

    if args.command == "stream":
        asyncio.run(__import__("sentinel.hunter.stream", fromlist=["run"]).run(args.url))
        return 0

    from sentinel.ingest import rescore_all, run_collector
    from sentinel.db import session_scope

    init_db()
    with httpx.Client(timeout=get_settings().HTTP_TIMEOUT_SECONDS, follow_redirects=True) as client:
        run = run_collector(CrtShHunter(args.tokens, lookback_days=args.days), client=client)
    with session_scope() as session:
        rescore_all(session)
    return 0 if run.ok else 1


def recheck(dry_run: bool = False) -> int:
    """Re-run the detector over stored hunter findings after a rule change.

    A finding the stricter detector rejects loses its hunter sighting; an
    indicator with no other source is deleted. Feeds that independently
    reported the same domain keep it.
    """
    from sqlalchemy import select

    from sentinel.db import session_scope
    from sentinel.ingest import rescore
    from sentinel.models import Indicator, Sighting

    init_db()
    removed = kept = 0
    with session_scope() as session:
        rows = session.scalars(
            select(Indicator).where(Indicator.sightings.any(Sighting.source == "phishhunter"))
        ).all()
        for indicator in rows:
            finding = analyze(indicator.value)
            if finding and finding.reportable:
                kept += 1
                continue
            removed += 1
            print(f"remove {indicator.value}")
            if dry_run:
                continue
            others = [s for s in indicator.sightings if s.source != "phishhunter"]
            if not others:
                session.delete(indicator)
            else:
                indicator.sightings = others
                rescore(indicator)
        if dry_run:
            session.rollback()
    print(f"{kept} kept, {removed} {'would be ' if dry_run else ''}removed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
