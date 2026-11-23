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


if __name__ == "__main__":
    sys.exit(main())
