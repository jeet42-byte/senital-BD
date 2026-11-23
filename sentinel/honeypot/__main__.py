"""Honeypot command line.

    python -m sentinel.honeypot ship --log-dir /var/lib/sentinel-bd/cowrie/log
    python -m sentinel.honeypot parse cowrie.json     # dry run: print what would be stored
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from sentinel.honeypot.cowrie import DailyStats, indicators_from_sessions, sessions_from_lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sentinel.honeypot")
    commands = parser.add_subparsers(dest="command", required=True)
    ship = commands.add_parser("ship", help="send new Cowrie log lines to the database")
    ship.add_argument("--log-dir", default="/var/lib/sentinel-bd/cowrie/log")
    ship.add_argument("--state", default="/var/lib/sentinel-bd/ship-state.json")
    parse = commands.add_parser("parse", help="show what a Cowrie log would produce")
    parse.add_argument("file")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if args.command == "parse":
        sessions = sessions_from_lines(Path(args.file).read_text(errors="replace").splitlines())
        for raw in indicators_from_sessions(sessions):
            print(f"{raw.type.value:7} {raw.confidence:3} {raw.value}  ({raw.note})")
        for day, kind, value, count in sorted(DailyStats().add(sessions).rows(top=5)):
            print(f"{day} {kind:9} {count:5}  {value}")
        return 0

    from sentinel.honeypot.ship import main as ship_main

    return ship_main(args.log_dir, args.state)


if __name__ == "__main__":
    sys.exit(main())
