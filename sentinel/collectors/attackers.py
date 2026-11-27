"""Attackers and scanners: IPs and networks seen attacking other people's systems.

  blocklist.de     IPs that attacked its members' SSH, mail, web and FTP
                   servers in the last 48 hours (fail2ban reports).
  CINS Army        IPs with a poor reputation across Sentinel IPS sensors.
  Spamhaus DROP    whole networks hijacked or run by criminals ("Don't Route
                   Or Peer"). Listed as IP ranges.

These widen the network-attack picture beyond Sentinel-BD's own honeypot:
an IP that brute-forced the honeypot and is also on blocklist.de scores
higher, because two independent sensors agree.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from sentinel.collectors.base import Collector, RawIndicator
from sentinel.indicators import IndicatorType


def _lines(text: str) -> Iterable[str]:
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            yield line


class BlocklistDeCollector(Collector):
    name = "blocklist.de"
    url = "https://lists.blocklist.de/lists/all.txt"

    def parse(self, text: str) -> Iterable[RawIndicator]:
        for line in _lines(text):
            yield RawIndicator(
                type=IndicatorType.IPV4, value=line, source=self.name,
                threat_type="bruteforce", tags=["bruteforce", "attacker"],
                reference=f"https://www.blocklist.de/en/view.html?ip={line}",
            )


class CinsCollector(Collector):
    name = "cins"
    url = "https://cinsscore.com/list/ci-badguys.txt"

    def parse(self, text: str) -> Iterable[RawIndicator]:
        for line in _lines(text):
            yield RawIndicator(
                type=IndicatorType.IPV4, value=line, source=self.name,
                threat_type="scanner", tags=["scanner", "attacker"],
                reference="https://cinsscore.com/",
            )


class SpamhausDropCollector(Collector):
    """DROP in its JSON-lines form, with the older text form also accepted:

        {"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
        1.10.16.0/20 ; SBL256894
    """

    name = "spamhaus-drop"
    url = "https://www.spamhaus.org/drop/drop_v4.json"

    def parse(self, text: str) -> Iterable[RawIndicator]:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            cidr = sbl = None
            if line.startswith("{"):
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                cidr, sbl = entry.get("cidr"), entry.get("sblid")
            else:
                cidr, _, rest = line.partition(";")
                sbl = rest.strip() or None
            if not cidr:
                continue  # e.g. the trailing {"type":"metadata",...} line
            yield RawIndicator(
                type=IndicatorType.CIDR, value=cidr.strip(), source=self.name,
                threat_type="hijacked_network", tags=["drop", "hijacked-network"],
                reference=f"https://check.spamhaus.org/sbl/query/{sbl}" if sbl else "https://www.spamhaus.org/drop/",
            )
