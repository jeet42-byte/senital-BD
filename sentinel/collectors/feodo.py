"""Feodo Tracker (abuse.ch): botnet command-and-control servers.

JSON list of {ip_address, port, status, hostname, as_number, as_name,
country, first_seen, last_online, malware}.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from sentinel.collectors.base import Collector, RawIndicator, parse_time
from sentinel.indicators import IndicatorType


class FeodoCollector(Collector):
    name = "feodotracker"
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    sends_abusech_key = True

    def parse(self, text: str) -> Iterable[RawIndicator]:
        for entry in json.loads(text):
            ip = entry.get("ip_address")
            if not ip:
                continue
            online = entry.get("status") == "online"
            tags = ["botnet_cc"]
            if entry.get("port"):
                tags.append(f"port:{entry['port']}")
            yield RawIndicator(
                type=IndicatorType.IPV4,
                value=ip,
                source=self.name,
                first_seen=parse_time(entry.get("first_seen")),
                last_seen=None if online else parse_time(entry.get("last_online")),
                threat_type="botnet_cc",
                malware=entry.get("malware"),
                tags=tags,
                reference=f"https://feodotracker.abuse.ch/browse/host/{ip}/",
                country=entry.get("country"),
            )
