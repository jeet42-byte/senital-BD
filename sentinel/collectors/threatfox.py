"""ThreatFox (abuse.ch): community-submitted IOCs, last 48 hours.

Since October 2026 the export needs a free abuse.ch Auth-Key in the URL path;
the old keyless https://threatfox.abuse.ch/export/json/recent/ answers 410.

JSON object keyed by IOC id; each value is a list holding one record with
ioc_value, ioc_type, threat_type, malware_printable, first_seen_utc,
last_seen_utc, confidence_level, reference and tags.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from sentinel.collectors.base import Collector, RawIndicator, parse_time, split_tags
from sentinel.indicators import IndicatorType

TYPE_MAP = {
    "ip:port": IndicatorType.IPV4,
    "domain": IndicatorType.DOMAIN,
    "url": IndicatorType.URL,
    "md5_hash": IndicatorType.MD5,
    "sha1_hash": IndicatorType.SHA1,
    "sha256_hash": IndicatorType.SHA256,
}


class ThreatFoxCollector(Collector):
    name = "threatfox"
    url = "https://threatfox-api.abuse.ch/v2/files/exports/{auth_key}/recent.json"

    def parse(self, text: str) -> Iterable[RawIndicator]:
        data = json.loads(text)
        records = data.values() if isinstance(data, dict) else [data]
        for group in records:
            for entry in group if isinstance(group, list) else [group]:
                kind = TYPE_MAP.get(entry.get("ioc_type", ""))
                if kind is None or not entry.get("ioc_value"):
                    continue
                confidence = entry.get("confidence_level")
                malware = entry.get("malware_printable")
                yield RawIndicator(
                    type=kind,
                    value=entry["ioc_value"],
                    source=self.name,
                    first_seen=parse_time(entry.get("first_seen_utc")),
                    last_seen=parse_time(entry.get("last_seen_utc")),
                    confidence=int(confidence) if confidence is not None else None,
                    threat_type=entry.get("threat_type"),
                    malware=None if malware in (None, "Unknown malware") else malware,
                    tags=split_tags(entry.get("tags")),
                    reference=entry.get("reference") or None,
                )
