"""URLhaus (abuse.ch): URLs distributing malware, last 30 days.

Since October 2026 the export needs a free abuse.ch Auth-Key in the URL path;
the old keyless https://urlhaus.abuse.ch/downloads/csv_recent/ answers 410.

CSV columns: id, dateadded, url, url_status, last_online, threat, tags,
urlhaus_link, reporter. Lines starting with '#' are comments.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable

from sentinel.collectors.base import Collector, RawIndicator, parse_time, split_tags
from sentinel.indicators import IndicatorType


class UrlhausCollector(Collector):
    name = "urlhaus"
    url = "https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"

    def parse(self, text: str) -> Iterable[RawIndicator]:
        rows = (line for line in io.StringIO(text) if line.strip() and not line.startswith("#"))
        for row in csv.reader(rows):
            if len(row) < 8 or row[0].strip().lower() == "id":  # header row
                continue
            _id, added, url, status, last_online, threat, tags, link = row[:8]
            first_seen = parse_time(added)
            # An online URL is live now; an offline one was last live then.
            last_seen = None if status == "online" else (parse_time(last_online) or first_seen)
            yield RawIndicator(
                type=IndicatorType.URL,
                value=url,
                source=self.name,
                first_seen=first_seen,
                last_seen=last_seen,
                threat_type=threat or "malware_download",
                tags=split_tags(tags),
                reference=link or None,
            )
