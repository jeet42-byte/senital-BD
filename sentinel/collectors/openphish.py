"""OpenPhish community feed: live phishing URLs, one per line."""

from __future__ import annotations

from collections.abc import Iterable

from sentinel.collectors.base import Collector, RawIndicator
from sentinel.indicators import IndicatorType


class OpenPhishCollector(Collector):
    name = "openphish"
    url = "https://openphish.com/feed.txt"

    def parse(self, text: str) -> Iterable[RawIndicator]:
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                yield RawIndicator(
                    type=IndicatorType.URL,
                    value=line,
                    source=self.name,
                    threat_type="phishing",
                    tags=["phishing"],
                )
