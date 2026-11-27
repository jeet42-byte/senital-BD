"""Registry of feed collectors. Add a new feed by subclassing Collector."""

from sentinel.collectors.attackers import BlocklistDeCollector, CinsCollector, SpamhausDropCollector
from sentinel.collectors.base import Collector, RawIndicator
from sentinel.collectors.feodo import FeodoCollector
from sentinel.collectors.openphish import OpenPhishCollector
from sentinel.collectors.threatfox import ThreatFoxCollector
from sentinel.collectors.urlhaus import UrlhausCollector

COLLECTORS: dict[str, Collector] = {
    collector.name: collector
    for collector in (
        FeodoCollector(),
        UrlhausCollector(),
        ThreatFoxCollector(),
        OpenPhishCollector(),
        BlocklistDeCollector(),
        CinsCollector(),
        SpamhausDropCollector(),
    )
}

__all__ = ["COLLECTORS", "Collector", "RawIndicator"]
