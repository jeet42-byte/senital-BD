"""Bangladesh relevance: does this indicator concern Bangladesh?

An indicator is BD-relevant when any of these holds, and the reasons are
stored so analysts can see why:

  tld:.bd             the domain or URL host is under .bd
  impersonates:<x>    the host imitates a Bangladeshi bank, MFS or telco
  ip:bd-space         the IP is in address space allocated to Bangladesh
  geo:BD              the source feed itself geolocates it to Bangladesh

The BD IP ranges come from APNIC's public delegation file. Refresh them with

    python -m sentinel.bd update
"""

from __future__ import annotations

import bisect
import ipaddress
import logging
import sys
from functools import lru_cache
from pathlib import Path

from sentinel.allowlist import is_allowlisted_domain
from sentinel.config import get_settings
from sentinel.indicators import IndicatorType, url_host

log = logging.getLogger(__name__)

APNIC_DELEGATED_URL = "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest"

# Names attackers put in lookalike domains (bkash-verify.com, nagad-bonus.xyz).
# Only distinctive tokens: "rocket" or "city" would match far too much.
BRAND_TOKENS: dict[str, str] = {
    "bkash": "bKash",
    "nagad": "Nagad",
    "dutchbangla": "Dutch-Bangla Bank",
    "dbbl": "Dutch-Bangla Bank",
    "sonalibank": "Sonali Bank",
    "janatabank": "Janata Bank",
    "agranibank": "Agrani Bank",
    "rupalibank": "Rupali Bank",
    "bracbank": "BRAC Bank",
    "islamibank": "Islami Bank",
    "ibbl": "Islami Bank",
    "pubalibank": "Pubali Bank",
    "primebank": "Prime Bank",
    "citybankbd": "City Bank",
    "grameenphone": "Grameenphone",
    "banglalink": "Banglalink",
    "teletalk": "Teletalk",
    "bangladesh": "Bangladesh (generic)",
}


class BdIpRanges:
    """Sorted IPv4 ranges with O(log n) membership tests."""

    def __init__(self, cidrs: list[str]):
        ranges = []
        for cidr in cidrs:
            net = ipaddress.IPv4Network(cidr, strict=False)
            ranges.append((int(net.network_address), int(net.broadcast_address)))
        ranges.sort()
        self._starts = [start for start, _ in ranges]
        self._ends = [end for _, end in ranges]

    def __len__(self) -> int:
        return len(self._starts)

    def overlaps(self, cidr: str) -> bool:
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            return False
        start, end = int(net.network_address), int(net.broadcast_address)
        i = bisect.bisect_right(self._starts, end) - 1
        return i >= 0 and self._ends[i] >= start

    def __contains__(self, ip: str) -> bool:
        try:
            value = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return False
        i = bisect.bisect_right(self._starts, value) - 1
        return i >= 0 and value <= self._ends[i]

    @classmethod
    def from_file(cls, path: str | Path) -> BdIpRanges:
        path = Path(path)
        if not path.exists():
            log.warning("No BD IP ranges at %s; run `python -m sentinel.bd update`", path)
            return cls([])
        lines = path.read_text().splitlines()
        return cls([line.strip() for line in lines if line.strip() and not line.startswith("#")])


def parse_apnic_delegated(text: str, country: str = "BD") -> list[str]:
    """CIDRs for one country from an RIR delegation file.

    Lines look like: apnic|BD|ipv4|103.4.144.0|1024|20100205|allocated
    The count is not always a power of two, so a block may need several CIDRs.
    """
    cidrs: list[str] = []
    for line in text.splitlines():
        parts = line.split("|")
        if len(parts) < 7 or parts[1] != country or parts[2] != "ipv4":
            continue
        if parts[6] not in {"allocated", "assigned"}:
            continue
        start = ipaddress.IPv4Address(parts[3])
        end = ipaddress.IPv4Address(int(start) + int(parts[4]) - 1)
        cidrs.extend(str(net) for net in ipaddress.summarize_address_range(start, end))
    return cidrs


@lru_cache
def bd_ranges() -> BdIpRanges:
    return BdIpRanges.from_file(get_settings().BD_RANGES_PATH)


def impersonated_brands(host: str) -> list[str]:
    """Bangladeshi brands a hostname appears to imitate (never the real site)."""
    host = host.lower()
    if is_allowlisted_domain(host):
        return []
    flat = host.replace("-", "").replace(".", "")
    return sorted({brand for token, brand in BRAND_TOKENS.items() if token in flat})


def bd_reasons(
    kind: IndicatorType | str,
    value: str,
    country: str | None = None,
    ranges: BdIpRanges | None = None,
) -> list[str]:
    kind = IndicatorType(kind)
    ranges = ranges if ranges is not None else bd_ranges()
    reasons: list[str] = []

    host = ""
    if kind is IndicatorType.DOMAIN:
        host = value
    elif kind is IndicatorType.URL:
        host = url_host(value)

    if host:
        if host == "bd" or host.endswith(".bd"):
            reasons.append("tld:.bd")
        reasons.extend(f"impersonates:{brand}" for brand in impersonated_brands(host))
        ip_value = host if _is_ip(host) else None
    else:
        ip_value = value if kind is IndicatorType.IPV4 else None

    if ip_value and ip_value in ranges:
        reasons.append("ip:bd-space")
    if kind is IndicatorType.CIDR and ranges.overlaps(value):
        reasons.append("ip:bd-space")
    if country and country.upper() == "BD":
        reasons.append("geo:BD")
    return reasons


def _is_ip(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def update_ranges(path: str | Path | None = None) -> int:
    """Download APNIC's delegation file and write the BD ranges. Returns the count."""
    import httpx

    settings = get_settings()
    path = Path(path or settings.BD_RANGES_PATH)
    response = httpx.get(
        APNIC_DELEGATED_URL,
        headers={"User-Agent": settings.USER_AGENT},
        timeout=settings.HTTP_TIMEOUT_SECONDS,
        follow_redirects=True,
    )
    response.raise_for_status()
    cidrs = parse_apnic_delegated(response.text)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# Bangladesh IPv4 space from APNIC delegated-apnic-latest\n" + "\n".join(cidrs) + "\n")
    bd_ranges.cache_clear()
    return len(cidrs)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if sys.argv[1:] == ["update"]:
        print(f"Wrote {update_ranges()} Bangladeshi IPv4 ranges")
    else:
        print("usage: python -m sentinel.bd update")
        sys.exit(2)
