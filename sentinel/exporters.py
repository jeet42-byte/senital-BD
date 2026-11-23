"""Feed exports: the formats firewalls, DNS servers and SIEMs consume.

  plain text   one indicator per line: Palo Alto EDL, FortiGate threat feed,
               pfSense/OPNsense pfBlockerNG, MikroTik scripts
  RPZ zone     DNS firewall for BIND, Unbound, PowerDNS (and Pi-hole via lists)
  STIX 2.1     bundle for MISP, OpenCTI, Splunk, Elastic, Wazuh

Domain and IP exports skip allowlisted entries (see allowlist.py). The URL
export keeps them, because blocking one URL never takes a whole site down.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Sequence
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session, noload, selectinload

from sentinel import __version__
from sentinel.allowlist import is_allowlisted_domain, is_allowlisted_ip
from sentinel.config import get_settings
from sentinel.indicators import IndicatorType
from sentinel.models import Indicator
from sentinel.scoring import as_utc

# Fixed namespace so the same indicator always gets the same STIX id.
STIX_NAMESPACE = uuid.UUID("6f1c2a8e-3d4b-5e6f-8a9b-0c1d2e3f4a5b")
IDENTITY_ID = f"identity--{uuid.uuid5(STIX_NAMESPACE, 'sentinel-bd')}"


def select_indicators(
    session: Session,
    types: Sequence[IndicatorType],
    min_score: int = 50,
    bd_only: bool = False,
    limit: int | None = None,
    with_sightings: bool = False,
) -> list[Indicator]:
    limit = min(limit or get_settings().FEED_MAX_ROWS, get_settings().FEED_MAX_ROWS)
    query = (
        select(Indicator)
        # Plain-text feeds only need the values; loading every sighting for
        # 50,000 rows would multiply the work for nothing.
        .options(selectinload(Indicator.sightings) if with_sightings else noload(Indicator.sightings))
        .where(Indicator.type.in_([t.value for t in types]), Indicator.score >= min_score)
        .order_by(Indicator.score.desc(), Indicator.last_seen.desc())
    )
    if bd_only:
        query = query.where(Indicator.bd_relevant.is_(True))

    rows: list[Indicator] = []
    # Over-fetch so allowlist filtering does not leave the feed short.
    for indicator in session.scalars(query.limit(limit * 2)):
        if indicator.type == IndicatorType.DOMAIN and is_allowlisted_domain(indicator.value):
            continue
        if indicator.type == IndicatorType.IPV4 and is_allowlisted_ip(indicator.value):
            continue
        rows.append(indicator)
        if len(rows) >= limit:
            break
    return rows


def to_plain_text(indicators: Sequence[Indicator], strip_scheme: bool = False) -> str:
    lines = []
    for indicator in indicators:
        value = indicator.value
        # Palo Alto URL EDLs expect "host/path" without the scheme.
        if strip_scheme and "://" in value:
            value = value.split("://", 1)[1]
        lines.append(value)
    return "\n".join(lines) + ("\n" if lines else "")


def to_mikrotik(ips: Sequence[Indicator], list_name: str = "sentinel-bd") -> str:
    """RouterOS script: replace the address list. Values are validated IPv4,
    so nothing from a feed can inject RouterOS commands."""
    lines = [
        "# Sentinel-BD address list for MikroTik RouterOS",
        f'/ip firewall address-list remove [find list="{list_name}"]',
    ]
    lines += [
        f'/ip firewall address-list add list="{list_name}" address={i.value} timeout=1d'
        for i in ips
        if i.type == IndicatorType.IPV4
    ]
    return "\n".join(lines) + "\n"


def to_rpz(domains: Sequence[Indicator], now: datetime | None = None) -> str:
    """Response Policy Zone: 'CNAME .' answers NXDOMAIN for the name and its subdomains."""
    now = now or datetime.now(timezone.utc)
    serial = int(now.timestamp())
    lines = [
        "; Sentinel-BD DNS firewall (RPZ)",
        f"; generated {now.strftime('%Y-%m-%dT%H:%M:%SZ')}, {len(domains)} domains",
        "$TTL 300",
        f"@ IN SOA localhost. hostmaster.localhost. ( {serial} 3600 600 86400 300 )",
        "  IN NS localhost.",
    ]
    for indicator in domains:
        lines.append(f"{indicator.value} CNAME .")
        lines.append(f"*.{indicator.value} CNAME .")
    return "\n".join(lines) + "\n"


def _stix_time(value: datetime) -> str:
    return as_utc(value).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _stix_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def stix_pattern(kind: str, value: str) -> str:
    value = _stix_escape(value)
    return {
        IndicatorType.IPV4.value: f"[ipv4-addr:value = '{value}']",
        IndicatorType.DOMAIN.value: f"[domain-name:value = '{value}']",
        IndicatorType.URL.value: f"[url:value = '{value}']",
        IndicatorType.MD5.value: f"[file:hashes.MD5 = '{value}']",
        IndicatorType.SHA1.value: f"[file:hashes.'SHA-1' = '{value}']",
        IndicatorType.SHA256.value: f"[file:hashes.'SHA-256' = '{value}']",
    }[kind]


def to_stix_bundle(indicators: Sequence[Indicator], now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    created = _stix_time(datetime(2026, 1, 1, tzinfo=timezone.utc))
    objects: list[dict] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": IDENTITY_ID,
            "created": created,
            "modified": created,
            "name": "Sentinel-BD",
            "identity_class": "system",
            "description": "Bangladesh-focused open threat intelligence feed",
        }
    ]
    for indicator in indicators:
        labels = sorted(
            {f"severity:{indicator.severity}", *(indicator.tags or []), *(indicator.bd_reasons or [])}
            | ({f"malware:{indicator.malware.lower()}"} if indicator.malware else set())
        )
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid5(STIX_NAMESPACE, f'{indicator.type}:{indicator.value}')}",
                "created_by_ref": IDENTITY_ID,
                "created": _stix_time(indicator.first_seen),
                "modified": _stix_time(indicator.last_seen),
                "name": f"{indicator.type}: {indicator.value}"[:250],
                "indicator_types": ["malicious-activity"],
                "pattern": stix_pattern(indicator.type, indicator.value),
                "pattern_type": "stix",
                "valid_from": _stix_time(indicator.first_seen),
                "confidence": indicator.score,
                "labels": labels,
                "external_references": [
                    {"source_name": s.source, **({"url": s.reference} if s.reference else {})}
                    for s in indicator.sightings
                ],
            }
        )
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
    return json.dumps(bundle, indent=1)


FEED_TYPES: dict[str, tuple[IndicatorType, ...]] = {
    "ip": (IndicatorType.IPV4,),
    "domain": (IndicatorType.DOMAIN,),
    "url": (IndicatorType.URL,),
    "hash": (IndicatorType.SHA256, IndicatorType.SHA1, IndicatorType.MD5),
}

GENERATOR = f"Sentinel-BD/{__version__}"
