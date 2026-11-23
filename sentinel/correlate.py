"""Correlation: link indicators that share infrastructure.

    python -m sentinel.correlate              # all steps
    python -m sentinel.correlate --no-dns     # skip DNS lookups

Steps (each only links indicators that are already known; nothing here
creates a new indicator):

  1. hosted-on    every URL is linked to its host, when the host (domain or
                  IP) is itself an indicator. URLhaus serving malware from an
                  IP that also attacked the honeypot shows up here.
  2. resolves-to  selected domains are looked up in DNS; an answer that is a
                  known malicious IP is linked. All answers are kept in
                  dns_resolution, but never become indicators themselves.

The honeypot shipper adds downloaded / delivers links as it goes.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import sys
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from sentinel.allowlist import is_allowlisted_domain
from sentinel.db import init_db, session_scope
from sentinel.indicators import IndicatorType, url_host
from sentinel.models import Indicator, Relation, Resolution, Sighting

log = logging.getLogger("sentinel.correlate")

CHUNK = 500
DNS_BATCH = 800            # lookups per run
DNS_RECHECK = timedelta(hours=24)
DNS_TIMEOUT = 3.0


def link(session: Session, src: Indicator, dst: Indicator, kind: str, origin: str,
         when: datetime | None = None) -> bool:
    """Create or refresh one relation. Returns True when it is new."""
    if src.id is None or dst.id is None:
        session.flush()
    when = when or datetime.now(timezone.utc)
    existing = session.scalar(select(Relation).where(
        Relation.src_id == src.id, Relation.dst_id == dst.id, Relation.kind == kind))
    if existing:
        existing.last_seen = max(_utc(existing.last_seen), when)
        return False
    session.add(Relation(src_id=src.id, dst_id=dst.id, kind=kind, origin=origin,
                         first_seen=when, last_seen=when))
    return True


def find(session: Session, kind: str, value: str) -> Indicator | None:
    return session.scalar(select(Indicator).where(Indicator.type == kind, Indicator.value == value))


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.IPv4Address(host)
        return True
    except ValueError:
        return False


def link_url_hosts(session: Session) -> int:
    """Step 1: url -> host, in bulk."""
    host_ids: dict[tuple[str, str], int] = {}
    for kind in (IndicatorType.IPV4.value, IndicatorType.DOMAIN.value):
        for row_id, value in session.execute(select(Indicator.id, Indicator.value).where(Indicator.type == kind)):
            host_ids[(kind, value)] = row_id
    if not host_ids:
        return 0

    existing = {
        (src, dst) for src, dst in session.execute(
            select(Relation.src_id, Relation.dst_id).where(Relation.kind == "hosted-on"))
    }
    created = 0
    urls = session.execute(
        select(Indicator.id, Indicator.value, Indicator.last_seen).where(Indicator.type == IndicatorType.URL.value)
    ).yield_per(5000)
    for url_id, url, seen in urls:
        host = url_host(url)
        target = host_ids.get(("ipv4" if _is_ip(host) else "domain", host))
        if target is None or (url_id, target) in existing:
            continue
        session.add(Relation(src_id=url_id, dst_id=target, kind="hosted-on", origin="url-host",
                             first_seen=seen, last_seen=seen))
        existing.add((url_id, target))
        created += 1
    session.flush()
    return created


def dns_candidates(session: Session, now: datetime, limit: int) -> list[Indicator]:
    """Domains worth resolving: the hunter's finds, anything aimed at
    Bangladesh, and the strongest of the rest; not checked in the last day."""
    stale = or_(Indicator.dns_checked_at.is_(None), Indicator.dns_checked_at < now - DNS_RECHECK)
    base = select(Indicator).where(Indicator.type == IndicatorType.DOMAIN.value, stale)
    picked: list[Indicator] = []
    seen: set[int] = set()
    for query in (
        base.where(Indicator.sightings.any(Sighting.source == "phishhunter")),
        base.where(Indicator.bd_relevant.is_(True)),
        base.where(Indicator.score >= 50).order_by(Indicator.score.desc()),
    ):
        for row in session.scalars(query.limit(limit)):
            if row.id not in seen and not is_allowlisted_domain(row.value):
                picked.append(row)
                seen.add(row.id)
            if len(picked) >= limit:
                return picked
    return picked


def resolve(domain: str) -> list[str]:
    """Public IPv4 answers for a domain; empty on any failure."""
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    try:
        answer = resolver.resolve(domain, "A")
    except (dns.exception.DNSException, OSError, ValueError):
        return []
    ips = []
    for record in answer:
        try:
            ip = ipaddress.IPv4Address(record.to_text())
        except ValueError:
            continue
        if ip.is_global:  # answers are attacker-controlled: drop 127.0.0.1, 10.x...
            ips.append(str(ip))
    return sorted(set(ips))[:16]


def link_dns(session: Session, now: datetime | None = None, limit: int = DNS_BATCH,
             resolver=resolve) -> tuple[int, int]:
    """Step 2: domain -> IP. Returns (domains looked up, links created)."""
    now = now or datetime.now(timezone.utc)
    domains = dns_candidates(session, now, limit)
    if not domains:
        return 0, 0
    with ThreadPoolExecutor(max_workers=16) as pool:
        answers = list(pool.map(resolver, (d.value for d in domains)))

    created = 0
    for domain, ips in zip(domains, answers):
        domain.dns_checked_at = now
        for ip in ips:
            row = session.scalar(select(Resolution).where(
                Resolution.indicator_id == domain.id, Resolution.ip == ip))
            if row:
                row.last_seen = now
            else:
                session.add(Resolution(indicator_id=domain.id, ip=ip, first_seen=now, last_seen=now))
            target = find(session, IndicatorType.IPV4.value, ip)
            if target is not None and link(session, domain, target, "resolves-to", "dns", now):
                created += 1
    session.flush()
    return len(domains), created


def correlate(dns: bool = True) -> dict[str, int]:
    result = {}
    with session_scope() as session:
        result["hosted_on"] = link_url_hosts(session)
    if dns:
        with session_scope() as session:
            looked_up, linked = link_dns(session)
            result["dns_lookups"], result["resolves_to"] = looked_up, linked
    log.info("correlation: %s", ", ".join(f"{k}={v}" for k, v in result.items()))
    return result


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Link indicators that share infrastructure")
    parser.add_argument("--no-dns", action="store_true", help="skip DNS lookups")
    args = parser.parse_args(list(argv) if argv is not None else None)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    init_db()
    correlate(dns=not args.no_dns)
    return 0


if __name__ == "__main__":
    sys.exit(main())
