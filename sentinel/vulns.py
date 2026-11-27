"""Vulnerability intelligence: which weaknesses are being exploited, and
which ones Bangladesh's CIRT has warned about.

    python -m sentinel.vulns                # KEV, EPSS and CIRT advisories
    python -m sentinel.vulns --only kev     # one step

Sources
  CISA KEV       Known Exploited Vulnerabilities: CVEs with evidence of
                 exploitation in the wild, and whether ransomware uses them.
  FIRST EPSS     for every CVE, the probability it is exploited in the next
                 30 days (daily model).
  BGD e-GOV CIRT advisories from Bangladesh's national CIRT. The CVEs they
                 name are flagged, and the indicators they publish defanged
                 (hxxp://, [.]) or as file hashes become indicators.

Priority (0-100, every part shown in the API):
  50 if in KEV + 40 x EPSS + 10 if used by ransomware
  + 15 if named in a CIRT advisory + 10 if added to KEV in the last 30 days
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import logging
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from sentinel.collectors.base import RawIndicator
from sentinel.config import get_settings
from sentinel.db import init_db, session_scope
from sentinel.indicators import IndicatorType, refang
from sentinel.models import Advisory, FeedRun, Vulnerability
from sentinel.scoring import as_utc

log = logging.getLogger("sentinel.vulns")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_BULK_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
CIRT_BASE = "https://www.cirt.gov.bd"
CIRT_LISTINGS = ("/alerts", "/news", "/bulletins")
CIRT_MAX_ADVISORIES = 30

LIKELY_EPSS = 0.5          # non-KEV CVEs kept as "likely exploited next"
LIKELY_KEEP = 150
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _client() -> httpx.Client:
    settings = get_settings()
    return httpx.Client(timeout=90, follow_redirects=True, headers={"User-Agent": settings.USER_AGENT})


def _date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# ------------------------------------------------------------------ priority

def priority_parts(v: Vulnerability, now: datetime | None = None) -> dict[str, int]:
    now = now or datetime.now(timezone.utc)
    parts = {
        "exploited": 50 if v.in_kev else 0,
        "epss": int(round(40 * (v.epss or 0))),
        "ransomware": 10 if v.ransomware_use else 0,
        "bd_advisory": 15 if v.bd_advisories else 0,
        "recent": 10 if v.kev_added and now - as_utc(v.kev_added) <= timedelta(days=30) else 0,
    }
    return parts


def rescore(v: Vulnerability, now: datetime | None = None) -> None:
    v.priority = min(100, sum(priority_parts(v, now).values()))
    v.updated_at = now or datetime.now(timezone.utc)


def _get(session: Session, cve: str) -> Vulnerability:
    cve = cve.upper()
    v = session.get(Vulnerability, cve)
    if v is None:
        v = Vulnerability(cve_id=cve, in_kev=False, ransomware_use=False, bd_advisories=0, priority=0)
        session.add(v)
    return v


# ---------------------------------------------------------------------- KEV

def parse_kev(text: str) -> list[dict]:
    return json.loads(text).get("vulnerabilities", [])


def apply_kev(session: Session, entries: list[dict]) -> int:
    for e in entries:
        cve = e.get("cveID")
        if not cve or not CVE_RE.fullmatch(cve):
            continue
        v = _get(session, cve)
        v.in_kev = True
        v.vendor = (e.get("vendorProject") or "")[:128] or None
        v.product = (e.get("product") or "")[:256] or None
        v.name = e.get("vulnerabilityName")
        v.description = e.get("shortDescription")
        v.kev_added = _date(e.get("dateAdded"))
        v.kev_due = _date(e.get("dueDate"))
        v.ransomware_use = str(e.get("knownRansomwareCampaignUse", "")).lower() == "known"
    session.flush()
    return len(entries)


# --------------------------------------------------------------------- EPSS

def parse_epss_csv(raw: bytes) -> dict[str, tuple[float, float]]:
    """cve -> (epss, percentile) from the daily bulk file (gzipped or not)."""
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    lines = (line for line in io.StringIO(raw.decode("utf-8", "replace")) if not line.startswith("#"))
    scores = {}
    for row in csv.DictReader(lines):
        try:
            scores[row["cve"].upper()] = (float(row["epss"]), float(row["percentile"]))
        except (KeyError, ValueError):
            continue
    return scores


def fetch_epss_api(client: httpx.Client, cves: list[str]) -> dict[str, tuple[float, float]]:
    """Fallback when the bulk file is unavailable: 100 CVEs per request."""
    scores = {}
    for i in range(0, len(cves), 100):
        response = client.get(EPSS_API_URL, params={"cve": ",".join(cves[i:i + 100])})
        response.raise_for_status()
        for row in response.json().get("data", []):
            scores[row["cve"].upper()] = (float(row["epss"]), float(row["percentile"]))
        time.sleep(1)
    return scores


def apply_epss(session: Session, scores: dict[str, tuple[float, float]], bulk: bool) -> int:
    tracked = {v.cve_id: v for v in session.scalars(select(Vulnerability))}
    for cve, v in tracked.items():
        if cve in scores:
            v.epss, v.epss_percentile = scores[cve]
    added = 0
    if bulk:
        # The likeliest next targets that are not yet known to be exploited.
        likely = sorted(((s[0], cve) for cve, s in scores.items() if s[0] >= LIKELY_EPSS and cve not in tracked),
                        reverse=True)[:LIKELY_KEEP]
        for _, cve in likely:
            v = _get(session, cve)
            v.epss, v.epss_percentile = scores[cve]
            added += 1
    session.flush()
    return added


# --------------------------------------------------------------------- CIRT

class _Page(HTMLParser):
    """Text, links and title of an HTML page (stdlib only)."""

    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.chunks: list[str] = []
        self.title = ""
        self._in = None

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href)
        if tag in ("script", "style", "title", "h1"):
            self._in = tag

    def handle_endtag(self, tag):
        if tag == self._in:
            self._in = None

    def handle_data(self, data):
        if self._in in ("script", "style"):
            return
        if self._in in ("title", "h1") and data.strip() and (self._in == "h1" or not self.title):
            self.title = data.strip()
        self.chunks.append(data)

    @property
    def text(self) -> str:
        return re.sub(r"\s+", " ", " ".join(self.chunks)).strip()


def parse_html(html: str) -> _Page:
    page = _Page()
    page.feed(html)
    return page


_DETAIL_RE = re.compile(r"^/(alerts|news|bulletins)/[^/\s?#]{8,}$")
_PUBLISHED_RE = re.compile(r"Published\s+on\s+(\d{1,2})-([A-Za-z]{3})-(\d{4})", re.IGNORECASE)
_MONTHS = {m: i for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}

# Only values an advisory itself marks as malicious: defanged ones, and hashes.
_DEFANGED_URL = re.compile(r"\b(?:hxxps?|fxp)\[?:\]?//\S+", re.IGNORECASE)
_DEFANGED_HOST = re.compile(r"\b[a-z0-9-]+(?:\[\.\][a-z0-9-]+)+\b|\b\d{1,3}(?:\[\.\]\d{1,3}){3}\b", re.IGNORECASE)
_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)


def advisory_links(listing_html: str) -> list[str]:
    seen, out = set(), []
    for href in parse_html(listing_html).links:
        path = href.split("?")[0].split("#")[0].rstrip("/")
        if path.startswith(CIRT_BASE):
            path = path[len(CIRT_BASE):]
        if _DETAIL_RE.match(path) and path not in seen:
            seen.add(path)
            out.append(urljoin(CIRT_BASE, path))
    return out


def parse_advisory(url: str, html: str) -> dict:
    page = parse_html(html)
    text = page.text
    published = None
    if m := _PUBLISHED_RE.search(text):
        day, month, year = m.groups()
        if month.lower() in _MONTHS:
            published = datetime(int(year), _MONTHS[month.lower()], int(day), tzinfo=timezone.utc)
    iocs: list[tuple[IndicatorType, str]] = []
    for match in _DEFANGED_URL.findall(text):
        iocs.append((IndicatorType.URL, refang(match.rstrip(").,;'\""))))
    for match in _DEFANGED_HOST.findall(text):
        value = refang(match)
        kind = IndicatorType.IPV4 if re.fullmatch(r"[\d.]+", value) else IndicatorType.DOMAIN
        iocs.append((kind, value))
    iocs += [(IndicatorType.SHA256, h) for h in _SHA256.findall(text)]
    iocs += [(IndicatorType.MD5, h) for h in _MD5.findall(text) if not _SHA256.search(h)]
    return {
        "url": url,
        "title": (page.title or url.rsplit("/", 1)[-1].replace("-", " "))[:500],
        "published": published,
        "cves": sorted({c.upper() for c in CVE_RE.findall(text)}),
        "iocs": list(dict.fromkeys(iocs)),
    }


def apply_advisories(session: Session, advisories: list[dict]) -> tuple[int, list[RawIndicator]]:
    raws: list[RawIndicator] = []
    new = 0
    for adv in advisories:
        row = session.scalar(select(Advisory).where(Advisory.url == adv["url"]))
        if row is None:
            row = Advisory(url=adv["url"], title=adv["title"], source="bgd-cirt")
            session.add(row)
            new += 1
        row.title, row.published, row.cves = adv["title"], adv["published"], adv["cves"]
        row.indicator_count = len(adv["iocs"])
        for kind, value in adv["iocs"]:
            raws.append(RawIndicator(
                type=kind, value=value, source="bgd-cirt", first_seen=adv["published"],
                threat_type="cirt_advisory", tags=["bgd-cirt", "advisory"], reference=adv["url"],
                extra_reasons=["cirt:BGD e-GOV CIRT"], note=adv["title"][:200],
            ))
    session.flush()
    counts: dict[str, int] = {}
    for adv in session.scalars(select(Advisory)):
        for cve in adv.cves or []:
            counts[cve] = counts.get(cve, 0) + 1
    for cve, n in counts.items():
        _get(session, cve).bd_advisories = n
    session.flush()
    return new, raws


def fetch_advisories(client: httpx.Client) -> list[dict]:
    urls: list[str] = []
    for path in CIRT_LISTINGS:
        try:
            response = client.get(urljoin(CIRT_BASE, path))
            response.raise_for_status()
            urls += [u for u in advisory_links(response.text) if u not in urls]
        except httpx.HTTPError as exc:
            log.warning("CIRT listing %s failed: %s", path, type(exc).__name__)
    advisories = []
    for url in urls[:CIRT_MAX_ADVISORIES]:
        try:
            response = client.get(url)
            response.raise_for_status()
            advisories.append(parse_advisory(url, response.text))
        except httpx.HTTPError as exc:
            log.warning("CIRT advisory failed: %s (%s)", url, type(exc).__name__)
        time.sleep(1)
    if not advisories and urls:
        raise RuntimeError("no CIRT advisory could be fetched")
    return advisories


# ---------------------------------------------------------------------- run

def _record(source: str, ok: bool, fetched: int = 0, created: int = 0, error: str | None = None) -> None:
    with session_scope() as session:
        now = datetime.now(timezone.utc)
        session.add(FeedRun(source=source, started_at=now, finished_at=now, ok=ok,
                            fetched=fetched, created=created, error=error))


def run(steps: set[str]) -> int:
    from sentinel.ingest import ingest_raw

    ok_steps = 0
    with _client() as client:
        if "kev" in steps:
            try:
                entries = parse_kev(client.get(KEV_URL).raise_for_status().text)
                with session_scope() as session:
                    apply_kev(session, entries)
                _record("cisa-kev", True, fetched=len(entries))
                ok_steps += 1
                log.info("KEV: %d exploited vulnerabilities", len(entries))
            except Exception as exc:  # noqa: BLE001 - one source failing must not stop the rest
                log.error("KEV failed: %s", exc)
                _record("cisa-kev", False, error=f"{type(exc).__name__}: {str(exc)[:300]}")

        if "cirt" in steps:
            try:
                advisories = fetch_advisories(client)
                with session_scope() as session:
                    new, raws = apply_advisories(session, advisories)
                    stats = ingest_raw(session, "bgd-cirt", raws)
                _record("bgd-cirt", True, fetched=len(advisories), created=stats.created)
                ok_steps += 1
                log.info("CIRT: %d advisories (%d new), %d indicators", len(advisories), new, len(raws))
            except Exception as exc:  # noqa: BLE001
                log.error("CIRT failed: %s", exc)
                _record("bgd-cirt", False, error=f"{type(exc).__name__}: {str(exc)[:300]}")

        if "epss" in steps:
            try:
                try:
                    scores, bulk = parse_epss_csv(client.get(EPSS_BULK_URL).raise_for_status().content), True
                except httpx.HTTPError:
                    with session_scope() as session:
                        cves = list(session.scalars(select(Vulnerability.cve_id)))
                    scores, bulk = fetch_epss_api(client, cves), False
                with session_scope() as session:
                    added = apply_epss(session, scores, bulk)
                _record("epss", True, fetched=len(scores), created=added)
                ok_steps += 1
                log.info("EPSS: %d scores, %d likely-next CVEs added", len(scores), added)
            except Exception as exc:  # noqa: BLE001
                log.error("EPSS failed: %s", exc)
                _record("epss", False, error=f"{type(exc).__name__}: {str(exc)[:300]}")

    with session_scope() as session:
        for v in session.scalars(select(Vulnerability)):
            rescore(v)
    return 0 if ok_steps else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Vulnerability intelligence for Sentinel-BD")
    parser.add_argument("--only", choices=["kev", "epss", "cirt"], action="append")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    init_db()
    return run(set(args.only or ["kev", "epss", "cirt"]))


if __name__ == "__main__":
    sys.exit(main())
