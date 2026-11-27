"""Indicator types, refanging, normalisation and validation.

Every value is normalised before it is stored, so the same indicator from
two feeds ("HXXP://Evil[.]com/x" and "http://evil.com/x") becomes one row.
Values that cannot be valid indicators - private IPs, malformed domains -
are rejected here rather than ending up in a firewall blocklist.
"""

from __future__ import annotations

import ipaddress
import re
from enum import Enum
from urllib.parse import urlsplit, urlunsplit


class IndicatorType(str, Enum):
    IPV4 = "ipv4"
    CIDR = "cidr"      # an IPv4 network range, e.g. a hijacked block on Spamhaus DROP
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


HASH_LENGTHS = {IndicatorType.MD5: 32, IndicatorType.SHA1: 40, IndicatorType.SHA256: 64}
HASH_TYPES = frozenset(HASH_LENGTHS)

_HEX = re.compile(r"^[0-9a-f]+$")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")

_REFANG = [
    (re.compile(r"^hxxp", re.I), "http"),
    (re.compile(r"^fxp", re.I), "ftp"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[/\]"), "/"),
]


def refang(value: str) -> str:
    """Undo common defanging: hxxp://evil[.]com -> http://evil.com"""
    value = value.strip()
    for pattern, replacement in _REFANG:
        value = pattern.sub(replacement, value)
    return value


def normalize_ipv4(value: str) -> str | None:
    value = refang(value)
    # ThreatFox reports "ip:port"; the port is not part of the indicator.
    if value.count(":") == 1:
        value = value.split(":", 1)[0]
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return None
    # Private, loopback, reserved and multicast addresses are never threat
    # indicators on the internet, and blocking them breaks local networks.
    if not ip.is_global:
        return None
    return str(ip)


# Ranges broader than this are never accepted: one bad /6 would block a
# continent.
MIN_PREFIX = 8


def normalize_cidr(value: str) -> str | None:
    value = refang(value).strip()
    try:
        net = ipaddress.IPv4Network(value, strict=False)
    except ValueError:
        return None
    if net.prefixlen < MIN_PREFIX:
        return None
    if not (net.network_address.is_global and net.broadcast_address.is_global):
        return None
    return str(net)


def normalize_domain(value: str) -> str | None:
    value = refang(value).lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(value) > 253 or "." not in value:
        return None
    labels = value.split(".")
    if not all(_LABEL.match(label) for label in labels):
        return None
    # The TLD must not be numeric; that rules out bare IPs posing as domains.
    if labels[-1].isdigit():
        return None
    return value


# Longer URLs are almost always junk, and PostgreSQL cannot index values
# much beyond 2.7 kB, which the unique (type, value) constraint needs.
MAX_URL_LENGTH = 2048


def normalize_url(value: str) -> str | None:
    value = refang(value)
    if len(value) > MAX_URL_LENGTH:
        return None
    if "://" not in value:
        value = "http://" + value
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https", "ftp"}:
        return None
    host = (parts.hostname or "").lower()
    if not host or not (normalize_domain(host) or normalize_ipv4(host)):
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    netloc = host if port is None else f"{host}:{port}"
    # The fragment never reaches the server, so it is not part of the URL
    # the firewall sees.
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def normalize_hash(kind: IndicatorType, value: str) -> str | None:
    value = value.strip().lower()
    if len(value) == HASH_LENGTHS[kind] and _HEX.match(value):
        return value
    return None


def normalize(kind: IndicatorType | str, value: str) -> str | None:
    """The canonical form of a value, or None when it is not a valid indicator."""
    kind = IndicatorType(kind)
    if not value or not value.strip():
        return None
    if kind is IndicatorType.IPV4:
        return normalize_ipv4(value)
    if kind is IndicatorType.CIDR:
        return normalize_cidr(value)
    if kind is IndicatorType.DOMAIN:
        return normalize_domain(value)
    if kind is IndicatorType.URL:
        return normalize_url(value)
    return normalize_hash(kind, value)


def guess_type(value: str) -> IndicatorType | None:
    """Best guess at what a user-supplied value is, for the lookup endpoint."""
    value = refang(value)
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}/\d{1,2}", value.strip()):
        return IndicatorType.CIDR
    if "://" in value or "/" in value:
        return IndicatorType.URL
    if normalize_ipv4(value) or _looks_like_ip(value):
        return IndicatorType.IPV4
    lowered = value.lower()
    if _HEX.match(lowered):
        for kind, length in HASH_LENGTHS.items():
            if len(lowered) == length:
                return kind
        return None
    if normalize_domain(value):
        return IndicatorType.DOMAIN
    return None


def _looks_like_ip(value: str) -> bool:
    host = value.split(":", 1)[0]
    try:
        ipaddress.IPv4Address(host)
        return True
    except ValueError:
        return False


def url_host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()
