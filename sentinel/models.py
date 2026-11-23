"""Tables.

indicator  one row per unique (type, value), with its current score
sighting   one row per (indicator, source): which feeds report it, and when
feed_run   one row per collector run, for monitoring the pipeline
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentinel.db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Indicator(Base):
    __tablename__ = "indicator"
    __table_args__ = (UniqueConstraint("type", "value", name="uq_indicator_type_value"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str] = mapped_column(String(16), index=True)
    value: Mapped[str] = mapped_column(Text)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    severity: Mapped[str] = mapped_column(String(8), default="low")

    bd_relevant: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    bd_reasons: Mapped[list] = mapped_column(JSON, default=list)

    threat_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    malware: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    # When the correlation job last looked this domain up in DNS.
    dns_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    sightings: Mapped[list[Sighting]] = relationship(
        back_populates="indicator", cascade="all, delete-orphan", lazy="selectin"
    )


class Sighting(Base):
    __tablename__ = "sighting"
    __table_args__ = (UniqueConstraint("indicator_id", "source", name="uq_sighting_source"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator_id: Mapped[int] = mapped_column(
        ForeignKey("indicator.id", ondelete="CASCADE"), index=True
    )
    source: Mapped[str] = mapped_column(String(32), index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Confidence the source itself gives (0-100), when it gives one.
    confidence: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reference: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Why this source flagged it, when it says (e.g. the phishing hunter).
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    indicator: Mapped[Indicator] = relationship(back_populates="sightings")


class Relation(Base):
    """A link between two known indicators.

    kinds:  hosted-on    url -> domain | ipv4   (the URL's host)
            resolves-to  domain -> ipv4         (DNS answer that is itself an indicator)
            downloaded   ipv4 -> url            (honeypot: the attacker fetched it)
            delivers     url -> sha256          (honeypot: the file that came back)
    """

    __tablename__ = "relation"
    __table_args__ = (UniqueConstraint("src_id", "dst_id", "kind", name="uq_relation"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    src_id: Mapped[int] = mapped_column(ForeignKey("indicator.id", ondelete="CASCADE"), index=True)
    dst_id: Mapped[int] = mapped_column(ForeignKey("indicator.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(24))
    origin: Mapped[str] = mapped_column(String(32))  # which job established it
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    src: Mapped[Indicator] = relationship(foreign_keys=[src_id], lazy="joined")
    dst: Mapped[Indicator] = relationship(foreign_keys=[dst_id], lazy="joined")


class Resolution(Base):
    """What a domain resolved to. Kept apart from indicators on purpose: a
    phishing domain on shared hosting must not get the host's IP blocked."""

    __tablename__ = "dns_resolution"
    __table_args__ = (UniqueConstraint("indicator_id", "ip", name="uq_resolution"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator_id: Mapped[int] = mapped_column(ForeignKey("indicator.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(45), index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class HoneypotDaily(Base):
    """Per-day honeypot counts: sessions, attackers, usernames, passwords,
    commands and protocols. Aggregates only; raw sessions are not stored."""

    __tablename__ = "honeypot_daily"
    __table_args__ = (UniqueConstraint("day", "kind", "value", name="uq_honeypot_daily"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    day: Mapped[str] = mapped_column(String(10), index=True)  # YYYY-MM-DD (UTC)
    kind: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(200))
    count: Mapped[int] = mapped_column(Integer, default=0)


class FeedRun(Base):
    __tablename__ = "feed_run"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(32), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fetched: Mapped[int] = mapped_column(Integer, default=0)
    rejected: Mapped[int] = mapped_column(Integer, default=0)
    created: Mapped[int] = mapped_column(Integer, default=0)
    updated: Mapped[int] = mapped_column(Integer, default=0)
    ok: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
