"""A read-only TAXII 2.1 server, so security tools can subscribe to Sentinel-BD.

TAXII is the standard protocol for sharing STIX threat intelligence; MISP,
OpenCTI, Splunk, Elastic and Microsoft Sentinel can all poll a TAXII feed.

  GET /taxii2/                                     discovery
  GET /taxii2/api1/                                API root
  GET /taxii2/api1/collections/                    collections
  GET /taxii2/api1/collections/{id}/               one collection
  GET /taxii2/api1/collections/{id}/objects/       STIX objects, paged
        ?added_after=2026-11-01T00:00:00Z&limit=500&next=<token>

Two collections: every indicator scoring 50 or more, and only those aimed at
Bangladesh. "Added" is when an indicator was last seen, so a poller asking
for objects added after its last poll gets everything new or refreshed.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session, selectinload

from sentinel.db import get_session
from sentinel.exporters import IDENTITY_ID, STIX_NAMESPACE, relations_among, to_stix_bundle
from sentinel.models import Indicator
from sentinel.scoring import as_utc

TAXII_MEDIA = "application/taxii+json;version=2.1"
STIX_MEDIA = "application/stix+json;version=2.1"
MIN_SCORE = 50
MAX_PAGE = 5000

COLLECTIONS = {
    str(uuid.uuid5(STIX_NAMESPACE, "collection:all")): {
        "title": "Sentinel-BD: all indicators",
        "description": "Every indicator scoring 50 or more: IPs, domains, URLs and file hashes.",
        "bd_only": False,
    },
    str(uuid.uuid5(STIX_NAMESPACE, "collection:bangladesh")): {
        "title": "Sentinel-BD: aimed at Bangladesh",
        "description": "Only indicators concerning Bangladesh: .bd domains, imitations of Bangladeshi "
                       "brands, and Bangladeshi IP space.",
        "bd_only": True,
    },
}

router = APIRouter(prefix="/taxii2", tags=["TAXII 2.1"])
SessionDep = Annotated[Session, Depends(get_session)]


def taxii(body: dict, status: int = 200, headers: dict | None = None, media: str = TAXII_MEDIA) -> JSONResponse:
    return JSONResponse(body, status_code=status, media_type=media, headers=headers)


def _root_url(request: Request) -> str:
    return str(request.url_for("api_root"))


def _collection_info(cid: str) -> dict:
    meta = COLLECTIONS[cid]
    return {
        "id": cid, "title": meta["title"], "description": meta["description"],
        "can_read": True, "can_write": False, "media_types": [STIX_MEDIA],
    }


def _collection(cid: str) -> dict:
    if cid not in COLLECTIONS:
        raise HTTPException(status_code=404, detail="Collection not found")
    return COLLECTIONS[cid]


def _ts(value: datetime) -> str:
    return as_utc(value).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_ts(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail="added_after must be an RFC 3339 timestamp") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@router.get("/", name="discovery")
def discovery(request: Request) -> JSONResponse:
    root = _root_url(request)
    return taxii({
        "title": "Sentinel-BD TAXII server",
        "description": "Bangladesh-focused open threat intelligence (read-only).",
        "default": root,
        "api_roots": [root],
    })


@router.get("/api1/", name="api_root")
def api_root() -> JSONResponse:
    return taxii({
        "title": "Sentinel-BD",
        "description": "Indicators scored by source agreement and freshness, tagged for Bangladesh.",
        "versions": [TAXII_MEDIA],
        "max_content_length": 50 * 1024 * 1024,
    })


@router.get("/api1/collections/")
def collections() -> JSONResponse:
    return taxii({"collections": [_collection_info(cid) for cid in COLLECTIONS]})


@router.get("/api1/collections/{cid}/")
def collection(cid: str) -> JSONResponse:
    _collection(cid)
    return taxii(_collection_info(cid))


@router.get("/api1/collections/{cid}/objects/")
def objects(
    session: SessionDep,
    cid: str,
    added_after: str | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 1000,
    next: Annotated[str | None, Query(alias="next", max_length=64)] = None,
) -> JSONResponse:
    meta = _collection(cid)
    query = (
        select(Indicator)
        .options(selectinload(Indicator.sightings))
        .where(Indicator.score >= MIN_SCORE)
        .order_by(Indicator.last_seen, Indicator.id)
    )
    if meta["bd_only"]:
        query = query.where(Indicator.bd_relevant.is_(True))
    if added_after:
        query = query.where(Indicator.last_seen > _parse_ts(added_after))
    if next:
        # The token is "<last_seen>|<id>" of the last object already sent.
        try:
            stamp, last_id = next.rsplit("|", 1)
            after, after_id = _parse_ts(stamp), int(last_id)
        except (ValueError, HTTPException):
            raise HTTPException(status_code=400, detail="Invalid next token") from None
        query = query.where(or_(Indicator.last_seen > after,
                                and_(Indicator.last_seen == after, Indicator.id > after_id)))

    rows = list(session.scalars(query.limit(limit + 1)))
    more = len(rows) > limit
    rows = rows[:limit]

    import json

    bundle = json.loads(to_stix_bundle(rows, relations=relations_among(session, rows)))
    body: dict = {"more": more, "objects": bundle["objects"]}
    headers = {}
    if rows:
        body["objects"] = [o for o in bundle["objects"] if o["id"] != IDENTITY_ID or not next]
        headers["X-TAXII-Date-Added-First"] = _ts(rows[0].last_seen)
        headers["X-TAXII-Date-Added-Last"] = _ts(rows[-1].last_seen)
        if more:
            body["next"] = f"{_ts(rows[-1].last_seen)}|{rows[-1].id}"
    else:
        body["objects"] = []
    return taxii(body, headers=headers)
