from datetime import datetime, timedelta, timezone

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import select

from sentinel import ransomware
from sentinel.db import session_scope
from sentinel.models import FeedRun, Indicator, RansomwareVictim

now = datetime.now(timezone.utc)
day = lambda n: (now - timedelta(days=n)).strftime("%Y-%m-%d %H:%M:%S")  # noqa: E731

V2 = [
    {"victim": "Dhaka Garments Ltd", "group": "LockBit5", "attackdate": day(3), "discovered": day(2),
     "country": "BD", "activity": "Manufacturing", "domain": "dhakagarments.example"},
    {"victim": "Colombo Logistics", "group": "akira", "attackdate": day(5), "country": "LK", "activity": "Transportation"},
    {"victim": "Ohio Dental", "group": "akira", "attackdate": day(1), "country": "US", "activity": "Healthcare"},
    {"victim": "Old Case", "group": "qilin", "attackdate": day(200), "country": "IN"},
    {"victim": "", "group": "nameless"},
    "garbage",
]
V1 = [{"post_title": "Chittagong Port Services", "group_name": "Qilin", "published": day(4),
       "discovered": day(4), "country": "bd", "activity": "Transportation/Logistics"}]


def test_both_api_shapes_are_understood():
    v2 = ransomware.parse_victims(V2)
    assert [v["victim"] for v in v2] == ["Dhaka Garments Ltd", "Colombo Logistics", "Ohio Dental", "Old Case"]
    assert v2[0]["group"] == "lockbit5" and v2[0]["country"] == "BD" and v2[0]["sector"] == "Manufacturing"
    v1 = ransomware.parse_victims({"victims": V1})
    assert v1[0]["victim"] == "Chittagong Port Services" and v1[0]["group"] == "qilin" and v1[0]["country"] == "BD"


def test_storing_is_idempotent_and_never_creates_indicators():
    with session_scope() as s:
        assert ransomware.store(s, ransomware.parse_victims(V2 + V1)) == (5, 4)  # BD, LK, IN, BD
    with session_scope() as s:
        assert ransomware.store(s, ransomware.parse_victims(V2)) == (0, 0)
        assert s.scalar(select(Indicator)) is None  # victims are never blocklisted
        assert len(s.scalars(select(RansomwareVictim).where(RansomwareVictim.south_asia.is_(True))).all()) == 4


def test_run_records_success_and_failure():
    ok = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=V2)))
    assert ransomware.run(ok) == 0
    down = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(502)))
    assert ransomware.run(down) == 1
    with session_scope() as s:
        assert [r.ok for r in s.scalars(select(FeedRun).order_by(FeedRun.id))] == [True, False]


def test_ransomware_api():
    with session_scope() as s:
        ransomware.store(s, ransomware.parse_victims(V2 + V1))
    from sentinel.api.main import app
    with TestClient(app) as client:
        data = client.get("/api/v1/ransomware", params={"days": 90}).json()
    assert data["total"] == 4 and data["south_asia"] == 3 and data["bangladesh"] == 2  # 200-day-old case excluded
    assert data["groups"][0] == {"value": "akira", "count": 2}
    assert data["countries"] == {"BD": 2, "LK": 1}
    assert data["recent"][0]["victim"] == "Dhaka Garments Ltd"
    assert "website" not in data["recent"][0]
