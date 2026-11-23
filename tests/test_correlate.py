import json
import shutil
import socket
import threading
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from sentinel.correlate import link_dns, link_url_hosts, resolve
from sentinel.db import session_scope
from sentinel.models import Indicator, Relation, Resolution
from tests.conftest import FIXTURES
from tests.test_ingest import load_all


def relations():
    with session_scope() as s:
        return {(r.src.value, r.kind, r.dst.value) for r in s.scalars(select(Relation))}


def test_urls_link_to_known_hosts_once():
    load_all()
    with session_scope() as s:
        assert link_url_hosts(s) >= 2
    found = relations()
    assert ("http://103.4.145.10:41234/Mozi.m", "hosted-on", "103.4.145.10") in found
    assert ("https://nagad-verify-account.com/login", "hosted-on", "nagad-verify-account.com") in found
    with session_scope() as s:
        assert link_url_hosts(s) == 0  # idempotent


def test_dns_links_only_known_ips_and_keeps_every_answer():
    load_all()
    answers = {"nagad-verify-account.com": ["185.220.101.45", "93.184.216.34"]}
    with session_scope() as s:
        looked_up, linked = link_dns(s, resolver=lambda d: answers.get(d, []))
    assert looked_up >= 1 and linked == 1
    assert ("nagad-verify-account.com", "resolves-to", "185.220.101.45") in relations()
    with session_scope() as s:
        ips = set(s.scalars(select(Resolution.ip)))
        assert ips == {"185.220.101.45", "93.184.216.34"}
        # The unknown hosting IP is recorded but never becomes an indicator.
        assert s.scalar(select(Indicator).where(Indicator.value == "93.184.216.34")) is None
        assert link_dns(s, resolver=lambda d: [])[0] == 0  # checked recently: skipped


def test_resolver_drops_private_and_bogus_answers(monkeypatch):
    import dns.resolver

    class Record:
        def __init__(self, text):
            self.text = text

        def to_text(self):
            return self.text

    monkeypatch.setattr(dns.resolver.Resolver, "resolve",
                        lambda self, name, rtype: [Record("10.0.0.5"), Record("127.0.0.1"), Record("8.8.8.8"), Record("junk")])
    assert resolve("example.test") == ["8.8.8.8"]


def test_honeypot_downloads_are_linked(tmp_path):
    from sentinel.honeypot.ship import ship

    log_dir = tmp_path / "log"
    log_dir.mkdir()
    shutil.copy(FIXTURES / "cowrie.json", log_dir / "cowrie.json")
    ship(log_dir, tmp_path / "state.json")
    found = relations()
    url = "http://185.220.101.45/bins/mozi.m"
    assert ("103.4.145.10", "downloaded", url) in found
    assert (url, "delivers", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") in found


def test_deleting_an_indicator_removes_its_links():
    load_all()
    with session_scope() as s:
        link_url_hosts(s)
    with session_scope() as s:
        s.delete(s.scalar(select(Indicator).where(Indicator.value == "103.4.145.10")))
    assert not any(dst == "103.4.145.10" for _, _, dst in relations())


@pytest.fixture
def client():
    load_all()
    with session_scope() as s:
        link_url_hosts(s)
        link_dns(s, resolver=lambda d: ["185.220.101.45"] if d == "nagad-verify-account.com" else [])
    from sentinel.api.main import app
    with TestClient(app) as c:
        yield c


def test_graph_api(client):
    g = client.get("/api/v1/graph", params={"type": "domain", "value": "nagad-verify-account.com"}).json()
    values = {n["value"] for n in g["nodes"]}
    assert {"nagad-verify-account.com", "https://nagad-verify-account.com/login", "185.220.101.45"} <= values
    assert g["resolutions"] == ["185.220.101.45"]
    assert {e["kind"] for e in g["edges"]} == {"hosted-on", "resolves-to"}
    assert client.get("/api/v1/graph", params={"type": "domain", "value": "nothing.example"}).status_code == 404


def test_correlations_prefer_cross_source_links(client):
    items = client.get("/api/v1/correlations").json()
    assert items and all(i["cross_source"] or i["own_sensor"] for i in items)
    pairs = {(i["src"]["value"], i["dst"]["value"]) for i in items}
    assert ("http://103.4.145.10:41234/Mozi.m", "103.4.145.10") in pairs  # URLhaus -> Feodo
    assert client.get("/api/v1/stats").json()["relations"]["hosted-on"] >= 2


def test_stix_export_carries_relationships(client):
    bundle = json.loads(client.get("/feeds/stix.json", params={"min_score": 0}).text)
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    ids = {o["id"] for o in bundle["objects"]}
    assert rels and all(r["source_ref"] in ids and r["target_ref"] in ids for r in rels)


def test_taxii_paging_and_filters(client):
    disc = client.get("/taxii2/").json()
    assert disc["api_roots"][0].endswith("/taxii2/api1/")
    cols = client.get("/taxii2/api1/collections/").json()["collections"]
    all_id = next(c["id"] for c in cols if not c["title"].endswith("Bangladesh"))
    bd_id = next(c["id"] for c in cols if c["title"].endswith("Bangladesh"))

    first = client.get(f"/taxii2/api1/collections/{all_id}/objects/", params={"limit": 2})
    assert first.headers["content-type"].startswith("application/taxii+json")
    page = first.json()
    assert page["more"] and page["next"]
    rest = client.get(f"/taxii2/api1/collections/{all_id}/objects/", params={"limit": 500, "next": page["next"]}).json()
    got = [o["id"] for o in page["objects"] + rest["objects"] if o["type"] == "indicator"]
    assert len(got) == len(set(got))  # no indicator twice across pages

    bd = client.get(f"/taxii2/api1/collections/{bd_id}/objects/").json()
    assert all(any(l.startswith(("tld:", "impersonates:", "ip:", "geo:")) for l in o["labels"])
               for o in bd["objects"] if o["type"] == "indicator")
    later = client.get(f"/taxii2/api1/collections/{all_id}/objects/", params={"added_after": "2099-01-01T00:00:00Z"}).json()
    assert later == {"more": False, "objects": []}
    assert client.get(f"/taxii2/api1/collections/{all_id}/objects/", params={"next": "garbage"}).status_code == 400
    assert client.get("/taxii2/api1/collections/not-a-collection/").status_code == 404


def test_real_taxii_client_can_read_the_feed():
    """MISP and OpenCTI talk to TAXII servers through libraries like this one."""
    import uvicorn
    from taxii2client.v21 import Server, as_pages

    from sentinel.api.main import app

    load_all()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        for _ in range(50):
            if server.started:
                break
            time.sleep(0.1)
        api_root = Server(f"http://127.0.0.1:{port}/taxii2/").api_roots[0]
        collection = next(c for c in api_root.collections if c.title.endswith("all indicators"))
        indicators = [o for page in as_pages(collection.get_objects, per_request=3)
                      for o in page.get("objects", []) if o["type"] == "indicator"]
        assert len(indicators) >= 5
    finally:
        server.should_exit = True
        thread.join(5)
