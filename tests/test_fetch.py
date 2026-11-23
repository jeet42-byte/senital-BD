"""Fetching: key placement, secrecy of the key, ZIP handling."""

import io
import zipfile

import httpx
import pytest

from sentinel import config
from sentinel.collectors import COLLECTORS
from sentinel.collectors.base import FeedError, decode_body
from sentinel.ingest import run_collector
from tests.conftest import fixture_text

KEY = "s3cret/key+with?odd#chars"
QUOTED = "s3cret%2Fkey%2Bwith%3Fodd%23chars"


@pytest.fixture
def with_key(monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", KEY)
    config.get_settings.cache_clear()
    yield
    config.get_settings.cache_clear()


def client_returning(status: int, body: bytes, seen: list):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, content=body)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_key_goes_in_the_path_quoted_and_not_in_a_header(with_key):
    seen: list[httpx.Request] = []
    with client_returning(200, fixture_text("urlhaus.csv").encode(), seen) as client:
        COLLECTORS["urlhaus"].fetch(client)
    request = seen[0]
    assert request.url.raw_path.decode() == f"/v2/files/exports/{QUOTED}/recent.csv"
    assert request.url.host == "urlhaus-api.abuse.ch"
    assert "auth-key" not in request.headers


def test_missing_key_fails_clearly_without_a_request():
    seen: list = []
    with client_returning(200, b"", seen) as client, pytest.raises(FeedError, match="ABUSECH_AUTH_KEY"):
        COLLECTORS["threatfox"].fetch(client)
    assert seen == []


@pytest.mark.parametrize("status,hint", [(401, True), (404, False), (410, False)])
def test_http_errors_never_reveal_the_key(with_key, status, hint):
    with client_returning(status, b"nope", []) as client, pytest.raises(FeedError) as info:
        COLLECTORS["threatfox"].fetch(client)
    message = str(info.value)
    assert KEY not in message and QUOTED not in message and "<AUTH-KEY>" in message
    assert f"HTTP {status}" in message
    assert ("check ABUSECH_AUTH_KEY" in message) is hint


def test_failed_run_stores_a_redacted_error(with_key):
    with client_returning(410, b"gone", []) as client:
        run = run_collector("urlhaus", client=client)
    assert not run.ok and "HTTP 410" in run.error and QUOTED not in run.error


def test_keyless_feeds_still_send_the_header_and_no_path_key(with_key):
    seen: list[httpx.Request] = []
    with client_returning(200, fixture_text("feodo.json").encode(), seen) as client:
        COLLECTORS["feodotracker"].fetch(client)
    assert seen[0].url.path == "/downloads/ipblocklist.json"
    assert seen[0].headers["auth-key"] == KEY


def test_zipped_exports_are_unpacked():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("recent.csv", fixture_text("urlhaus.csv"))
    assert decode_body(buffer.getvalue()) == fixture_text("urlhaus.csv")
    assert decode_body(b"plain text") == "plain text"


def test_urlhaus_header_row_is_skipped():
    text = "id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n" + fixture_text("urlhaus.csv")
    assert len(list(COLLECTORS["urlhaus"].parse(text))) == 6
