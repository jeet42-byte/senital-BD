import os
import shutil

from fastapi.testclient import TestClient
from sqlalchemy import select

from sentinel.db import session_scope
from sentinel.honeypot.cowrie import DailyStats, indicators_from_sessions, sessions_from_lines
from sentinel.honeypot.ship import read_new_lines, ship
from sentinel.models import FeedRun, HoneypotDaily, Indicator
from tests.conftest import FIXTURES, fixture_text

LINES = fixture_text("cowrie.json").splitlines()


def test_sessions_are_grouped_and_bad_lines_skipped():
    sessions = {s.session: s for s in sessions_from_lines(LINES)}
    assert set(sessions) == {"a1", "b2", "c3", "d4"}
    a1, b2 = sessions["a1"], sessions["b2"]
    assert a1.usernames == ["root", "admin"] and not a1.logged_in and a1.client == "SSH-2.0-Go"
    assert b2.logged_in and len(b2.commands) == 2 and b2.downloads[0][0].endswith("mozi.m")
    assert sessions["c3"].protocol == "telnet" and not sessions["c3"].tried_login


def test_indicators_scale_with_behaviour():
    raws = {(r.type.value, r.value): r for r in indicators_from_sessions(sessions_from_lines(LINES))}
    assert raws[("ipv4", "45.95.11.20")].confidence == 60        # brute force only
    assert raws[("ipv4", "103.4.145.10")].confidence == 95       # logged in and downloaded
    assert raws[("url", "http://185.220.101.45/bins/mozi.m")].confidence == 90
    assert ("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") in raws
    # A connection that never tried to log in is scanning noise, not reported.
    assert not any(value == "192.0.2.55" for _, value in raws)
    assert "1 download" in raws[("ipv4", "103.4.145.10")].note


def test_daily_stats():
    rows = DailyStats().add(sessions_from_lines(LINES)).rows()
    by = {(kind, value): count for _, kind, value, count in rows}
    assert by[("session", "all")] == 4
    assert by[("password", "123456")] == 1 and by[("username", "root")] == 2
    assert by[("protocol", "telnet")] == 2
    assert ("attacker", "192.0.2.55") not in by


def test_reader_handles_partial_lines_and_rotation(tmp_path):
    log_dir, state = tmp_path / "log", tmp_path / "state.json"
    log_dir.mkdir()
    current = log_dir / "cowrie.json"
    current.write_text(LINES[0] + "\n" + LINES[1][:20])  # second line half-written
    lines, new_state = read_new_lines(log_dir, state)
    assert lines == [LINES[0]]
    state.write_text(__import__("json").dumps(new_state))

    with current.open("a") as handle:
        handle.write(LINES[1][20:] + "\n")
    lines, new_state = read_new_lines(log_dir, state)
    assert lines == [LINES[1]]
    state.write_text(__import__("json").dumps(new_state))

    # Daily rotation: the old file is renamed, a new one starts.
    os.rename(current, log_dir / "cowrie.json.2026-11-23")
    current.write_text(LINES[2] + "\n")
    lines, _ = read_new_lines(log_dir, state)
    assert lines == [LINES[2]]  # nothing re-read from the rotated file


def test_ship_writes_indicators_stats_and_run(tmp_path):
    log_dir = tmp_path / "log"
    log_dir.mkdir()
    shutil.copy(FIXTURES / "cowrie.json", log_dir / "cowrie.json")
    state = tmp_path / "state.json"

    run = ship(log_dir, state)
    assert run.ok and run.created == 5  # 3 attacker IPs, 1 download URL, 1 file hash
    with session_scope() as db:
        ip = db.scalar(select(Indicator).where(Indicator.value == "103.4.145.10"))
        assert ip.sightings[0].source == "honeypot" and ip.bd_relevant
        assert "interactive" in ip.tags and ip.severity == "high"
        assert db.scalar(select(HoneypotDaily).where(HoneypotDaily.kind == "password",
                                                     HoneypotDaily.value == "123456")).count == 1

    again = ship(log_dir, state)  # nothing new: no double counting
    assert again.created == 0 and again.updated == 0
    with session_scope() as db:
        assert db.scalar(select(HoneypotDaily).where(HoneypotDaily.kind == "session")).count == 4
        assert len(db.scalars(select(FeedRun).where(FeedRun.source == "honeypot")).all()) == 2


def test_honeypot_api(tmp_path):
    from sentinel.api.main import app

    log_dir = tmp_path / "log"
    log_dir.mkdir()
    shutil.copy(FIXTURES / "cowrie.json", log_dir / "cowrie.json")
    ship(log_dir, tmp_path / "state.json")
    with TestClient(app) as client:
        data = client.get("/api/v1/honeypot", params={"days": 90}).json()
    assert data["sessions"] == 4 and data["attackers"] == 3 and data["login_attempts"] == 4
    assert data["usernames"][0] == {"value": "root", "count": 2}
    assert data["protocols"] == {"ssh": 2, "telnet": 2}
    assert data["last_report"] is not None and len(data["timeline"]) == 90
    # Attacker-chosen text is stored as data; the dashboard renders it as text.
    assert any(u["value"] == "<script>alert(1)</script>" for u in data["usernames"])
