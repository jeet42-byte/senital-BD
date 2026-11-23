from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """Each test gets an empty database and the fixture BD ranges.

    SQLite by default; set TEST_DATABASE_URL to run the suite on PostgreSQL.
    """
    url = os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{tmp_path / 'test.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("BD_RANGES_PATH", str(FIXTURES / "bd_ipv4.txt"))

    from sentinel import bd, config, db

    config.get_settings.cache_clear()
    bd.bd_ranges.cache_clear()
    engine = db.init_db()
    db.Base.metadata.drop_all(engine)
    db.Base.metadata.create_all(engine)
    yield
    config.get_settings.cache_clear()
    bd.bd_ranges.cache_clear()


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")
