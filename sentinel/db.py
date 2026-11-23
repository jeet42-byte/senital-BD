"""Database engine and session handling.

SQLite for local work and tests, PostgreSQL (e.g. Neon) in production. The
engine is created lazily so tests can point it at a temporary database.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from sentinel.config import get_settings


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def _with_driver(url: str) -> str:
    """Neon and Render hand out postgres:// URLs; SQLAlchemy needs the driver named."""
    for prefix in ("postgres://", "postgresql://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix):]
    return url


def init_db(url: str | None = None) -> Engine:
    """Create the engine (once, or again when given a new URL) and the tables."""
    global _engine, _SessionLocal
    url = _with_driver(url or get_settings().DATABASE_URL)
    if _engine is None or _engine.url.render_as_string(hide_password=False) != url:
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        _engine = create_engine(url, pool_pre_ping=True, connect_args=connect_args)
        if url.startswith("sqlite"):
            # PostgreSQL enforces ON DELETE CASCADE; SQLite only when asked.
            event.listen(_engine, "connect", lambda conn, _: conn.execute("PRAGMA foreign_keys=ON"))
        _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)

    from sentinel import models  # noqa: F401  registers the tables

    Base.metadata.create_all(_engine)
    _add_missing_columns(_engine)
    return _engine


def _add_missing_columns(engine: Engine) -> None:
    """Add columns introduced after a table was created.

    create_all() never alters an existing table. New columns are always
    nullable, so adding them is safe on a live database; anything more
    involved would need a real migration tool.
    """
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    with engine.begin() as connection:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue
            present = {column["name"] for column in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name not in present and column.nullable:
                    ddl_type = column.type.compile(dialect=engine.dialect)
                    connection.execute(text(f'ALTER TABLE {table.name} ADD COLUMN {column.name} {ddl_type}'))


@contextmanager
def session_scope() -> Iterator[Session]:
    """A session that commits on success and rolls back on error."""
    if _SessionLocal is None:
        init_db()
    assert _SessionLocal is not None
    session = _SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_session() -> Iterator[Session]:
    """FastAPI dependency."""
    with session_scope() as session:
        yield session
