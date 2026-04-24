"""SQLAlchemy engine, session factory, and schema bootstrap.

Kept deliberately small; no module-level side effects. Callers import
`get_engine()` / `session_scope()` rather than a bare `engine`.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from deepsecurity.config import settings
from deepsecurity.models import Base


def _ensure_sqlite_parent_dir(database_url: str) -> None:
    """If ``database_url`` is a file-based SQLite URL, create the parent dir.

    SQLite will happily create the .db file itself but bails with
    ``OperationalError: unable to open database file`` when the parent
    directory doesn't exist. Rather than force every operator to
    ``mkdir data`` we just do it on engine creation — it's idempotent and
    costs nothing when the dir already exists.

    In-memory SQLite (``sqlite:///:memory:``), non-SQLite URLs, and
    absolute URLs pointing at ``/`` are all handled safely.
    """
    if not database_url.startswith("sqlite:"):
        return
    # Strip the scheme. Handles both sqlite:/// (absolute) and sqlite:///
    # (relative) styles, plus sqlite+pysqlite://... .
    prefix, _, tail = database_url.partition(":///")
    if not tail or tail == ":memory:":
        return
    # On Windows, 'sqlite:///C:/Apps/foo.db' is parsed as tail='C:/Apps/foo.db';
    # on Unix 'sqlite:////abs/path.db' is tail='/abs/path.db'. Either way,
    # Path(tail).parent is correct.
    try:
        parent = Path(tail).expanduser().parent
        if str(parent) and parent != Path("."):
            parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        # If mkdir fails we'll let SQLAlchemy surface the real error.
        pass


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    """Return the process-wide SQLAlchemy engine."""
    url = settings.database_url
    _ensure_sqlite_parent_dir(url)
    return create_engine(
        url,
        echo=False,
        future=True,
        pool_pre_ping=True,
    )


@lru_cache(maxsize=1)
def _session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)


def SessionLocal() -> Session:  # noqa: N802 — keeps legacy call-site compatibility
    return _session_factory()()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Yield a session that commits on success, rolls back on exception, always closes."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """Create tables if they don't exist. Idempotent."""
    Base.metadata.create_all(bind=get_engine())
