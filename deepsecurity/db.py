"""SQLAlchemy engine, session factory, and schema bootstrap.

Kept deliberately small; no module-level side effects. Callers import
`get_engine()` / `session_scope()` rather than a bare `engine`.

v2.5.0 — Alembic migrations are now the source of truth for schema. Fresh
installs are still bootstrapped via ``Base.metadata.create_all`` (the
fastest path) and then ``stamp``ed at the latest revision so subsequent
``alembic upgrade head`` calls behave correctly. Existing deployments at
the v2.4.x baseline can run ``alembic stamp head`` once.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

from sqlalchemy import Engine, create_engine, inspect
from sqlalchemy.orm import Session, sessionmaker

from deepsecurity.config import settings
from deepsecurity.logging_config import get_logger
from deepsecurity.models import Base

_log = get_logger(__name__)


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
    _, _, tail = database_url.partition(":///")
    if not tail or tail == ":memory:":
        return
    # On Windows, 'sqlite:///C:/Apps/foo.db' is parsed as tail='C:/Apps/foo.db';
    # on Unix 'sqlite:////abs/path.db' is tail='/abs/path.db'. Either way,
    # Path(tail).parent is correct.
    try:
        parent = Path(tail).expanduser().parent
        if str(parent) and parent != Path():
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


def SessionLocal() -> Session:
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


def _alembic_config() -> object | None:
    """Return an Alembic Config object pointed at our migrations dir, or None.

    Alembic is an optional dep at runtime — it's pulled in via
    requirements-dev.txt and the [postgres] extra, but a minimal
    SQLite-only single-node deploy doesn't strictly need it. Importing it
    inside the function keeps the runtime path import-light when it's
    absent.
    """
    try:
        from alembic.config import Config
    except ImportError:  # pragma: no cover — best-effort
        return None
    repo_root = Path(__file__).resolve().parents[1]
    ini = repo_root / "alembic.ini"
    if not ini.exists():
        return None
    cfg = Config(str(ini))
    cfg.set_main_option("script_location", str(repo_root / "migrations"))
    cfg.set_main_option("sqlalchemy.url", settings.database_url)
    return cfg


def _stamp_head(cfg: object) -> None:
    """Mark the alembic_version table at the latest revision (no SQL run)."""
    try:
        from alembic import command as alembic_command

        alembic_command.stamp(cfg, "head")
        _log.info("db.alembic.stamped_head")
    except Exception:
        _log.exception("db.alembic.stamp_failed")


def _upgrade_to_head(cfg: object) -> None:
    """Run alembic upgrade head — apply any pending migrations."""
    try:
        from alembic import command as alembic_command

        alembic_command.upgrade(cfg, "head")
        _log.info("db.alembic.upgraded")
    except Exception:
        _log.exception("db.alembic.upgrade_failed")
        raise


def init_db() -> None:
    """Bring the schema up to head. Safe and idempotent.

    Strategy:
        1. If the DB has no tables yet, create_all + stamp head. Fast path
           for fresh installs and tests.
        2. If the DB has our tables but no alembic_version row, the deploy
           is a v2.4.x baseline upgrade; stamp head and stop.
        3. Otherwise, run ``alembic upgrade head`` to apply any pending
           migrations.

    All branches no-op cleanly when alembic isn't importable.
    """
    engine = get_engine()
    insp = inspect(engine)
    has_any_app_table = "scan_sessions" in insp.get_table_names()
    has_alembic_table = "alembic_version" in insp.get_table_names()
    cfg = _alembic_config()

    if not has_any_app_table:
        _log.info("db.init.create_all")
        Base.metadata.create_all(bind=engine)
        if cfg is not None:
            _stamp_head(cfg)
        return

    if has_any_app_table and not has_alembic_table:
        _log.info("db.init.legacy_baseline_detected")
        if cfg is not None:
            _stamp_head(cfg)
        return

    # Tables + alembic_version both exist — apply any pending migrations.
    if cfg is not None:
        _upgrade_to_head(cfg)
    else:
        # Alembic missing — at least keep the schema consistent with the
        # ORM so a developer who skipped the dev install can still boot.
        _log.warning("db.init.alembic_missing_fallback_create_all")
        Base.metadata.create_all(bind=engine)
