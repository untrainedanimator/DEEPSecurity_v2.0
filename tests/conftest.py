"""Test fixtures.

Strategy:
    - Every test gets its own temp tree (tmp_path) with a scan root inside it.
    - We rebuild Settings per test by setting env vars BEFORE importing
      deepsecurity.config. The singleton is reset via cache_clear().
    - The DB is a file SQLite under tmp_path so the test suite is fully isolated.
"""
from __future__ import annotations

import os
from collections.abc import Generator
from pathlib import Path

import pytest


@pytest.fixture
def temp_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Generator[Path, None, None]:
    """Configure a minimum-viable environment for tests. Returns the tmp root."""
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    quarantine = tmp_path / "quarantine"
    safelist = tmp_path / "safelist"
    deleted = tmp_path / "deleted"
    signatures = tmp_path / "signatures.txt"
    db_path = tmp_path / "test.db"

    env = {
        "DEEPSEC_ENV": "development",
        "DEEPSEC_SECRET_KEY": "a" * 32,
        "DEEPSEC_JWT_SECRET": "b" * 32,
        "DEEPSEC_SCAN_ROOT": str(scan_root),
        "DEEPSEC_QUARANTINE_DIR": str(quarantine),
        "DEEPSEC_SAFELIST_DIR": str(safelist),
        "DEEPSEC_DELETED_DIR": str(deleted),
        "DEEPSEC_SIGNATURE_PATH": str(signatures),
        "DEEPSEC_DATABASE_URL": f"sqlite:///{db_path}",
        "DEEPSEC_ML_MODEL_PATH": "",
        "DEEPSEC_ML_CONFIDENCE_THRESHOLD": "0.85",
        "DEEPSEC_CORS_ORIGINS": "http://localhost:5173",
        "DEEPSEC_LOG_LEVEL": "WARNING",
        "DEEPSEC_LOG_JSON": "false",
        "DEEPSEC_OUTLOOK_ENABLED": "false",
        "DEEPSEC_DEV_USER": "admin",
        "DEEPSEC_DEV_PASSWORD": "correct-horse-battery-staple",
        "DEEPSEC_DEV_ROLE": "admin",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)

    # Reset any cached settings/engine/session factory. The live singleton
    # lives behind a proxy in ``deepsecurity.config.settings`` that re-reads
    # ``get_settings()`` on every attribute access, so clearing the cache is
    # enough — DO NOT reassign ``cfg_mod.settings``: that would overwrite the
    # proxy with a concrete Settings object, and any module imported after
    # that point would bind the concrete object, which then goes stale the
    # next time a fixture runs.
    from deepsecurity.config import get_settings
    from deepsecurity.db import _session_factory, get_engine

    get_settings.cache_clear()
    get_engine.cache_clear()
    _session_factory.cache_clear()

    yield tmp_path

    # Cleanup caches so the next test sees a fresh world. Dispose the engine
    # BEFORE clearing its cache entry so every pooled SQLite connection is
    # closed cleanly; otherwise Python's garbage collector finalises them
    # later and pytest's ``unraisableexception`` plugin promotes the
    # ``ResourceWarning`` into a test failure on whichever unlucky test is
    # running at GC time.
    try:
        get_engine().dispose()
    except Exception:
        pass
    get_settings.cache_clear()
    get_engine.cache_clear()
    _session_factory.cache_clear()

    # Force a GC pass NOW so any lingering sqlite3.Connection wrappers
    # finalise inside the fixture (where the filterwarnings rules apply
    # cleanly) rather than during pytest's session-end cleanup hook. On
    # Python 3.14 the delayed finalisation triggers a
    # PytestUnraisableExceptionWarning that crashes an otherwise-green
    # run. This is belt-and-braces alongside the filterwarnings entry
    # in pyproject.toml.
    import gc

    gc.collect()


@pytest.fixture
def initialized_db(temp_env: Path) -> Path:
    from deepsecurity.db import init_db

    init_db()
    return temp_env


@pytest.fixture
def scan_root(temp_env: Path) -> Path:
    return (temp_env / "scan").resolve()


@pytest.fixture
def fresh_state() -> Generator[None, None, None]:
    """Reset the process-wide scan_state singleton between tests."""
    from deepsecurity import scan_state as sstate

    sstate.state = sstate.ScanState()
    yield
    sstate.state = sstate.ScanState()
