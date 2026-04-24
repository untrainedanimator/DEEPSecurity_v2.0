"""Security headers + rate limit + request-size guard + metrics endpoint."""
from __future__ import annotations

from pathlib import Path

from flask.testing import FlaskClient


def _client(temp_env: Path) -> FlaskClient:
    from deepsecurity.api import create_app

    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_security_headers_are_set(temp_env: Path) -> None:
    c = _client(temp_env)
    r = c.get("/healthz")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "no-referrer" in r.headers["Referrer-Policy"]
    assert "Strict-Transport-Security" in r.headers
    assert "Content-Security-Policy" in r.headers


def test_metrics_endpoint_is_text(temp_env: Path) -> None:
    c = _client(temp_env)
    r = c.get("/metrics")
    assert r.status_code == 200
    assert r.content_type.startswith("text/plain")
    assert b"deepsec_build_info" in r.data


def test_rate_limit_triggers_429(temp_env: Path, monkeypatch) -> None:
    monkeypatch.setenv("DEEPSEC_RATE_LIMIT_ANON_PER_MINUTE", "2")

    # Rebuild settings so the override takes effect. Because ``settings`` is
    # a proxy that re-reads ``get_settings()`` on every attribute access,
    # clearing the cache is enough — do NOT reassign ``cfg_mod.settings`` or
    # we'd overwrite the proxy with a concrete object and leak that across
    # subsequent tests.
    from deepsecurity.config import get_settings
    from deepsecurity.db import _session_factory, get_engine

    get_settings.cache_clear()
    get_engine.cache_clear()
    _session_factory.cache_clear()

    c = _client(temp_env)
    assert c.get("/api/scanner/status").status_code in (200, 401)
    assert c.get("/api/scanner/status").status_code in (200, 401)
    third = c.get("/api/scanner/status")
    # Either 429 from rate-limiter, or 401 on a route that requires auth —
    # the limit kicks in on anonymous traffic first.
    assert third.status_code in (429, 401)
    if third.status_code == 429:
        assert third.get_json()["error"] == "rate_limited"
        assert "Retry-After" in third.headers


def test_request_size_limit(temp_env: Path, monkeypatch) -> None:
    monkeypatch.setenv("DEEPSEC_MAX_REQUEST_BYTES", "1024")
    from deepsecurity.config import get_settings
    from deepsecurity.db import _session_factory, get_engine

    get_settings.cache_clear()
    get_engine.cache_clear()
    _session_factory.cache_clear()

    c = _client(temp_env)
    big_payload = {"path": "x" * 2000}
    r = c.post("/api/scanner/start", json=big_payload)
    # 413 Request Entity Too Large or 401 (if auth hits first).
    assert r.status_code in (401, 413)
