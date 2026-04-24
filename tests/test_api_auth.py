"""API auth: login, 401s, 403s, and the no-fallback guarantee."""
from __future__ import annotations

from pathlib import Path

from flask.testing import FlaskClient


def _client(temp_env: Path) -> FlaskClient:
    from deepsecurity.api import create_app

    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_login_issues_token(temp_env: Path) -> None:
    c = _client(temp_env)
    r = c.post(
        "/api/auth/login",
        json={"username": "admin", "password": "correct-horse-battery-staple"},
    )
    assert r.status_code == 200
    body = r.get_json()
    assert "access_token" in body
    assert body["role"] == "admin"


def test_login_bad_password_is_401(temp_env: Path) -> None:
    c = _client(temp_env)
    r = c.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401


def test_protected_route_without_token_is_401(temp_env: Path, fresh_state: None) -> None:
    c = _client(temp_env)
    r = c.post("/api/scanner/start", json={"path": str(temp_env / "scan")})
    assert r.status_code == 401
    body = r.get_json()
    # Must be "unauthenticated" — NOT a fallback user identity.
    assert body["error"] == "unauthenticated"


def test_whoami_with_valid_token(temp_env: Path) -> None:
    c = _client(temp_env)
    tok = c.post(
        "/api/auth/login",
        json={"username": "admin", "password": "correct-horse-battery-staple"},
    ).get_json()["access_token"]
    r = c.get("/api/auth/whoami", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    assert r.get_json() == {"username": "admin", "role": "admin"}


def test_health_is_unauthenticated(temp_env: Path) -> None:
    c = _client(temp_env)
    r = c.get("/healthz")
    assert r.status_code == 200
    assert r.get_json() == {"status": "ok"}


def test_readyz_reports_checks(temp_env: Path) -> None:
    c = _client(temp_env)
    r = c.get("/readyz")
    assert r.status_code == 200
    body = r.get_json()
    assert body["status"] == "ok"
    assert "database" in body["checks"]
    assert "scan_root" in body["checks"]
