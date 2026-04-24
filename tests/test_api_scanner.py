"""API-level scanner tests — end-to-end via Flask test client."""
from __future__ import annotations

import os
from pathlib import Path

from flask.testing import FlaskClient


def _client(temp_env: Path) -> tuple[FlaskClient, str]:
    from deepsecurity.api import create_app

    app = create_app()
    app.config["TESTING"] = True
    c = app.test_client()
    tok = c.post(
        "/api/auth/login",
        json={"username": "admin", "password": "correct-horse-battery-staple"},
    ).get_json()["access_token"]
    return c, tok


def _auth(tok: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {tok}"}


def test_start_scan_rejects_path_outside_root(temp_env: Path, fresh_state: None) -> None:
    c, tok = _client(temp_env)
    outside = temp_env / "outside"
    outside.mkdir()
    (outside / "a.txt").write_text("x")

    r = c.post("/api/scanner/start", json={"path": str(outside)}, headers=_auth(tok))
    assert r.status_code == 400
    assert r.get_json()["error"] == "path_outside_scan_root"


def test_start_scan_404_when_path_missing(temp_env: Path, fresh_state: None) -> None:
    c, tok = _client(temp_env)
    scan_root = temp_env / "scan"
    r = c.post(
        "/api/scanner/start",
        json={"path": str(scan_root / "nope")},
        headers=_auth(tok),
    )
    assert r.status_code == 404


def test_status_endpoint_returns_shape(temp_env: Path, fresh_state: None) -> None:
    c, _tok = _client(temp_env)
    r = c.get("/api/scanner/status")
    assert r.status_code == 200
    body = r.get_json()
    for key in (
        "running",
        "scanned_count",
        "total_files",
        "current_file",
        "progress_percent",
        "cpu",
        "ram",
    ):
        assert key in body


def test_sessions_requires_auth(temp_env: Path) -> None:
    c, _tok = _client(temp_env)
    r = c.get("/api/scanner/sessions")
    assert r.status_code == 401


def test_cancel_requires_auth(temp_env: Path, fresh_state: None) -> None:
    c, _tok = _client(temp_env)
    r = c.post("/api/scanner/cancel")
    assert r.status_code == 401


def test_results_requires_session_id(temp_env: Path) -> None:
    c, tok = _client(temp_env)
    r = c.get("/api/scanner/results", headers=_auth(tok))
    assert r.status_code == 400
