"""Tests for the v2.5 OIDC blueprint.

Live OIDC end-to-end tests need a real IdP, which is out of scope for
unit tests. We instead verify:
    * /api/auth/oidc/login returns 503 when OIDC is disabled
    * /api/auth/oidc/callback returns 503 when OIDC is disabled
    * production env disables /api/auth/login (dev-password fallback)
    * the role-mapping function correctly handles every claim shape
"""

from __future__ import annotations

import pytest


def _client(monkeypatch, **env):
    """Build a Flask test client with the given env overrides."""
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    from deepsecurity.config import get_settings

    get_settings.cache_clear()
    from deepsecurity.api import create_app

    app = create_app()
    return app.test_client()


# --------------------------------------------------------------------------
# OIDC disabled by default → /login + /callback return 503 with hint
# --------------------------------------------------------------------------


def test_oidc_login_returns_503_when_disabled(monkeypatch) -> None:
    c = _client(monkeypatch, DEEPSEC_OIDC_ENABLED="false")
    r = c.get("/api/auth/oidc/login")
    assert r.status_code == 503
    body = r.get_json()
    assert body["error"] == "oidc_not_configured"


def test_oidc_callback_returns_503_when_disabled(monkeypatch) -> None:
    c = _client(monkeypatch, DEEPSEC_OIDC_ENABLED="false")
    r = c.get("/api/auth/oidc/callback?code=abc&state=xyz")
    assert r.status_code == 503


# --------------------------------------------------------------------------
# Production refuses dev-password login
# --------------------------------------------------------------------------


def test_dev_password_login_disabled_in_production(monkeypatch) -> None:
    c = _client(
        monkeypatch,
        DEEPSEC_ENV="production",
        DEEPSEC_DEV_PASSWORD="this-is-not-actually-tried",
        # Need real-looking secrets so config validates.
        DEEPSEC_SECRET_KEY="0123456789abcdef0123456789abcdef",
        DEEPSEC_JWT_SECRET="fedcba9876543210fedcba9876543210",
    )
    r = c.post(
        "/api/auth/login",
        json={"username": "admin", "password": "this-is-not-actually-tried"},
    )
    assert r.status_code == 403
    body = r.get_json()
    assert body["error"] == "dev_login_disabled_in_production"
    assert "oidc" in body["hint"].lower()


# --------------------------------------------------------------------------
# Role mapping unit tests
# --------------------------------------------------------------------------


@pytest.fixture
def role_mapper(monkeypatch):
    monkeypatch.setenv("DEEPSEC_OIDC_ADMIN_GROUPS", "deepsec-admin,sec-leads")
    monkeypatch.setenv("DEEPSEC_OIDC_SECURITY_GROUPS", "deepsec-security")
    monkeypatch.setenv("DEEPSEC_OIDC_ANALYST_GROUPS", "deepsec-analyst,viewers")
    monkeypatch.setenv("DEEPSEC_OIDC_DEFAULT_ROLE", "")
    monkeypatch.setenv("DEEPSEC_OIDC_ROLE_CLAIM", "groups")
    from deepsecurity.config import get_settings

    get_settings.cache_clear()
    from deepsecurity.api.oidc import _map_role

    return _map_role


def test_role_admin_wins_over_other_groups(role_mapper) -> None:
    assert role_mapper({"groups": ["deepsec-admin", "deepsec-analyst"]}) == "admin"


def test_role_security(role_mapper) -> None:
    assert role_mapper({"groups": ["deepsec-security"]}) == "security"


def test_role_analyst(role_mapper) -> None:
    assert role_mapper({"groups": ["viewers"]}) == "analyst"


def test_role_string_claim(role_mapper) -> None:
    # Some IdPs return a single string instead of a list.
    assert role_mapper({"groups": "deepsec-admin"}) == "admin"


def test_role_no_match_default_empty_denies(role_mapper) -> None:
    # Empty default = strict mode. No groups → role = "".
    assert role_mapper({"groups": ["completely-unrelated"]}) == ""


def test_role_no_match_with_default(monkeypatch) -> None:
    monkeypatch.setenv("DEEPSEC_OIDC_ADMIN_GROUPS", "x")
    monkeypatch.setenv("DEEPSEC_OIDC_SECURITY_GROUPS", "y")
    monkeypatch.setenv("DEEPSEC_OIDC_ANALYST_GROUPS", "z")
    monkeypatch.setenv("DEEPSEC_OIDC_DEFAULT_ROLE", "analyst")
    monkeypatch.setenv("DEEPSEC_OIDC_ROLE_CLAIM", "groups")
    from deepsecurity.config import get_settings

    get_settings.cache_clear()
    from deepsecurity.api.oidc import _map_role

    assert _map_role({"groups": ["nothing"]}) == "analyst"
