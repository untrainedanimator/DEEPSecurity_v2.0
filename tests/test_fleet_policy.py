"""FLEET_POLICY (v2.4) — per-agent policy push, end-to-end.

Covers:
  - POST /api/agents/<id>/policy with valid / invalid / partial bodies
  - Heartbeat response now carries policy_sha
  - GET /api/agents/<id>/policy — agent fetches own, can't fetch others
  - Worker helpers: _policy_file_for, _load/_save, _maybe_fetch_and_apply

Integration-style where possible: stand up a real Flask test client,
enrol + register an agent, push a policy, verify round-trip. No real
network / no real watchdog spawned.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from flask.testing import FlaskClient


# ---------------------------------------------------------------------------
# Helpers: enrol + register an agent via the real API so we have real creds.
# ---------------------------------------------------------------------------


@pytest.fixture
def authed_client(temp_env: Path) -> tuple[FlaskClient, str]:
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


def _enrol_and_register(client: FlaskClient, admin_token: str) -> tuple[str, str]:
    """Return (agent_id, api_key). Covers the usual two-step dance."""
    r = client.post(
        "/api/agents/enrol",
        json={"label": "fleet-test", "ttl_hours": 1},
        headers=_auth(admin_token),
    )
    assert r.status_code == 201, r.get_json()
    enrol_tok = r.get_json()["enrolment_token"]

    r = client.post(
        "/api/agents/register",
        json={
            "enrolment_token": enrol_tok,
            "hostname": "host-fleet-test",
            "os": "windows",
            "os_version": "10",
            "agent_version": "2.4.0",
        },
    )
    assert r.status_code == 201, r.get_json()
    body = r.get_json()
    return body["agent_id"], body["api_key"]


def _agent_headers(agent_id: str, api_key: str) -> dict[str, str]:
    return {
        "X-DEEPSEC-AGENT-ID": agent_id,
        "X-DEEPSEC-AGENT-KEY": api_key,
    }


# ---------------------------------------------------------------------------
# API — set / get policy round-trip.
# ---------------------------------------------------------------------------


def test_policy_is_empty_before_any_push(initialized_db: Path, authed_client) -> None:
    """Agent heartbeat returns policy_sha='' when no policy was ever set."""
    c, tok = authed_client
    agent_id, api_key = _enrol_and_register(c, tok)

    r = c.post(
        "/api/agents/heartbeat",
        json={"cpu_percent": 1.0, "ram_percent": 10.0},
        headers=_agent_headers(agent_id, api_key),
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body.get("policy_sha") == ""


def test_set_policy_with_full_body(initialized_db: Path, authed_client) -> None:
    c, tok = authed_client
    agent_id, api_key = _enrol_and_register(c, tok)

    policy = {
        "exclusion_globs": "**/node_modules/**;**/.venv/**",
        "dlp_severity_overrides": {"email_address": "observe"},
        "autostart_scope": "user_risk",
        "signatures_url": "https://policy.example.com/sigs.txt",
    }
    r = c.post(
        f"/api/agents/{agent_id}/policy",
        json=policy,
        headers=_auth(tok),
    )
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["agent_id"] == agent_id
    assert len(body["policy_sha"]) == 64  # sha256 hex

    # Deterministic SHA — the canonical form is sorted JSON with
    # compact separators. Recompute and compare.
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    expected_sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert body["policy_sha"] == expected_sha


def test_set_policy_rejects_unknown_keys(initialized_db: Path, authed_client) -> None:
    """A typo like 'exclude_globs' (missing the 'ion') must fail rather
    than be silently discarded."""
    c, tok = authed_client
    agent_id, _ = _enrol_and_register(c, tok)

    r = c.post(
        f"/api/agents/{agent_id}/policy",
        json={"exclude_globs": "**/node_modules/**"},  # typo
        headers=_auth(tok),
    )
    assert r.status_code == 400
    body = r.get_json()
    assert body["error"] == "unknown_policy_keys"
    assert "exclude_globs" in body["unknown"]


def test_set_policy_validates_autostart_scope(
    initialized_db: Path, authed_client
) -> None:
    c, tok = authed_client
    agent_id, _ = _enrol_and_register(c, tok)

    r = c.post(
        f"/api/agents/{agent_id}/policy",
        json={"autostart_scope": "full-drive"},  # not in {'', 'user_risk', 'system'}
        headers=_auth(tok),
    )
    assert r.status_code == 400
    assert r.get_json()["error"] == "bad_value"


def test_set_policy_404_on_unknown_agent(
    initialized_db: Path, authed_client
) -> None:
    c, tok = authed_client
    r = c.post(
        "/api/agents/unknown-agent-id/policy",
        json={"autostart_scope": "user_risk"},
        headers=_auth(tok),
    )
    assert r.status_code == 404


def test_heartbeat_surfaces_current_policy_sha(
    initialized_db: Path, authed_client
) -> None:
    c, tok = authed_client
    agent_id, api_key = _enrol_and_register(c, tok)

    c.post(
        f"/api/agents/{agent_id}/policy",
        json={"autostart_scope": "user_risk"},
        headers=_auth(tok),
    )
    r = c.post(
        "/api/agents/heartbeat",
        json={"cpu_percent": 1.0, "ram_percent": 10.0},
        headers=_agent_headers(agent_id, api_key),
    )
    assert r.status_code == 200
    assert r.get_json()["policy_sha"], "heartbeat should carry the new policy_sha"


def test_agent_can_fetch_own_policy(initialized_db: Path, authed_client) -> None:
    c, tok = authed_client
    agent_id, api_key = _enrol_and_register(c, tok)

    policy = {"exclusion_globs": "**/foo/**", "autostart_scope": ""}
    c.post(
        f"/api/agents/{agent_id}/policy", json=policy, headers=_auth(tok)
    )

    r = c.get(
        f"/api/agents/{agent_id}/policy",
        headers=_agent_headers(agent_id, api_key),
    )
    assert r.status_code == 200
    body = r.get_json()
    assert body["policy"] == policy
    assert len(body["policy_sha"]) == 64


def test_agent_cannot_fetch_another_agents_policy(
    initialized_db: Path, authed_client
) -> None:
    c, tok = authed_client
    # Register two agents; one tries to read the other's policy.
    a1_id, a1_key = _enrol_and_register(c, tok)
    a2_id, a2_key = _enrol_and_register(c, tok)

    c.post(
        f"/api/agents/{a2_id}/policy",
        json={"autostart_scope": "user_risk"},
        headers=_auth(tok),
    )

    r = c.get(
        f"/api/agents/{a2_id}/policy",
        headers=_agent_headers(a1_id, a1_key),  # a1 using a1's creds
    )
    assert r.status_code == 403
    assert r.get_json()["error"] == "agent_id_mismatch"


def test_policy_round_trip_survives_update(
    initialized_db: Path, authed_client
) -> None:
    c, tok = authed_client
    agent_id, api_key = _enrol_and_register(c, tok)

    # Push v1 then v2.
    c.post(
        f"/api/agents/{agent_id}/policy",
        json={"autostart_scope": "user_risk"},
        headers=_auth(tok),
    )
    r1 = c.post(
        "/api/agents/heartbeat",
        json={"cpu_percent": 1.0},
        headers=_agent_headers(agent_id, api_key),
    )
    sha_v1 = r1.get_json()["policy_sha"]

    c.post(
        f"/api/agents/{agent_id}/policy",
        json={"autostart_scope": "system"},
        headers=_auth(tok),
    )
    r2 = c.post(
        "/api/agents/heartbeat",
        json={"cpu_percent": 1.0},
        headers=_agent_headers(agent_id, api_key),
    )
    sha_v2 = r2.get_json()["policy_sha"]

    assert sha_v1 != sha_v2
    assert len(sha_v1) == 64 and len(sha_v2) == 64


# ---------------------------------------------------------------------------
# Worker-side helpers — pure-python, no network.
# ---------------------------------------------------------------------------


def test_worker_persists_new_policy_to_disk(tmp_path: Path) -> None:
    """On a policy_sha mismatch, worker fetches and writes to disk."""
    from deepsecurity.agent.worker import (
        _load_local_policy,
        _maybe_fetch_and_apply_policy,
        _policy_file_for,
    )

    class _Cfg:
        path = str(tmp_path / "deepsec-agent.json")

    cfg = _Cfg()
    mock_transport = MagicMock()
    mock_transport.get_policy.return_value = {
        "policy_sha": "abc" * 21 + "a",  # 64-char-ish placeholder
        "policy": {"autostart_scope": "user_risk"},
        "updated_at": "2026-04-25T00:00:00+00:00",
        "updated_by": "admin",
    }

    # Before: no local policy file.
    assert _load_local_policy(cfg) == {}

    _maybe_fetch_and_apply_policy(mock_transport, cfg, "abc" * 21 + "a")

    # After: the file exists with the fetched policy.
    persisted = _load_local_policy(cfg)
    assert persisted["policy_sha"] == "abc" * 21 + "a"
    assert persisted["policy"]["autostart_scope"] == "user_risk"
    assert _policy_file_for(cfg).exists()


def test_worker_skips_fetch_when_already_in_sync(tmp_path: Path) -> None:
    """If local policy_sha matches server, no fetch — don't waste a
    round-trip."""
    from deepsecurity.agent.worker import (
        _maybe_fetch_and_apply_policy,
        _save_local_policy,
    )

    class _Cfg:
        path = str(tmp_path / "deepsec-agent.json")

    cfg = _Cfg()
    _save_local_policy(
        cfg,
        {"policy_sha": "same-sha", "policy": {"autostart_scope": "user_risk"}},
    )

    mock_transport = MagicMock()
    _maybe_fetch_and_apply_policy(mock_transport, cfg, "same-sha")
    mock_transport.get_policy.assert_not_called()


def test_worker_skips_when_server_has_no_policy(tmp_path: Path) -> None:
    """An empty policy_sha (no policy pushed) must not trigger a fetch."""
    from deepsecurity.agent.worker import _maybe_fetch_and_apply_policy

    class _Cfg:
        path = str(tmp_path / "deepsec-agent.json")

    mock_transport = MagicMock()
    _maybe_fetch_and_apply_policy(mock_transport, _Cfg(), "")
    mock_transport.get_policy.assert_not_called()


def test_worker_survives_transport_error(tmp_path: Path) -> None:
    """If the policy fetch network call fails, the worker must log and
    continue — never raise."""
    from deepsecurity.agent.transport import TransportError
    from deepsecurity.agent.worker import _maybe_fetch_and_apply_policy

    class _Cfg:
        path = str(tmp_path / "deepsec-agent.json")

    mock_transport = MagicMock()
    mock_transport.get_policy.side_effect = TransportError("boom")

    # Must not raise.
    _maybe_fetch_and_apply_policy(mock_transport, _Cfg(), "new-sha")
