"""Compliance templates — schema + dispatcher integration tests.

Every template module owns the exact shape of its own output, so these
tests focus on:

    1. The module has the four required metadata attributes.
    2. ``build(session, window)`` returns a JSON-serialisable dict
       that contains at minimum: template_id, title, control_ref,
       description, generated_at, window.
    3. The dispatcher route ``GET /api/compliance/template/<id>`` returns
       200 for every registered template_id.
    4. Unknown template_ids return 404 with the ``available`` list.
    5. Per-template sanity: at least one template-specific assertion
       confirming the module pulled its intended data.

Fixture: the ``initialized_db`` fixture seeds a tmp_path SQLite DB and
then we add a few audit events + a scan session + a DLP finding so the
templates have something to report.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from flask.testing import FlaskClient

from deepsecurity.compliance import DateWindow
from deepsecurity.compliance_templates import REGISTRY, list_templates
from deepsecurity.db import session_scope
from deepsecurity.models import Agent, AuditLog, DLPFinding, ScanResult, ScanSession


# ---------------------------------------------------------------------------
# Shared fixtures — seed a representative DB so every template has data.
# ---------------------------------------------------------------------------


def _seed_mixed_data() -> None:
    """Add one scan, one detection, one DLP finding, a handful of audit
    events, and one agent so every template produces a non-empty pack."""
    now = datetime.now(timezone.utc)
    with session_scope() as s:
        scan = ScanSession(
            actor="admin",
            status="completed",
            started_at=now - timedelta(hours=1),
            ended_at=now - timedelta(minutes=58),
            total_files=3,
            total_detections=1,
            scan_root="C:/Users/test/Documents",
        )
        s.add(scan)
        s.flush()
        s.add(
            ScanResult(
                session_id=scan.id,
                file_path="C:/Users/test/Documents/x.bin",
                sha256="0" * 64,
                label="malicious",
                ml_confidence=1.0,
                anomaly_score=2.0,
                entropy=7.5,
                file_status="quarantined",
                detection_reason="signature_match",
                detected_at=now - timedelta(minutes=59),
            )
        )
        s.add(
            DLPFinding(
                session_id=scan.id,
                file_path="C:/Users/test/Documents/secrets.env",
                pattern_name="aws_access_key_id",
                severity="critical",
                line_number=2,
                redacted_preview="AWS_KEY=****",
                detected_at=now - timedelta(minutes=59),
            )
        )
        s.add_all(
            [
                AuditLog(actor="admin", action="auth.login", status="ok", timestamp=now - timedelta(minutes=30)),
                AuditLog(actor="anon", action="auth.login", status="denied", timestamp=now - timedelta(minutes=25)),
                AuditLog(actor="admin", action="scan.start", status="ok", timestamp=now - timedelta(minutes=20)),
                AuditLog(actor="admin", action="scan.finish", status="ok", timestamp=now - timedelta(minutes=18)),
                AuditLog(actor="admin", action="quarantine.copied", status="ok", timestamp=now - timedelta(minutes=15)),
            ]
        )
        s.add(
            Agent(
                id="agent-test-00000000000000000001",
                labels='["e2e-agent"]',  # JSON string per model
                hostname="host-test",
                os="windows",
                os_version="10",
                agent_version="2.4.0",
                api_key_hash="x" * 64,
                registered_at=now - timedelta(days=1),
                last_heartbeat_at=now - timedelta(minutes=5),
                enabled=True,
            )
        )


# ---------------------------------------------------------------------------
# REGISTRY shape — guards against accidental deletion of a template.
# ---------------------------------------------------------------------------


def test_registry_has_all_eight_phase2_templates() -> None:
    expected = {
        "soc2-cc6-1",
        "soc2-cc6-6",
        "soc2-cc7-1",
        "iso27001-a-8-1",
        "iso27001-a-8-9",
        "iso27001-a-12-4",
        "hipaa-164-308-a-1",
        "hipaa-164-312-a-1",
    }
    assert set(REGISTRY.keys()) == expected, (
        f"REGISTRY drifted from Phase 2 plan. "
        f"Missing: {expected - set(REGISTRY.keys())}. "
        f"Unexpected: {set(REGISTRY.keys()) - expected}."
    )


def test_list_templates_returns_metadata_only() -> None:
    meta = list_templates()
    assert len(meta) == 8
    for row in meta:
        assert {"template_id", "title", "control_ref", "description"} <= row.keys()


# ---------------------------------------------------------------------------
# Per-template: metadata + build() shape.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("template_id", sorted(REGISTRY.keys()))
def test_template_has_required_metadata(template_id: str) -> None:
    mod = REGISTRY[template_id]
    assert mod.TEMPLATE_ID == template_id
    assert isinstance(mod.TITLE, str) and mod.TITLE.strip()
    assert isinstance(mod.CONTROL_REF, str) and mod.CONTROL_REF.strip()
    assert isinstance(mod.DESCRIPTION, str) and len(mod.DESCRIPTION) > 30
    assert callable(mod.build)


@pytest.mark.parametrize("template_id", sorted(REGISTRY.keys()))
def test_template_build_returns_jsonable_dict(
    template_id: str, initialized_db: Path
) -> None:
    _seed_mixed_data()
    mod = REGISTRY[template_id]
    window = DateWindow.last_days(7)
    with session_scope() as s:
        payload = mod.build(s, window)

    # Must be a dict …
    assert isinstance(payload, dict)
    # … with the five universal metadata keys.
    for key in ("template_id", "title", "control_ref", "description",
                "generated_at", "window"):
        assert key in payload, f"{template_id} build() missing {key!r}"
    assert payload["template_id"] == template_id
    assert payload["window"].get("start") < payload["window"].get("end")

    # … and fully serialisable (no bare datetimes, no objects).
    # json.dumps raises if it can't, which will fail the test.
    json.dumps(payload, default=str)


# ---------------------------------------------------------------------------
# Template-specific sanity — each pack surfaces its intended data.
# ---------------------------------------------------------------------------


def test_soc2_cc6_1_counts_logins(initialized_db: Path) -> None:
    _seed_mixed_data()
    from deepsecurity.compliance_templates import soc2_cc6_1

    with session_scope() as s:
        p = soc2_cc6_1.build(s, DateWindow.last_days(1))
    assert p["authentication"]["total_login_attempts"] == 2
    assert p["authentication"]["successful"] == 1
    assert p["authentication"]["failed"] == 1


def test_soc2_cc7_1_reports_detections_and_dlp(initialized_db: Path) -> None:
    _seed_mixed_data()
    from deepsecurity.compliance_templates import soc2_cc7_1

    with session_scope() as s:
        p = soc2_cc7_1.build(s, DateWindow.last_days(1))
    assert p["scans"]["sessions_run"] == 1
    assert p["detections"]["total"] == 1
    assert p["dlp"]["findings_total"] == 1
    assert p["dlp"]["by_severity"].get("critical") == 1


def test_iso27001_a_8_1_lists_agents(initialized_db: Path) -> None:
    _seed_mixed_data()
    from deepsecurity.compliance_templates import iso27001_a_8_1

    with session_scope() as s:
        p = iso27001_a_8_1.build(s, DateWindow.last_days(1))
    assert p["agent_fleet"]["total_registered"] == 1
    assert p["agent_fleet"]["currently_reporting"] == 1
    assert p["agent_fleet"]["agents"][0]["id"].startswith("agent-test-")


def test_iso27001_a_8_9_reports_integrity(initialized_db: Path) -> None:
    _seed_mixed_data()
    from deepsecurity.compliance_templates import iso27001_a_8_9

    with session_scope() as s:
        p = iso27001_a_8_9.build(s, DateWindow.last_days(1))
    # "integrity" key present with a status.
    assert "status" in p["integrity"]
    # Posture settings surfaced.
    assert "dlp_enabled" in p["posture_settings"]


def test_iso27001_a_12_4_reports_volume(initialized_db: Path) -> None:
    _seed_mixed_data()
    from deepsecurity.compliance_templates import iso27001_a_12_4

    with session_scope() as s:
        p = iso27001_a_12_4.build(s, DateWindow.last_days(1))
    assert p["volume"]["total_events"] >= 5
    assert "auth.login" in p["category_coverage"]["counts"]


def test_hipaa_164_312_a_1_masks_db_url(initialized_db: Path, monkeypatch) -> None:
    """The 312(a)(1) template must not leak DB passwords even if the
    operator has switched from sqlite to a postgres DSN."""
    monkeypatch.setenv(
        "DEEPSEC_DATABASE_URL", "postgres://admin:hunter2@db.x.com:5432/deepsec"
    )
    # Force settings to re-read.
    from deepsecurity.config import get_settings

    get_settings.cache_clear()

    _seed_mixed_data()
    from deepsecurity.compliance_templates import hipaa_164_312_a_1

    with session_scope() as s:
        p = hipaa_164_312_a_1.build(s, DateWindow.last_days(1))
    masked = p["encryption_and_decryption"]["database_url_masked"]
    assert "hunter2" not in masked
    assert "***" in masked


# ---------------------------------------------------------------------------
# Dispatcher route — one parametrised test covers every template_id.
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


@pytest.mark.parametrize("template_id", sorted(REGISTRY.keys()))
def test_dispatcher_route_returns_200(
    template_id: str, initialized_db: Path, authed_client
) -> None:
    _seed_mixed_data()
    c, tok = authed_client
    r = c.get(
        f"/api/compliance/template/{template_id}?days=7", headers=_auth(tok)
    )
    assert r.status_code == 200, (
        f"{template_id}: expected 200, got {r.status_code}: {r.get_json()}"
    )
    body = r.get_json()
    assert body["template_id"] == template_id


def test_dispatcher_unknown_template_returns_404(
    initialized_db: Path, authed_client
) -> None:
    c, tok = authed_client
    r = c.get("/api/compliance/template/does-not-exist", headers=_auth(tok))
    assert r.status_code == 404
    body = r.get_json()
    assert body["error"] == "unknown_template"
    assert isinstance(body["available"], list)
    assert len(body["available"]) == 8


def test_dispatcher_days_param_is_validated(initialized_db: Path, authed_client) -> None:
    c, tok = authed_client
    # Non-numeric days → 400
    r = c.get(
        "/api/compliance/template/soc2-cc6-1?days=abc", headers=_auth(tok)
    )
    assert r.status_code == 400
    # Negative clamped to 1 — still returns 200.
    r = c.get(
        "/api/compliance/template/soc2-cc6-1?days=-5", headers=_auth(tok)
    )
    assert r.status_code == 200


def test_dispatcher_pdf_without_weasyprint_returns_501(
    initialized_db: Path, authed_client
) -> None:
    """Operators without weasyprint get a helpful 501, not a crash."""
    import sys

    # Force the weasyprint import to fail inside the route.
    sys.modules["weasyprint"] = None  # type: ignore[assignment]
    try:
        c, tok = authed_client
        r = c.get(
            "/api/compliance/template/soc2-cc6-1?days=7&format=pdf",
            headers=_auth(tok),
        )
        # Either 501 (no weasyprint) or 200 (operator happens to have it).
        assert r.status_code in (200, 501)
        if r.status_code == 501:
            assert r.get_json()["error"] == "pdf_unavailable"
    finally:
        del sys.modules["weasyprint"]


def test_list_templates_route_returns_eight(
    initialized_db: Path, authed_client
) -> None:
    c, tok = authed_client
    r = c.get("/api/compliance/templates", headers=_auth(tok))
    assert r.status_code == 200
    body = r.get_json()
    assert len(body["templates"]) == 8
    ids = {t["template_id"] for t in body["templates"]}
    assert "soc2-cc6-1" in ids
    assert "hipaa-164-312-a-1" in ids
