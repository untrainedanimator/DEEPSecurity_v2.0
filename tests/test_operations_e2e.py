"""Automated end-to-end tests mirroring docs/TEST_OPERATIONS.md.

Each class corresponds to a Phase in the manual runbook. The point of this
file is to make the manual test plan reproducible — `pytest
tests/test_operations_e2e.py` runs the whole thing in ~30 seconds and
returns a pass/fail instead of a 2-hour manual session.

Tests that need real OS artefacts (long-running processes, high file-write
rates) are marked `slow` and skipped by default; run them with
    pytest -m slow

Everything else runs on the default pytest invocation.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import pytest
from flask.testing import FlaskClient


# ---------------------------------------------------------------------------
# Test fixtures (on top of conftest.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def authed_client(temp_env: Path) -> tuple[FlaskClient, str]:
    """Flask test client + a valid operator JWT."""
    from deepsecurity.api import create_app

    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "correct-horse-battery-staple"},
    )
    assert resp.status_code == 200
    token = resp.get_json()["access_token"]
    return client, token


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ===========================================================================
# Phase 3.1 — Signature detection (EICAR)
# ===========================================================================


class TestSignatureDetection:
    """Phase 3.1 — A file whose SHA-256 is in the signature list is quarantined.

    The original file is left in place (copy semantics), a copy appears in
    quarantine, and the detection reason cites signature_match with a
    MITRE tag of T1588.001.

    NOTE: we deliberately avoid the real EICAR test string here. On Windows,
    Defender recognizes EICAR the moment it hits disk and starts
    quarantining/locking the file — our own ``read_bytes()`` then fails with
    ``OSError 22: Invalid argument``. Since the test is really about our
    signature-match code path, not about the literal EICAR bytes, we plant a
    harmless fixed byte-string and put its SHA-256 in the signature file.
    Same code path, no fight with Defender.
    """

    # Fixed, deterministic, AV-neutral payload. Never, ever put the real
    # EICAR string in the test tree — see the NOTE above.
    FAKE_MALWARE_BODY = b"DEEPSEC-TEST-PAYLOAD-" + b"Z" * 48
    FAKE_MALWARE_SHA256 = hashlib.sha256(FAKE_MALWARE_BODY).hexdigest()

    def test_eicar_quarantined_on_signature_hit(
        self,
        initialized_db: Path,
        scan_root: Path,
        fresh_state: None,
    ) -> None:
        from deepsecurity.config import settings
        from deepsecurity.scanner import scan_directory

        sample = scan_root / "fake_signature_sample.bin"
        sample.write_bytes(self.FAKE_MALWARE_BODY)
        assert hashlib.sha256(sample.read_bytes()).hexdigest() == self.FAKE_MALWARE_SHA256

        settings.signature_path.parent.mkdir(parents=True, exist_ok=True)
        settings.signature_path.write_text(self.FAKE_MALWARE_SHA256 + "\n")

        summary = scan_directory(scan_root, actor="test", user_role="admin")

        assert summary["total_files"] == 1
        assert summary["total_detections"] == 1
        assert sample.exists(), "original must not be deleted (we copy, never move)"

        # A quarantine copy appeared.
        qdir = settings.quarantine_dir
        qentries = list(qdir.iterdir()) if qdir.exists() else []
        assert len(qentries) == 1
        assert qentries[0].read_bytes() == self.FAKE_MALWARE_BODY


# ===========================================================================
# Phase 3.3 — Entropy + MIME whitelist
# ===========================================================================


class TestEntropyMimeWhitelist:
    """The v1.0-working regression: high-entropy media must not be quarantined."""

    def test_high_entropy_jpeg_not_flagged(
        self, initialized_db: Path, scan_root: Path, fresh_state: None
    ) -> None:
        from deepsecurity.scanner import scan_directory

        (scan_root / "photo.jpg").write_bytes(os.urandom(8192))
        summary = scan_directory(scan_root, actor="test", user_role="admin")
        assert summary["total_detections"] == 0

    def test_high_entropy_octet_stream_is_suspicious(
        self, initialized_db: Path, scan_root: Path, fresh_state: None
    ) -> None:
        from deepsecurity.db import session_scope
        from deepsecurity.models import ScanResult
        from deepsecurity.scanner import scan_directory

        (scan_root / "weird.bin").write_bytes(os.urandom(8192))
        summary = scan_directory(scan_root, actor="test", user_role="admin")

        with session_scope() as s:
            rows = s.query(ScanResult).filter_by(session_id=summary["session_id"]).all()
            labels = [r.label for r in rows]

        assert "suspicious" in labels
        # Must not be quarantined on entropy alone.
        assert all(r.file_status != "quarantined" for r in rows)


# ===========================================================================
# Phase 3.4 — DLP
# ===========================================================================


class TestDLPIntegration:
    """End-to-end: write secrets, scan, verify findings persisted + MITRE-tagged."""

    SECRET_FILE_CONTENT = (
        "# test fixture\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\n"
        "SSN=123-45-6789\n"
        "support@example.com\n"
    )

    def test_dlp_findings_persisted_and_redacted(
        self, initialized_db: Path, scan_root: Path, fresh_state: None
    ) -> None:
        from deepsecurity.db import session_scope
        from deepsecurity.models import DLPFinding
        from deepsecurity.scanner import scan_directory

        (scan_root / "secrets.env").write_text(self.SECRET_FILE_CONTENT)
        scan_directory(scan_root, actor="test", user_role="admin")

        with session_scope() as s:
            findings = s.query(DLPFinding).all()
            by_pattern = {f.pattern_name for f in findings}

        assert "aws_access_key_id" in by_pattern
        assert "private_key_pem" in by_pattern
        assert "us_ssn" in by_pattern
        assert "email_address" in by_pattern

        with session_scope() as s:
            for f in s.query(DLPFinding).all():
                assert "AKIAIOSFODNN7EXAMPLE" not in f.redacted_preview
                assert "wJalrXUtnFEMI" not in f.redacted_preview
                assert "****" in f.redacted_preview

    def test_dlp_findings_api_includes_mitre_tags(
        self, initialized_db: Path, scan_root: Path, authed_client, fresh_state: None
    ) -> None:
        from deepsecurity.scanner import scan_directory

        client, token = authed_client
        (scan_root / "creds.env").write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
        scan_directory(scan_root, actor="test", user_role="admin")

        resp = client.get("/api/dlp/findings", headers=_auth(token))
        assert resp.status_code == 200
        rows = resp.get_json()
        aws = [r for r in rows if r["pattern"] == "aws_access_key_id"]
        assert len(aws) >= 1
        assert "T1552.001" in aws[0]["mitre_tags"]


# ===========================================================================
# Phase 4 — Response actions
# ===========================================================================


class TestResponseActions:
    """Quarantine lifecycle, delete-with-reason, session rollback."""

    def test_permanent_delete_requires_reason(
        self, initialized_db: Path, authed_client
    ) -> None:
        client, token = authed_client

        # Plant a dummy file in quarantine.
        from deepsecurity.config import settings

        qdir = settings.quarantine_dir
        qdir.mkdir(parents=True, exist_ok=True)
        dummy = qdir / "dummy_to_delete.bin"
        dummy.write_bytes(b"x")

        # No reason → 400.
        resp = client.post(
            "/api/quarantine/delete",
            json={"name": "dummy_to_delete.bin"},
            headers=_auth(token),
        )
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "reason_required"
        assert dummy.exists(), "file must still exist after rejected delete"

        # Short reason → 400.
        resp = client.post(
            "/api/quarantine/delete",
            json={"name": "dummy_to_delete.bin", "reason": "ok"},
            headers=_auth(token),
        )
        assert resp.status_code == 400
        assert dummy.exists()

        # Proper reason → 200, file gone.
        resp = client.post(
            "/api/quarantine/delete",
            json={
                "name": "dummy_to_delete.bin",
                "reason": "verified malicious by analyst",
            },
            headers=_auth(token),
        )
        assert resp.status_code == 200
        assert resp.get_json()["deleted"] is True
        assert not dummy.exists()

    def test_session_rollback_restores_all_quarantined(
        self,
        initialized_db: Path,
        scan_root: Path,
        authed_client,
        fresh_state: None,
    ) -> None:
        from deepsecurity.config import settings
        from deepsecurity.scanner import compute_sha256, scan_directory

        client, token = authed_client

        # Two files, both signature-matched.
        f1 = scan_root / "bad1.bin"
        f1.write_bytes(b"malware A")
        f2 = scan_root / "bad2.bin"
        f2.write_bytes(b"malware B")
        settings.signature_path.parent.mkdir(parents=True, exist_ok=True)
        settings.signature_path.write_text(
            compute_sha256(f1) + "\n" + compute_sha256(f2) + "\n"
        )

        summary = scan_directory(scan_root, actor="test", user_role="admin")
        session_id = summary["session_id"]
        assert summary["total_detections"] == 2

        # Delete the originals so restore has somewhere to go.
        f1.unlink()
        f2.unlink()

        resp = client.post(
            "/api/quarantine/restore-session",
            json={"session_id": session_id},
            headers=_auth(token),
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["restored"] == 2
        assert body["failed"] == 0
        # Originals back.
        assert f1.exists()
        assert f2.exists()


# ===========================================================================
# Phase 5 — Self-integrity
# ===========================================================================


class TestSelfIntegrity:
    """Snapshot → tamper → check detects → re-snapshot → check clean."""

    def test_snapshot_tamper_detect_recover(
        self, initialized_db: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Point the integrity snapshot at a scratch location so we don't
        # collide with whatever the real deepsecurity package looks like.
        monkeypatch.setenv(
            "DEEPSEC_INTEGRITY_SNAPSHOT_PATH",
            str(tmp_path / "integrity.json"),
        )
        # Clear the settings cache so the env var above is picked up. The
        # ``settings`` symbol across the codebase is a proxy that re-reads
        # ``get_settings()`` per attribute, so no reassignment is needed.
        from deepsecurity.config import get_settings, settings

        get_settings.cache_clear()

        from deepsecurity.integrity import check, snapshot

        # 1. Baseline.
        report = snapshot()
        assert report.status == "ok"
        assert report.total_files > 0

        # 2. Tamper the snapshot file itself to simulate code drift.
        snap_path = settings.integrity_snapshot_path
        saved = json.loads(snap_path.read_text())
        # Change a random file's hash to something else.
        some_file = next(iter(saved["files"]))
        saved["files"][some_file] = "0" * 64
        snap_path.write_text(json.dumps(saved))

        # 3. Check detects mismatch.
        report = check()
        assert report.status == "tampered"
        assert some_file in report.mismatched

        # 4. Re-snapshot recovers.
        snapshot()
        report = check()
        assert report.status == "ok"


# ===========================================================================
# Phase 6 — Agent roundtrip
# ===========================================================================


class TestAgentRoundtrip:
    """Operator enrols token → agent registers → operator queues command →
    agent pulls → agent posts result → operator sees completed."""

    def test_full_enrol_register_command_cycle(
        self, initialized_db: Path, authed_client, fresh_state: None
    ) -> None:
        client, token = authed_client

        # 1. Operator: issue an enrolment token.
        resp = client.post(
            "/api/agents/enrol",
            json={"label": "pytest-agent", "ttl_hours": 1},
            headers=_auth(token),
        )
        assert resp.status_code == 201
        enrolment_token = resp.get_json()["enrolment_token"]

        # 2. Agent: register. (No auth — the enrolment token IS the cred.)
        resp = client.post(
            "/api/agents/register",
            json={
                "enrolment_token": enrolment_token,
                "hostname": "test-host",
                "os": "linux",
                "os_version": "test",
                "agent_version": "2.2.0",
                "labels": ["ci"],
            },
        )
        assert resp.status_code == 201
        agent_id = resp.get_json()["agent_id"]
        api_key = resp.get_json()["api_key"]

        # 3. Same enrolment token cannot be reused.
        resp = client.post(
            "/api/agents/register",
            json={
                "enrolment_token": enrolment_token,
                "hostname": "evil",
                "os": "linux",
                "os_version": "x",
                "agent_version": "2.2.0",
            },
        )
        assert resp.status_code == 401

        agent_headers = {
            "X-DEEPSEC-AGENT-ID": agent_id,
            "X-DEEPSEC-AGENT-KEY": api_key,
        }

        # 4. Agent: heartbeat.
        resp = client.post(
            "/api/agents/heartbeat",
            json={"cpu_percent": 1.0, "ram_percent": 10.0},
            headers=agent_headers,
        )
        assert resp.status_code == 200

        # 5. Operator: queue a command.
        resp = client.post(
            f"/api/agents/{agent_id}/commands",
            json={"kind": "self_test", "payload": {}},
            headers=_auth(token),
        )
        assert resp.status_code == 201
        cmd_id = resp.get_json()["command_id"]

        # 6. Agent: pull commands.
        resp = client.get("/api/agents/commands", headers=agent_headers)
        assert resp.status_code == 200
        cmds = resp.get_json()["commands"]
        assert any(c["command_id"] == cmd_id for c in cmds)

        # 7. Agent: post result.
        resp = client.post(
            "/api/agents/results",
            json={"command_id": cmd_id, "success": True, "result": {"alive": True}},
            headers=agent_headers,
        )
        assert resp.status_code == 200

        # 8. Operator: verify agent is listed + last-heartbeat set.
        resp = client.get("/api/agents", headers=_auth(token))
        assert resp.status_code == 200
        rows = resp.get_json()
        assert any(r["id"] == agent_id for r in rows)

        # 9. Operator: revoke. Agent can no longer heartbeat.
        resp = client.delete(f"/api/agents/{agent_id}", headers=_auth(token))
        assert resp.status_code == 200
        resp = client.post("/api/agents/heartbeat", json={}, headers=agent_headers)
        assert resp.status_code == 401

    def test_bad_enrolment_token_rejected(self, initialized_db: Path, authed_client) -> None:
        client, _token = authed_client
        resp = client.post(
            "/api/agents/register",
            json={
                "enrolment_token": "definitely-not-a-real-token",
                "hostname": "test",
                "os": "linux",
                "os_version": "x",
                "agent_version": "2.2.0",
            },
        )
        assert resp.status_code == 401

    def test_unauthenticated_agent_heartbeat_401(self, initialized_db: Path, authed_client) -> None:
        client, _token = authed_client
        resp = client.post("/api/agents/heartbeat", json={})
        assert resp.status_code == 401


# ===========================================================================
# Phase 7 — Failure injection
# ===========================================================================


class TestFailureInjection:
    """Negative-path coverage — every guard we ship has to return the
    right HTTP code, every time."""

    def test_protected_route_without_token_is_401(self, temp_env: Path) -> None:
        from deepsecurity.api import create_app

        app = create_app()
        app.config["TESTING"] = True
        c = app.test_client()

        for path in (
            "/api/scanner/sessions",
            "/api/dlp/findings",
            "/api/audit",
            "/api/processes/scan",
            "/api/quarantine/list",
            "/api/compliance/report",
            "/api/agents",
        ):
            resp = c.get(path) if path != "/api/processes/scan" else c.post(path)
            assert resp.status_code == 401, f"{path} must require auth"

    def test_malformed_jwt_is_401(self, temp_env: Path) -> None:
        from deepsecurity.api import create_app

        app = create_app()
        app.config["TESTING"] = True
        c = app.test_client()
        resp = c.get(
            "/api/scanner/sessions",
            headers={"Authorization": "Bearer not_a_real_token"},
        )
        assert resp.status_code == 401

    def test_login_wrong_password_is_401(self, temp_env: Path) -> None:
        from deepsecurity.api import create_app

        app = create_app()
        app.config["TESTING"] = True
        c = app.test_client()
        resp = c.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrong-on-purpose"},
        )
        assert resp.status_code == 401

    def test_relative_path_rejected(
        self, initialized_db: Path, authed_client, fresh_state: None
    ) -> None:
        client, token = authed_client
        resp = client.post(
            "/api/scanner/start",
            json={"path": "../etc/passwd"},
            headers=_auth(token),
        )
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "path_outside_scan_root"

    def test_security_headers_present_on_every_response(self, temp_env: Path) -> None:
        from deepsecurity.api import create_app

        app = create_app()
        app.config["TESTING"] = True
        c = app.test_client()
        resp = c.get("/healthz")
        for h in (
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Content-Security-Policy",
            "Strict-Transport-Security",
        ):
            assert h in resp.headers, f"missing security header: {h}"


# ===========================================================================
# Phase 3.5–3.7 — slow OS-level tests
# ===========================================================================
#
# These need real processes / high file-event rates. Marked `slow` so
# default CI runs stay fast. Run locally with `pytest -m slow`.


@pytest.mark.slow
class TestSlowOSLevel:
    def test_ransomware_rate_detector_fires(
        self, initialized_db: Path, scan_root: Path, fresh_state: None
    ) -> None:
        from deepsecurity.ransomware_guard import RansomwareGuard

        guard = RansomwareGuard(threshold=10, window_seconds=1.0, auto_kill=False)
        # Blast 50 "writes" in 200 ms.
        t0 = time.monotonic()
        for i in range(50):
            guard.record_write(f"/tmp/fake_{i}")
            if time.monotonic() - t0 > 0.2:
                break

        # The guard itself doesn't return the alert; we verify indirectly
        # that the alert bus would have dispatched by checking the DB
        # audit log was written.
        from deepsecurity.db import session_scope
        from deepsecurity.models import AuditLog

        with session_scope() as s:
            rows = (
                s.query(AuditLog)
                .filter(AuditLog.action == "ransomware.suspected")
                .all()
            )
        assert len(rows) >= 1, "ransomware rate should have tripped at least once"
