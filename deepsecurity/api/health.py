"""Liveness + readiness probes + root discovery — unauthenticated.

Liveness (/healthz):
    Always 200 if the process is alive and serving requests.

Readiness (/readyz):
    200 only if DB is reachable AND scan_root exists. Otherwise 503.
    Containers use this to gate traffic.

Root (/):
    Tiny JSON directory so an operator hitting the API in a browser gets
    something helpful instead of a 404.
"""
from __future__ import annotations

from typing import Any

from flask import Blueprint, jsonify
from sqlalchemy import text

from deepsecurity import __version__
from deepsecurity.config import settings
from deepsecurity.db import get_engine

health_bp = Blueprint("health", __name__)


@health_bp.route("/", methods=["GET"])
def index() -> Any:
    return jsonify(
        {
            "service": "deepsecurity",
            "version": __version__,
            "tagline": (
                "User-space policy, DLP, and compliance overlay for endpoints. "
                "Runs alongside your AV — not a replacement. "
                "MITRE-tagged detections, SIEM-ready events, audit trails."
            ),
            "positioning": {
                "is": [
                    "policy + DLP overlay",
                    "MITRE ATT&CK-tagged detection",
                    "compliance audit trail",
                    "SIEM signal source",
                ],
                "is_not": [
                    "AV replacement (keep Defender on)",
                    "EDR (we don't hook the kernel)",
                    "network security product",
                    "self-protecting agent",
                ],
                "threat_model_doc": "docs/THREAT_MODEL.md",
            },
            "env": settings.env,
            "endpoints": {
                "health": "/healthz",
                "readiness": "/readyz",
                "metrics": "/metrics",
                "login": "POST /api/auth/login",
                "whoami": "GET /api/auth/whoami",
                "scanner": {
                    "start": "POST /api/scanner/start",
                    "status": "GET /api/scanner/status",
                    "cancel": "POST /api/scanner/cancel",
                    "sessions": "GET /api/scanner/sessions",
                    "results": "GET /api/scanner/results?session_id=...",
                },
                "quarantine": {
                    "list": "GET /api/quarantine/list",
                    "restore": "POST /api/quarantine/restore",
                    "delete": "POST /api/quarantine/delete",
                    "safelist": "POST /api/quarantine/safelist",
                },
                "dlp": "GET /api/dlp/findings",
                "watchdog": {
                    "status": "GET /api/watchdog/status",
                    "start": "POST /api/watchdog/start",
                    "stop": "POST /api/watchdog/stop",
                    "system_roots": "GET /api/watchdog/system-roots",
                },
                "intel_update": "POST /api/intel/update",
                "audit": "GET /api/audit",
                "compliance": {
                    "report": "GET /api/compliance/report?days=30",
                    "audit_csv": "GET /api/compliance/audit.csv?days=30",
                    "purge": "POST /api/compliance/purge",
                },
                "system": {
                    "summary": "GET /api/system/summary",
                    "top": "GET /api/system/top",
                },
                "network": {
                    "connections": "GET /api/network/connections",
                    "io": "GET /api/network/io",
                },
                "processes": "POST /api/processes/scan",
                "sinks": {
                    "status": "GET /api/sinks/status",
                    "test": "POST /api/sinks/test",
                },
                "agents": {
                    "list": "GET /api/agents  (operator)",
                    "enrol": "POST /api/agents/enrol  (operator)",
                    "register": "POST /api/agents/register  (agent enrolment)",
                    "heartbeat": "POST /api/agents/heartbeat  (agent)",
                    "commands": "GET /api/agents/commands  (agent)",
                    "results": "POST /api/agents/results  (agent)",
                    "events": "POST /api/agents/events  (agent)",
                    "queue": "POST /api/agents/<id>/commands  (operator)",
                    "revoke": "DELETE /api/agents/<id>  (operator)",
                },
            },
        }
    ), 200


@health_bp.route("/favicon.ico", methods=["GET"])
def favicon() -> Any:
    # 204 No Content — tells the browser to stop asking without a 404.
    return ("", 204)


@health_bp.route("/healthz", methods=["GET"])
def healthz() -> Any:
    return jsonify({"status": "ok"}), 200


@health_bp.route("/readyz", methods=["GET"])
def readyz() -> Any:
    checks: dict[str, str] = {}
    overall_ok = True

    # DB reachable?
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["database"] = f"error: {type(exc).__name__}"
        overall_ok = False

    # Scan root state — empty is fine (permissive mode, default).
    roots = settings.scan_roots
    if not roots:
        checks["scan_root"] = "permissive (any absolute path)"
    else:
        existing = [r for r in roots if r.exists()]
        missing = [r for r in roots if not r.exists()]
        if existing and not missing:
            checks["scan_root"] = f"restricted ({len(roots)} root(s))"
        elif existing:
            checks["scan_root"] = f"restricted ({len(existing)}/{len(roots)} roots exist)"
        else:
            checks["scan_root"] = f"restricted but all {len(roots)} configured roots missing"
            overall_ok = False

    return jsonify({"status": "ok" if overall_ok else "degraded", "checks": checks}), (
        200 if overall_ok else 503
    )
