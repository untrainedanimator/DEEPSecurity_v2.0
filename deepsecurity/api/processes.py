"""Running-process visibility + enforcement (user-space, not EDR)."""
from __future__ import annotations

from typing import Any

from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt

from deepsecurity.api.auth import require_role
from deepsecurity.audit import audit_log
from deepsecurity.config import settings
from deepsecurity.processes import kill_process, scan_all_processes

processes_bp = Blueprint("processes", __name__)


@processes_bp.route("/scan", methods=["POST"])
@require_role("admin", "security")
def scan() -> Any:
    """Scan every visible process. If DEEPSEC_AUTO_KILL_KNOWN_BAD is true,
    terminate each known_bad process and include the outcome per-row."""
    results = scan_all_processes(auto_kill_known_bad=settings.auto_kill_known_bad)

    flagged = [r for r in results if r["label"] != "clean"]
    for r in flagged:
        if "auto_kill_result" in r:
            # Already audit-logged by scan_all_processes.
            continue
        audit_log(
            actor="system",
            action="process.flagged",
            status=r["label"],
            file_path=r.get("exe"),
            details={
                "pid": r["pid"],
                "name": r["name"],
                "reasons": r["reasons"],
                "mitre_tags": r.get("mitre_tags", []),
                "cpu_percent": r["cpu_percent"],
            },
        )

    return jsonify(
        {
            "total": len(results),
            "known_bad": sum(1 for r in results if r["label"] == "known_bad"),
            "suspicious": sum(1 for r in results if r["label"] == "suspicious"),
            "auto_killed": sum(
                1 for r in results if r.get("auto_kill_result", {}).get("killed")
            ),
            "auto_kill_enabled": settings.auto_kill_known_bad,
            "processes": results,
        }
    )


@processes_bp.route("/kill", methods=["POST"])
@require_role("admin", "security")
def kill() -> Any:
    """Terminate a specific PID. Explicit, audit-logged, reason required.

    Body: {"pid": 1234, "reason": "analyst verdict: malware", "force": false}
    """
    data = request.get_json(silent=True) or {}
    pid = data.get("pid")
    reason = str(data.get("reason", "")).strip()
    force = bool(data.get("force", False))

    if not isinstance(pid, int) or pid <= 0:
        return jsonify({"error": "bad_param", "param": "pid"}), 400
    if not reason or len(reason) < 3:
        return jsonify({"error": "reason_required"}), 400

    actor = str(get_jwt().get("sub", "unknown"))
    result = kill_process(pid, force=force)
    audit_log(
        actor=actor,
        action="process.kill",
        status="ok" if result.get("killed") else "failed",
        details={"pid": pid, "reason": reason, "force": force, "result": result},
    )
    return jsonify(result), (200 if result.get("killed") else 400)
