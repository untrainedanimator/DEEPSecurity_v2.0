"""DLP findings browser + filter. Enriches rows with MITRE ATT&CK tags."""
from __future__ import annotations

from typing import Any

from flask import Blueprint, jsonify, request

from deepsecurity.api.auth import require_role
from deepsecurity.db import session_scope
from deepsecurity.mitre import tags_for_dlp_pattern
from deepsecurity.models import DLPFinding

dlp_bp = Blueprint("dlp", __name__)


@dlp_bp.route("/findings", methods=["GET"])
@require_role("admin", "security", "analyst")
def findings() -> Any:
    limit = min(int(request.args.get("limit", 200)), 2000)
    severity = request.args.get("severity")
    session_id = request.args.get("session_id")

    with session_scope() as s:
        q = s.query(DLPFinding)
        if severity:
            q = q.filter(DLPFinding.severity == severity)
        if session_id:
            try:
                q = q.filter(DLPFinding.session_id == int(session_id))
            except ValueError:
                return jsonify({"error": "bad_param", "param": "session_id"}), 400
        rows = q.order_by(DLPFinding.detected_at.desc()).limit(limit).all()
        return jsonify(
            [
                {
                    "id": r.id,
                    "session_id": r.session_id,
                    "file_path": r.file_path,
                    "pattern": r.pattern_name,
                    "severity": r.severity,
                    "line": r.line_number,
                    "preview": r.redacted_preview,
                    "mitre_tags": tags_for_dlp_pattern(r.pattern_name),
                    "detected_at": r.detected_at.isoformat() if r.detected_at else None,
                }
                for r in rows
            ]
        )
