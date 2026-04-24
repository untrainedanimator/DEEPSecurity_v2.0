"""Audit log viewer — query + paginate."""
from __future__ import annotations

from typing import Any

from flask import Blueprint, jsonify, request

from deepsecurity.api.auth import require_role
from deepsecurity.db import session_scope
from deepsecurity.models import AuditLog

audit_bp = Blueprint("audit", __name__)


@audit_bp.route("", methods=["GET"])
@require_role("admin", "security", "analyst")
def list_audit() -> Any:
    limit = min(int(request.args.get("limit", 100)), 1000)
    actor = request.args.get("actor")
    action = request.args.get("action")

    with session_scope() as s:
        q = s.query(AuditLog)
        if actor:
            q = q.filter(AuditLog.actor == actor)
        if action:
            q = q.filter(AuditLog.action == action)
        rows = q.order_by(AuditLog.timestamp.desc()).limit(limit).all()
        return jsonify(
            [
                {
                    "id": r.id,
                    "actor": r.actor,
                    "action": r.action,
                    "status": r.status,
                    "file_path": r.file_path,
                    "details": r.details,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                }
                for r in rows
            ]
        )
