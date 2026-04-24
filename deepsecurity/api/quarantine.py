"""Quarantine review endpoints — list, restore, delete.

Restore and delete are privileged: admin or security role only.
Every action writes to the audit log with actor + file + reason.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt

from deepsecurity.api.auth import require_role
from deepsecurity.audit import audit_log
from deepsecurity.config import settings
from deepsecurity.db import session_scope
from deepsecurity.models import SafeListEntry
from deepsecurity.paths import resolve_under_root
from deepsecurity.scanner import compute_sha256, restore_from_quarantine

quarantine_bp = Blueprint("quarantine", __name__)


@quarantine_bp.route("/list", methods=["GET"])
@require_role("admin", "security", "analyst")
def list_quarantined() -> Any:
    qdir = settings.quarantine_dir
    if not qdir.exists():
        return jsonify({"entries": []}), 200

    entries = []
    for p in sorted(qdir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if not p.is_file():
            continue
        st = p.stat()
        entries.append(
            {
                "name": p.name,
                "size_bytes": st.st_size,
                "mtime": st.st_mtime,
            }
        )
    return jsonify({"entries": entries}), 200


@quarantine_bp.route("/restore", methods=["POST"])
@require_role("admin", "security")
def restore() -> Any:
    data = request.get_json(silent=True) or {}
    qname = str(data.get("name", ""))
    original_raw = str(data.get("original_path", ""))
    if not qname or not original_raw:
        return jsonify({"error": "missing_fields", "required": ["name", "original_path"]}), 400

    qpath = settings.quarantine_dir / qname
    # Restore target must still be inside one of the allowed scan roots.
    original = resolve_under_root(original_raw, settings.scan_roots)

    actor = str(get_jwt().get("sub", "unknown"))
    ok = restore_from_quarantine(qpath, original)
    audit_log(
        actor=actor,
        action="quarantine.restore",
        status="ok" if ok else "failed",
        file_path=original,
        details={"quarantine_name": qname},
    )
    if not ok:
        return jsonify({"restored": False, "reason": "missing_or_io_error"}), 404

    return jsonify({"restored": True, "path": str(original)}), 200


@quarantine_bp.route("/delete", methods=["POST"])
@require_role("admin")
def delete_quarantined() -> Any:
    """Permanently delete a quarantined copy. Admin-only."""
    data = request.get_json(silent=True) or {}
    qname = str(data.get("name", ""))
    reason = str(data.get("reason", "")).strip()
    if not qname:
        return jsonify({"error": "missing_fields", "required": ["name"]}), 400
    if not reason or len(reason) < 3:
        return jsonify({"error": "reason_required"}), 400

    qpath = settings.quarantine_dir / qname
    if not qpath.exists():
        return jsonify({"deleted": False, "reason": "not_found"}), 404

    actor = str(get_jwt().get("sub", "unknown"))
    sha = compute_sha256(qpath)
    qpath.unlink()
    audit_log(
        actor=actor,
        action="quarantine.delete",
        status="ok",
        file_path=qpath,
        details={"sha256": sha, "reason": reason},
    )
    return jsonify({"deleted": True, "sha256": sha}), 200


@quarantine_bp.route("/restore-session", methods=["POST"])
@require_role("admin", "security")
def restore_session() -> Any:
    """Bulk-restore every quarantined file from a scan session (session rollback).

    For each `ScanResult` row with file_status='quarantined' and a non-null
    quarantine_path, move the quarantine copy back to the original file_path.
    Misses (already-restored, moved elsewhere) are counted, not failed-on.
    """
    from flask_jwt_extended import get_jwt

    from deepsecurity.db import session_scope as db_session
    from deepsecurity.models import ScanResult
    from deepsecurity.scanner import restore_from_quarantine

    data = request.get_json(silent=True) or {}
    raw_sid = data.get("session_id")
    if raw_sid is None:
        return jsonify({"error": "missing_param", "param": "session_id"}), 400
    try:
        session_id = int(raw_sid)
    except (TypeError, ValueError):
        return jsonify({"error": "bad_param", "param": "session_id"}), 400

    actor = str(get_jwt().get("sub", "unknown"))
    restored = 0
    missing = 0
    failed = 0
    details: list[dict[str, Any]] = []

    with db_session() as s:
        rows = (
            s.query(ScanResult)
            .filter(ScanResult.session_id == session_id)
            .filter(ScanResult.file_status == "quarantined")
            .all()
        )
        for r in rows:
            if not r.quarantine_path:
                missing += 1
                continue
            qp = Path(r.quarantine_path)
            original = Path(r.file_path)
            if not qp.exists():
                missing += 1
                details.append({"file": str(original), "status": "missing_in_quarantine"})
                continue
            try:
                ok = restore_from_quarantine(qp, original)
                if ok:
                    restored += 1
                    r.file_status = "restored"
                    details.append({"file": str(original), "status": "restored"})
                else:
                    failed += 1
                    details.append({"file": str(original), "status": "failed"})
            except Exception:
                failed += 1
                details.append({"file": str(original), "status": "failed"})

    audit_log(
        actor=actor,
        action="quarantine.restore_session",
        status="ok" if failed == 0 else "partial",
        details={
            "session_id": session_id,
            "restored": restored,
            "missing": missing,
            "failed": failed,
        },
    )
    return jsonify(
        {"session_id": session_id, "restored": restored, "missing": missing,
         "failed": failed, "items": details}
    )


@quarantine_bp.route("/safelist", methods=["POST"])
@require_role("admin", "security")
def add_to_safelist() -> Any:
    """Add a file hash to the safelist so future scans don't flag it."""
    data = request.get_json(silent=True) or {}
    sha = str(data.get("sha256", "")).lower()
    path_raw = str(data.get("file_path", ""))
    if len(sha) != 64 or not path_raw:
        return jsonify({"error": "bad_fields"}), 400

    # Path must still be inside one of the allowed scan roots.
    file_path = resolve_under_root(path_raw, settings.scan_roots)

    actor = str(get_jwt().get("sub", "unknown"))
    with session_scope() as s:
        s.add(
            SafeListEntry(
                file_hash=sha,
                file_path=str(file_path),
                action="safelist",
                actor=actor,
            )
        )
    audit_log(actor=actor, action="quarantine.safelist", file_path=file_path, details={"sha256": sha})
    return jsonify({"added": True}), 201
