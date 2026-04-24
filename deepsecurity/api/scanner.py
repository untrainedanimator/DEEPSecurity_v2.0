"""Scanner routes.

All paths coming in from the client go through resolve_under_root() — no
bare OS calls on untrusted strings. All actions are audit-logged.
"""
from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any

import psutil
from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt

from deepsecurity.api.auth import require_role
from deepsecurity.audit import audit_log
from deepsecurity.config import settings
from deepsecurity.db import session_scope
from deepsecurity.logging_config import get_logger
from deepsecurity.models import ScanResult, ScanSession
from deepsecurity.paths import resolve_under_root
from deepsecurity.scan_state import state
from deepsecurity.scanner import scan_directory

_log = get_logger(__name__)
scanner_bp = Blueprint("scanner", __name__)


def _normalize_user_path(raw: str) -> str:
    """Clean up a user-entered path before resolution.

    Handles the common mistakes we see when people paste paths into a web
    form: leading/trailing whitespace, surrounding quotes, bare drive
    letters on Windows, Windows paths with forward slashes.
    """
    p = raw.strip()
    # Strip one level of matched surrounding quotes ("C:\Apps" → C:\Apps).
    if len(p) >= 2 and p[0] == p[-1] and p[0] in ('"', "'"):
        p = p[1:-1].strip()
    # "C" or "C:" → "C:\\" on Windows so it points at the drive root rather
    # than the "current directory on C:".
    if os.name == "nt":
        if len(p) == 1 and p.isalpha():
            p = f"{p.upper()}:\\"
        elif len(p) == 2 and p[0].isalpha() and p[1] == ":":
            p = f"{p.upper()}\\"
    return p


def _path_not_found_hint(target: Path, original: str) -> str:
    """Give the user something actionable when their path doesn't exist."""
    if os.name == "nt":
        # Drive root missing → bad drive letter.
        anchor = Path(target.anchor) if target.anchor else None
        if anchor is not None and str(anchor) and not anchor.exists():
            return (
                f"drive {anchor} does not exist — check the letter "
                f"(was: {original!r})"
            )
    if target.parent.exists() and target.parent != target:
        return (
            f"parent directory exists ({target.parent}) but {target.name!r} "
            f"is not inside it — check spelling and case"
        )
    return (
        f"path {target} does not exist. paste the full absolute path "
        f"and make sure there are no trailing spaces or quotes"
    )


@scanner_bp.route("/start", methods=["POST"])
@require_role("admin", "security")
def start_scan() -> Any:
    claims = get_jwt()
    actor = str(claims.get("sub", "unknown"))
    role = str(claims.get("role", ""))

    data = request.get_json(silent=True) or {}
    raw_input = str(data.get("path", settings.scan_root))
    raw_path = _normalize_user_path(raw_input)
    quarantine_enabled = bool(data.get("quarantine", True))

    if not raw_path:
        return (
            jsonify(
                {
                    "error": "missing_path",
                    "message": "provide an absolute path in the `path` field",
                }
            ),
            400,
        )

    target = resolve_under_root(raw_path, settings.scan_roots)
    if not target.exists():
        return (
            jsonify(
                {
                    "error": "path_not_found",
                    "path": str(target),
                    "input": raw_input,
                    "normalized": raw_path,
                    "message": _path_not_found_hint(target, raw_input),
                }
            ),
            404,
        )
    # Need read access to actually scan.
    if not os.access(str(target), os.R_OK):
        return (
            jsonify(
                {
                    "error": "permission_denied",
                    "path": str(target),
                    "message": (
                        f"no read access to {target} — try running "
                        f"DEEPSecurity as administrator or pick a path your "
                        f"user owns"
                    ),
                }
            ),
            403,
        )

    if state.snapshot()["running"]:
        return jsonify({"status": "already_running"}), 409

    def _worker() -> None:
        try:
            scan_directory(
                target,
                actor=actor,
                user_role=role,
                quarantine_enabled=quarantine_enabled,
            )
        except Exception:
            _log.exception("scan.worker_failed")

    threading.Thread(target=_worker, daemon=True, name="deepsec-scan").start()

    return jsonify({"status": "started", "path": str(target)}), 202


@scanner_bp.route("/status", methods=["GET"])
def status() -> Any:
    snap = state.snapshot()
    snap_out: dict[str, Any] = {**snap}

    # Per-process metrics — this is what's FAIR to attribute to DEEPSecurity.
    try:
        proc = psutil.Process(os.getpid())
        proc_cpu = proc.cpu_percent(interval=0.0)
        mem = proc.memory_info()
        snap_out["process"] = {
            "cpu_percent": round(float(proc_cpu), 2),
            "rss_mb": round(mem.rss / (1024 * 1024), 1),
        }
    except Exception:
        snap_out["process"] = {"cpu_percent": 0.0, "rss_mb": 0.0}

    # System-wide metrics — provided as context, NOT as our utilisation.
    snap_out["system"] = {
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "ram_percent": psutil.virtual_memory().percent,
    }

    # Keep the old fields for backward compatibility; they're the system ones.
    snap_out["cpu"] = snap_out["system"]["cpu_percent"]
    snap_out["ram"] = snap_out["system"]["ram_percent"]

    progress = (
        int((snap["scanned_count"] / snap["total_files"]) * 100)
        if snap["total_files"]
        else 0
    )
    snap_out["progress_percent"] = progress
    return jsonify(snap_out), 200


@scanner_bp.route("/cancel", methods=["POST"])
@require_role("admin", "security")
def cancel() -> Any:
    state.cancel()
    audit_log(actor=str(get_jwt().get("sub", "unknown")), action="scan.cancel_requested")
    return jsonify({"status": "cancelling"}), 202


@scanner_bp.route("/sessions", methods=["GET"])
@require_role("admin", "security", "analyst")
def list_sessions() -> Any:
    limit = min(int(request.args.get("limit", 25)), 200)
    with session_scope() as s:
        rows = (
            s.query(ScanSession)
            .order_by(ScanSession.started_at.desc())
            .limit(limit)
            .all()
        )
        return jsonify(
            [
                {
                    "id": r.id,
                    "actor": r.actor,
                    "status": r.status,
                    "scan_root": r.scan_root,
                    "total_files": r.total_files,
                    "total_detections": r.total_detections,
                    "started_at": r.started_at.isoformat() if r.started_at else None,
                    "ended_at": r.ended_at.isoformat() if r.ended_at else None,
                }
                for r in rows
            ]
        )


@scanner_bp.route("/results", methods=["GET"])
@require_role("admin", "security", "analyst")
def list_results() -> Any:
    sid_raw = request.args.get("session_id")
    if not sid_raw:
        return jsonify({"error": "missing_param", "param": "session_id"}), 400
    try:
        session_id = int(sid_raw)
    except ValueError:
        return jsonify({"error": "bad_param", "param": "session_id"}), 400

    limit = min(int(request.args.get("limit", 500)), 5000)
    label_filter = request.args.get("label")  # "malicious" | "suspicious" | "clean"

    with session_scope() as s:
        q = s.query(ScanResult).filter(ScanResult.session_id == session_id)
        if label_filter:
            q = q.filter(ScanResult.label == label_filter)
        rows = q.order_by(ScanResult.detected_at.desc()).limit(limit).all()
        return jsonify(
            [
                {
                    "id": r.id,
                    "file_path": r.file_path,
                    "sha256": r.sha256,
                    "label": r.label,
                    "confidence": r.ml_confidence,
                    "anomaly_score": r.anomaly_score,
                    "entropy": r.entropy,
                    "file_status": r.file_status,
                    "reason": r.detection_reason,
                    "quarantine_path": r.quarantine_path,
                    "detected_at": r.detected_at.isoformat() if r.detected_at else None,
                }
                for r in rows
            ]
        )
