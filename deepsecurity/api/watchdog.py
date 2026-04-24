"""Watchdog start/stop/status."""
from __future__ import annotations

from typing import Any

from flask import Blueprint, jsonify, request

from deepsecurity.api.auth import require_role
from deepsecurity.watchdog_monitor import controller

watchdog_bp = Blueprint("watchdog", __name__)


@watchdog_bp.route("/status", methods=["GET"])
@require_role("admin", "security", "analyst")
def status() -> Any:
    return jsonify(
        {
            "available": controller.available,
            "running": controller.running,
            "watching": controller.watching,
        }
    )


@watchdog_bp.route("/start", methods=["POST"])
@require_role("admin", "security")
def start() -> Any:
    """Start watching.

    Body options (any ONE):
      {"scope": "user_risk"}                    — Downloads, Desktop, Documents,
                                                   Outlook cache, %TEMP%
                                                   (recommended default)
      {"scope": "system"}                       — every drive / every common
                                                   user path (high volume)
      {"paths": ["C:\\\\Apps\\\\Imgs2", "D:\\\\"]} — explicit multi-path
      {"path":  "/home/dino/Downloads"}         — single-path shorthand
      {}                                        — fall back to DEEPSEC_SCAN_ROOT
    """
    data = request.get_json(silent=True) or {}
    scope = data.get("scope")
    paths: list[str] | None = None
    if isinstance(data.get("paths"), list):
        paths = [str(p) for p in data["paths"]]
    elif data.get("path"):
        paths = [str(data["path"])]

    valid_scopes = {"system", "user_risk"}
    result = controller.start(
        paths, scope=scope if scope in valid_scopes else None
    )
    code = 200 if result.get("started") else 400
    return jsonify(result), code


@watchdog_bp.route("/system-roots", methods=["GET"])
@require_role("admin", "security", "analyst")
def system_roots() -> Any:
    """Preview every scope preset and what it resolves to on this host."""
    from deepsecurity.watchdog_monitor import (
        default_system_roots,
        default_user_risk_roots,
    )

    return jsonify(
        {
            "scopes": {
                "user_risk": {
                    "label": "user-risk paths (recommended)",
                    "description": (
                        "Downloads, Desktop, Documents, Outlook cache, %TEMP%. "
                        "Where malware and policy violations actually land."
                    ),
                    "paths": [str(p) for p in default_user_risk_roots()],
                },
                "system": {
                    "label": "whole system",
                    "description": (
                        "Every attached drive (Windows) / every common user "
                        "path (Unix). Broad coverage, high event volume."
                    ),
                    "paths": [str(p) for p in default_system_roots()],
                },
            },
            # Legacy field — existing UI versions still read this.
            "paths": [str(p) for p in default_system_roots()],
        }
    )


@watchdog_bp.route("/stop", methods=["POST"])
@require_role("admin", "security")
def stop() -> Any:
    return jsonify(controller.stop())
