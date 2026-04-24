"""Threat-intel feed refresh."""
from __future__ import annotations

from typing import Any

from flask import Blueprint, jsonify, request

from deepsecurity.api.auth import require_role
from deepsecurity.threat_intel import update_all_feeds

intel_bp = Blueprint("intel", __name__)


@intel_bp.route("/update", methods=["POST"])
@require_role("admin")
def update() -> Any:
    # Optional OTX pulses provided in the POST body.
    body = request.get_json(silent=True) or {}
    pulses = [
        (p["pulse_id"], p["api_key"])
        for p in body.get("otx_pulses", [])
        if isinstance(p, dict) and "pulse_id" in p and "api_key" in p
    ]
    results = update_all_feeds(pulses or None)
    return jsonify(
        [
            {
                "feed": r.name,
                "fetched": r.fetched,
                "added": r.added,
                "skipped": r.skipped,
                "error": r.error,
            }
            for r in results
        ]
    )
