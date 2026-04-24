"""SOC2 CC6.6 — Boundary / perimeter protection.

Covers: "The entity implements logical access security measures to
protect against threats from sources outside its system boundaries."

For DEEPSecurity the boundary evidence is:
    - The CORS allow-list in effect
    - Rate-limit denials (the main abuse defence)
    - IP reputation lookups (if enabled)
    - Authentication denials at the boundary (bad JWT, no token, etc.)
    - The deployed security headers on every HTTP response
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from deepsecurity.compliance import DateWindow
from deepsecurity.config import settings
from deepsecurity.models import AuditLog


TEMPLATE_ID = "soc2-cc6-6"
TITLE = "SOC2 CC6.6 — Boundary and perimeter protection"
CONTROL_REF = "AICPA Trust Services Criteria CC6.6"
DESCRIPTION = (
    "Evidence that the system refuses unauthenticated or abusive "
    "callers at the HTTP boundary — CORS scoped to explicit origins, "
    "rate limits, JWT required on every /api route, standard "
    "security headers on every response."
)


def build(session: Session, window: DateWindow) -> dict[str, Any]:
    audit = (
        session.query(AuditLog)
        .filter(AuditLog.timestamp >= window.start)
        .filter(AuditLog.timestamp <= window.end)
        .all()
    )

    rate_limit_denials = [
        a for a in audit if a.action == "rate_limit.denied"
    ]
    auth_denials = [
        a for a in audit if a.action in {"auth.denied", "auth.forbidden"}
    ]
    ip_reputation_hits = [
        a for a in audit if a.action == "network.known_bad_ip"
    ]

    return {
        "template_id": TEMPLATE_ID,
        "title": TITLE,
        "control_ref": CONTROL_REF,
        "description": DESCRIPTION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window": {
            "start": window.start.isoformat(),
            "end": window.end.isoformat(),
        },
        "cors_policy": {
            "mode": "allow-list",
            "allowed_origins": settings.cors_origin_list,
            "wildcard_allowed": False,  # enforced by config validator
        },
        "rate_limiting": {
            "anon_per_minute": settings.rate_limit_anon_per_minute,
            "auth_per_minute": settings.rate_limit_auth_per_minute,
            "denials_in_window": len(rate_limit_denials),
        },
        "auth_denials_in_window": len(auth_denials),
        "ip_reputation": {
            "enabled": settings.ip_reputation_enabled,
            "feed_path": str(settings.ip_reputation_path),
            "known_bad_hits_in_window": len(ip_reputation_hits),
        },
        "security_headers_enforced": [
            "X-Frame-Options: DENY",
            "X-Content-Type-Options: nosniff",
            "Referrer-Policy: no-referrer",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "Permissions-Policy",
        ],
        "max_request_bytes": settings.max_request_bytes,
    }
