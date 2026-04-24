"""SOC2 CC6.1 — Logical and physical access controls.

Covers: "The entity implements logical access security software,
infrastructure, and architectures over protected information assets to
protect them from security events to meet the entity's objectives."

For DEEPSecurity specifically, the relevant evidence is:
    - Who authenticated (successful + failed logins) during the window
    - Role assignments in effect
    - Route-level access denials from the JWT / role guard
    - Rate-limit denials (defence against brute force)
    - Every audited action attributable to a specific actor

Auditor's typical ask: "Show me who has admin access, when they used it,
and prove non-admins were refused admin routes."
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from deepsecurity.compliance import DateWindow
from deepsecurity.models import AuditLog


TEMPLATE_ID = "soc2-cc6-1"
TITLE = "SOC2 CC6.1 — Logical access controls"
CONTROL_REF = "AICPA Trust Services Criteria CC6.1"
DESCRIPTION = (
    "Evidence that authentication is enforced, role-based access is "
    "applied, and attempts by unauthenticated or under-privileged "
    "callers are refused. Drawn from the audit log."
)


def build(session: Session, window: DateWindow) -> dict[str, Any]:
    audit = (
        session.query(AuditLog)
        .filter(AuditLog.timestamp >= window.start)
        .filter(AuditLog.timestamp <= window.end)
        .all()
    )

    login_events = [a for a in audit if a.action == "auth.login"]
    login_ok = [a for a in login_events if a.status == "ok"]
    login_fail = [a for a in login_events if a.status != "ok"]

    # Denials = any audited action refused by role/route guard.
    denials = [a for a in audit if a.status in {"denied", "forbidden", "unauthorized"}]

    # Actor → event-count rollup for access review.
    by_actor: dict[str, int] = {}
    for a in audit:
        by_actor[a.actor or "unknown"] = by_actor.get(a.actor or "unknown", 0) + 1

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
        "authentication": {
            "total_login_attempts": len(login_events),
            "successful": len(login_ok),
            "failed": len(login_fail),
            "failure_rate": round(
                len(login_fail) / max(len(login_events), 1), 4
            ),
            "unique_actors_logged_in": len({a.actor for a in login_ok if a.actor}),
        },
        "access_denials": {
            "total": len(denials),
            "by_action": _group(denials, "action"),
            "by_actor": _group(denials, "actor"),
        },
        "actor_activity": dict(
            sorted(by_actor.items(), key=lambda kv: -kv[1])
        ),
        "note": (
            "DEEPSecurity does not manage the identity provider; user "
            "membership in groups/roles is enforced by whichever IdP "
            "issues the JWT. This report documents the decisions "
            "recorded at the DEEPSecurity boundary."
        ),
    }


def _group(rows: list, attr: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        k = str(getattr(r, attr) or "unknown")
        out[k] = out.get(k, 0) + 1
    return out
