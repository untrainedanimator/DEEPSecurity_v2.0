"""HIPAA 45 CFR §164.312(a)(1) — Access control.

Required implementation specifications:
    (A) Unique user identification — assign each user a unique name/number
    (B) Emergency access procedure — workflow to obtain ePHI during emergencies
    (C) Automatic logoff — terminate sessions after predetermined inactivity
    (D) Encryption and decryption — encrypt ePHI at rest

For DEEPSecurity, the evidence is:
    - Unique identifiers in effect (the JWT `sub` claim; one role per
      session)
    - Session lifetime (`jwt_access_minutes`) → proxy for automatic logoff
    - Encryption-at-rest posture (the SQLite / Postgres DSN — we don't
      encrypt the DB ourselves; operators choose their storage backend)
    - Unique-actor count and role distribution in the audit log
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from deepsecurity.compliance import DateWindow
from deepsecurity.config import settings
from deepsecurity.models import AuditLog
from deepsecurity.secret_masking import mask_database_url


TEMPLATE_ID = "hipaa-164-312-a-1"
TITLE = "HIPAA §164.312(a)(1) — Access control"
CONTROL_REF = "45 CFR §164.312(a)(1)(i)–(iv)"
DESCRIPTION = (
    "Evidence for the four access-control implementation "
    "specifications: unique user identification (JWT sub), emergency "
    "access (documented out-of-band), automatic logoff (JWT expiry), "
    "and encryption/decryption posture (DB backend storage guarantees)."
)


def build(session: Session, window: DateWindow) -> dict[str, Any]:
    audit = (
        session.query(AuditLog)
        .filter(AuditLog.timestamp >= window.start)
        .filter(AuditLog.timestamp <= window.end)
        .all()
    )

    unique_actors = sorted({a.actor for a in audit if a.actor})
    by_actor_action: dict[str, dict[str, int]] = {}
    for a in audit:
        actor = a.actor or "unknown"
        by_actor_action.setdefault(actor, {})
        by_actor_action[actor][a.action] = (
            by_actor_action[actor].get(a.action, 0) + 1
        )

    db_url = settings.database_url or ""
    encryption_note: str
    if db_url.startswith("sqlite:"):
        encryption_note = (
            "SQLite file is not encrypted at rest by DEEPSecurity. "
            "For HIPAA compliance, deploy on a filesystem with "
            "encryption at rest (BitLocker, LUKS, or equivalent), "
            "or migrate to Postgres with pgcrypto / TDE."
        )
    elif "postgres" in db_url:
        encryption_note = (
            "Postgres backend. Encryption at rest is the responsibility "
            "of the database host — enable TDE / pgcrypto / disk-level "
            "encryption as appropriate and document the choice."
        )
    else:
        encryption_note = (
            f"Unknown backend: {db_url[:20]}... — operator must document "
            "encryption-at-rest posture separately."
        )

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
        "unique_user_identification": {
            "mechanism": "JWT sub claim",
            "unique_actors_in_window": len(unique_actors),
            "actors": unique_actors,
            "by_actor_activity": by_actor_action,
        },
        "emergency_access_procedure": {
            "in_product_implementation": "none (out-of-scope)",
            "note": (
                "DEEPSecurity does not provide a break-glass workflow. "
                "Operators must document their emergency-access procedure "
                "separately, including who may issue tokens and how "
                "activity during emergencies is reviewed."
            ),
        },
        "automatic_logoff": {
            "mechanism": "JWT expiry",
            "jwt_access_minutes": settings.jwt_access_minutes,
            "note": (
                "Tokens expire after the configured access minutes. "
                "There is no server-side session to invalidate; a stolen "
                "token is good until its expiry. For shorter logoff, "
                "reduce jwt_access_minutes."
            ),
        },
        "encryption_and_decryption": {
            "database_url_masked": mask_database_url(db_url),
            "note": encryption_note,
        },
    }
