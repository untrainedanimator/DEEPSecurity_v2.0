"""ISO/IEC 27001:2022 Annex A 12.4 — Logging and monitoring.

Covers: "Logs that record activities, exceptions, faults and other
relevant events shall be produced, stored, protected and analysed."

For DEEPSecurity, the evidence of adequate logging is:
    - Event volume during the window, by action and actor
    - Coverage of core action categories (auth, scan, quarantine, etc.)
    - Denial volume (the signal an attacker cares about suppressing)
    - Retention state (do logs older than the policy exist? they
      shouldn't, per `purge_older_than`)
    - Log destinations (DB + structured stdout + optional Syslog/CEF/SMTP)
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from deepsecurity.compliance import DateWindow
from deepsecurity.config import settings
from deepsecurity.models import AuditLog


TEMPLATE_ID = "iso27001-a-12-4"
TITLE = "ISO 27001 A.12.4 — Logging and monitoring"
CONTROL_REF = "ISO/IEC 27001:2022 Annex A 12.4"
DESCRIPTION = (
    "Audit-log volume and category breakdown for the window, plus the "
    "retention policy and enabled destinations. Covers the control's "
    "requirement that relevant events are produced, stored, and "
    "analysable."
)


_REQUIRED_CATEGORIES = {
    "auth.login",
    "scan.start",
    "scan.finish",
    "quarantine.copied",
    "quarantine.restored",
    "agent.enrolled",
    "agent.revoked",
    "watchdog.started",
}


def build(session: Session, window: DateWindow) -> dict[str, Any]:
    audit = (
        session.query(AuditLog)
        .filter(AuditLog.timestamp >= window.start)
        .filter(AuditLog.timestamp <= window.end)
        .all()
    )

    by_action: dict[str, int] = {}
    by_actor: dict[str, int] = {}
    denials = 0
    for a in audit:
        by_action[a.action] = by_action.get(a.action, 0) + 1
        by_actor[a.actor or "unknown"] = by_actor.get(a.actor or "unknown", 0) + 1
        if a.status in {"denied", "forbidden", "unauthorized"}:
            denials += 1

    coverage = {
        cat: by_action.get(cat, 0) for cat in _REQUIRED_CATEGORIES
    }
    categories_with_no_events = [k for k, v in coverage.items() if v == 0]

    # Retention: do events older than retention_days still exist?
    retention_check_cutoff = datetime.now(timezone.utc) - _relativedelta_days(
        settings.retention_days
    )
    # We use the session directly so the count reflects the live DB,
    # not just the window rows.
    stale_events = (
        session.query(AuditLog)
        .filter(AuditLog.timestamp < retention_check_cutoff)
        .count()
    )

    destinations = {
        "database": True,
        "structured_stdout": True,
        "syslog_rfc5424": bool(settings.syslog_host),
        "cef_over_syslog": bool(settings.cef_host),
        "slack_webhook": bool(settings.slack_webhook_url),
        "generic_webhook": bool(settings.alert_webhook_url),
        "smtp_email": bool(settings.smtp_host and settings.alert_email_to),
    }

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
        "volume": {
            "total_events": len(audit),
            "denials": denials,
            "by_action_top_20": dict(
                sorted(by_action.items(), key=lambda kv: -kv[1])[:20]
            ),
            "by_actor": by_actor,
        },
        "category_coverage": {
            "required": sorted(_REQUIRED_CATEGORIES),
            "counts": coverage,
            "categories_with_no_events_in_window": sorted(
                categories_with_no_events
            ),
        },
        "retention": {
            "policy_days": settings.retention_days,
            "events_older_than_policy_still_present": stale_events,
        },
        "log_destinations": destinations,
    }


def _relativedelta_days(days: int):  # noqa: ANN202
    from datetime import timedelta

    return timedelta(days=days)
