"""Compliance reporting — GDPR/HIPAA/ISO-style evidence pack.

Generates a point-in-time report covering:
    - Scans executed in a date range, by status and actor
    - Detections by label (clean / suspicious / malicious)
    - DLP findings by severity (PII / secrets)
    - Audit events by actor (access review)
    - Quarantine lifecycle (created, restored, deleted)
    - Data retention status: events older than retention_days

Output:
    - JSON (machine-readable, audit-friendly)
    - CSV per section (spreadsheet-friendly; streamable)

Not included by design: raw file contents. DLP previews are already redacted.
"""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func

from deepsecurity.db import session_scope
from deepsecurity.models import AuditLog, ScanResult, ScanSession


@dataclass
class DateWindow:
    start: datetime
    end: datetime

    @classmethod
    def last_days(cls, days: int) -> "DateWindow":
        now = datetime.now(timezone.utc)
        return cls(start=now - timedelta(days=days), end=now)


def generate_report(window: DateWindow) -> dict[str, Any]:
    """Build a JSON-ready report dict for the window."""
    with session_scope() as s:
        # Scans in window
        scans = (
            s.query(ScanSession)
            .filter(ScanSession.started_at >= window.start)
            .filter(ScanSession.started_at <= window.end)
            .all()
        )
        scans_summary = {
            "total": len(scans),
            "by_status": _count_by(scans, lambda r: r.status),
            "by_actor": _count_by(scans, lambda r: r.actor),
        }

        # Detection labels
        label_counts = dict(
            s.query(ScanResult.label, func.count(ScanResult.id))
            .join(ScanSession, ScanSession.id == ScanResult.session_id)
            .filter(ScanSession.started_at >= window.start)
            .filter(ScanSession.started_at <= window.end)
            .group_by(ScanResult.label)
            .all()
        )

        # Audit events
        audit_rows = (
            s.query(AuditLog)
            .filter(AuditLog.timestamp >= window.start)
            .filter(AuditLog.timestamp <= window.end)
            .all()
        )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window": {"start": window.start.isoformat(), "end": window.end.isoformat()},
        "scans": scans_summary,
        "detections": {
            "by_label": label_counts,
            "total": sum(label_counts.values()),
        },
        "quarantine": {
            "actions": _count_by(
                [a for a in audit_rows if a.action.startswith("quarantine.")],
                lambda r: r.action,
            ),
        },
        "audit": {
            "total_events": len(audit_rows),
            "by_action": _count_by(audit_rows, lambda r: r.action),
            "by_actor": _count_by(audit_rows, lambda r: r.actor),
            "denials": sum(1 for a in audit_rows if a.status == "denied"),
        },
        "retention": {
            "policy_days": 90,
            "oldest_event": min((a.timestamp for a in audit_rows), default=None),
        },
    }


def _count_by(rows: list, key: Any) -> dict[str, int]:
    buckets: dict[str, int] = {}
    for r in rows:
        k = str(key(r)) if callable(key) else str(key)
        buckets[k] = buckets.get(k, 0) + 1
    return buckets


def audit_csv_export(window: DateWindow) -> str:
    """Stream-able CSV of the audit log for the window. Returns text."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp", "actor", "action", "status", "file_path", "details"])
    with session_scope() as s:
        rows = (
            s.query(AuditLog)
            .filter(AuditLog.timestamp >= window.start)
            .filter(AuditLog.timestamp <= window.end)
            .order_by(AuditLog.timestamp.asc())
            .all()
        )
        for r in rows:
            w.writerow(
                [
                    r.timestamp.isoformat() if r.timestamp else "",
                    r.actor,
                    r.action,
                    r.status,
                    r.file_path or "",
                    r.details or "",
                ]
            )
    return buf.getvalue()


def purge_older_than(days: int) -> dict[str, int]:
    """Delete audit / result rows older than `days`. Returns deleted counts."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    with session_scope() as s:
        n_audit = (
            s.query(AuditLog).filter(AuditLog.timestamp < cutoff).delete(synchronize_session=False)
        )
        n_results = (
            s.query(ScanResult)
            .filter(ScanResult.detected_at < cutoff)
            .delete(synchronize_session=False)
        )
        n_sessions = (
            s.query(ScanSession)
            .filter(ScanSession.started_at < cutoff)
            .delete(synchronize_session=False)
        )
    return {
        "audit_deleted": int(n_audit),
        "results_deleted": int(n_results),
        "sessions_deleted": int(n_sessions),
    }
