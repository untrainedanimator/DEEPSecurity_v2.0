"""SOC2 CC7.1 — Threat detection and response.

Covers: "To meet its objectives, the entity uses detection and
monitoring procedures to identify (1) changes to configurations that
result in the introduction of new vulnerabilities, and (2) the
susceptibility to newly discovered vulnerabilities."

For DEEPSecurity, the monitoring evidence is:
    - Scan sessions run during the window
    - Detections by label / reason / MITRE tag
    - DLP findings by severity
    - Watchdog coverage (what's being watched right now)
    - Integrity check status (tamper-awareness of our own binaries)
    - Ransomware rate detector state
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from deepsecurity.compliance import DateWindow
from deepsecurity.config import settings
from deepsecurity.models import AuditLog, DLPFinding, ScanResult, ScanSession


TEMPLATE_ID = "soc2-cc7-1"
TITLE = "SOC2 CC7.1 — Threat detection and monitoring"
CONTROL_REF = "AICPA Trust Services Criteria CC7.1"
DESCRIPTION = (
    "Evidence that continuous monitoring is in place: scans executed, "
    "detections generated, DLP findings captured, file-system watchdog "
    "active. Every detection carries MITRE ATT&CK technique tags for "
    "downstream triage."
)


def build(session: Session, window: DateWindow) -> dict[str, Any]:
    # Scans in window
    scan_sessions = (
        session.query(ScanSession)
        .filter(ScanSession.started_at >= window.start)
        .filter(ScanSession.started_at <= window.end)
        .all()
    )

    # Detections — labels + reasons (reasons live as a stringified list
    # in ScanResult.detection_reason; we count occurrences of key phrases)
    label_counts = dict(
        session.query(ScanResult.label, func.count(ScanResult.id))
        .join(ScanSession, ScanSession.id == ScanResult.session_id)
        .filter(ScanSession.started_at >= window.start)
        .filter(ScanSession.started_at <= window.end)
        .group_by(ScanResult.label)
        .all()
    )

    results = (
        session.query(ScanResult)
        .join(ScanSession, ScanSession.id == ScanResult.session_id)
        .filter(ScanSession.started_at >= window.start)
        .filter(ScanSession.started_at <= window.end)
        .all()
    )
    reason_tally: dict[str, int] = {}
    for r in results:
        reason_txt = str(r.detection_reason or "").lower()
        for reason_key in (
            "signature_match",
            "entropy_spike",
            "yara",
            "ml_malicious",
        ):
            if reason_key in reason_txt:
                reason_tally[reason_key] = reason_tally.get(reason_key, 0) + 1

    # DLP findings in window (join to ScanSession for time window)
    dlp_findings = (
        session.query(DLPFinding)
        .join(ScanSession, ScanSession.id == DLPFinding.session_id)
        .filter(ScanSession.started_at >= window.start)
        .filter(ScanSession.started_at <= window.end)
        .all()
    )
    dlp_by_severity: dict[str, int] = {}
    for d in dlp_findings:
        dlp_by_severity[d.severity] = dlp_by_severity.get(d.severity, 0) + 1

    # Ransomware guard activity
    audit = (
        session.query(AuditLog)
        .filter(AuditLog.timestamp >= window.start)
        .filter(AuditLog.timestamp <= window.end)
        .all()
    )
    ransomware_alerts = [
        a for a in audit if a.action == "ransomware.suspected"
    ]
    integrity_alerts = [
        a for a in audit if a.action.startswith("integrity.")
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
        "scans": {
            "sessions_run": len(scan_sessions),
            "by_actor": _group(scan_sessions, "actor"),
            "by_status": _group(scan_sessions, "status"),
        },
        "detections": {
            "by_label": label_counts,
            "by_reason_keyword": reason_tally,
            "total": sum(label_counts.values()),
        },
        "dlp": {
            "findings_total": len(dlp_findings),
            "by_severity": dlp_by_severity,
        },
        "realtime_monitoring": {
            "watchdog_autostart": settings.watchdog_autostart,
            "watching_scope": settings.watchdog_autostart or "manual",
            "ransomware_rate_threshold_per_window": settings.ransomware_rate_threshold,
            "ransomware_rate_window_seconds": settings.ransomware_rate_window_seconds,
            "alerts_in_window": {
                "ransomware_suspected": len(ransomware_alerts),
                "integrity_events": len(integrity_alerts),
            },
        },
        "self_protection": {
            "integrity_check_on_boot": settings.integrity_check_on_boot,
            "integrity_snapshot_path": str(settings.integrity_snapshot_path),
        },
    }


def _group(rows: list, attr: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        k = str(getattr(r, attr) or "unknown")
        out[k] = out.get(k, 0) + 1
    return out
