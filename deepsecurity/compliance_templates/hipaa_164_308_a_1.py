"""HIPAA 45 CFR §164.308(a)(1) — Security management process.

Covers: "Implement policies and procedures to prevent, detect, contain,
and correct security violations."

Key implementation specifications in this section:
    (A) Risk Analysis — identify risks to ePHI
    (B) Risk Management — reduce risks to reasonable & appropriate level
    (C) Sanction Policy — log actions taken against workforce who fail
    (D) Information System Activity Review — log review cadence

For DEEPSecurity, the evidence is:
    - Risk signals in the window (detections, DLP findings touching
      folders that could hold ePHI)
    - Response actions (quarantine, auto-kill, agent revocation)
    - Review cadence (is the operator actually reading the audit log?
      we can't measure that directly but we can report the volume they
      would need to review)
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from deepsecurity.compliance import DateWindow
from deepsecurity.models import AuditLog, DLPFinding, ScanResult, ScanSession


TEMPLATE_ID = "hipaa-164-308-a-1"
TITLE = "HIPAA §164.308(a)(1) — Security management process"
CONTROL_REF = "45 CFR §164.308(a)(1)(ii)(A)–(D)"
DESCRIPTION = (
    "Evidence of risk identification and response: the detections and "
    "DLP findings that flagged potential ePHI exposure in the window, "
    "and the containment actions (quarantine, auto-kill, revocation) "
    "taken in response. Volume of audit events is reported as a proxy "
    "for the information-system-activity-review workload."
)


# Heuristic: paths with these tokens are plausible ePHI repositories.
# Operators should override this list via a future settings knob; for
# now we use a conservative default that captures the common shapes.
_PHI_PATH_MARKERS = (
    "patient",
    "ehr",
    "emr",
    "medical",
    "health",
    "phi",
    "icd",
    "hospital",
)


def build(session: Session, window: DateWindow) -> dict[str, Any]:
    detections = (
        session.query(ScanResult)
        .join(ScanSession, ScanSession.id == ScanResult.session_id)
        .filter(ScanSession.started_at >= window.start)
        .filter(ScanSession.started_at <= window.end)
        .filter(ScanResult.label != "clean")
        .all()
    )

    dlp_findings = (
        session.query(DLPFinding)
        .join(ScanSession, ScanSession.id == DLPFinding.session_id)
        .filter(ScanSession.started_at >= window.start)
        .filter(ScanSession.started_at <= window.end)
        .all()
    )

    def _is_phi_path(p: str) -> bool:
        lp = (p or "").lower()
        return any(m in lp for m in _PHI_PATH_MARKERS)

    phi_detections = [d for d in detections if _is_phi_path(d.file_path)]
    phi_dlp = [d for d in dlp_findings if _is_phi_path(d.file_path)]

    audit = (
        session.query(AuditLog)
        .filter(AuditLog.timestamp >= window.start)
        .filter(AuditLog.timestamp <= window.end)
        .all()
    )
    containment_actions = {
        "quarantine_copied": sum(1 for a in audit if a.action == "quarantine.copied"),
        "quarantine_deleted": sum(1 for a in audit if a.action == "quarantine.deleted"),
        "process_killed": sum(1 for a in audit if a.action == "process.kill"),
        "process_auto_killed": sum(1 for a in audit if a.action == "process.auto_killed"),
        "agent_revoked": sum(1 for a in audit if a.action == "agent.revoked"),
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
        "risk_signals": {
            "total_detections": len(detections),
            "detections_on_phi_candidate_paths": len(phi_detections),
            "dlp_findings_total": len(dlp_findings),
            "dlp_findings_on_phi_candidate_paths": len(phi_dlp),
        },
        "containment_actions": containment_actions,
        "information_system_activity_review": {
            "audit_events_in_window": len(audit),
            "note": (
                "Volume indicates the reviewer's workload. HIPAA does "
                "not mandate a specific cadence; operators should "
                "document their review policy separately and show that "
                "policy alongside this report."
            ),
        },
        "phi_path_markers_used": list(_PHI_PATH_MARKERS),
    }
