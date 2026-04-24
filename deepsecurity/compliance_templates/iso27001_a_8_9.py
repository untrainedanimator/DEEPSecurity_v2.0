"""ISO/IEC 27001:2022 Annex A 8.9 — Configuration management.

Covers: "Configurations, including security configurations, of
hardware, software, services and networks shall be established,
documented, implemented, monitored and reviewed."

For DEEPSecurity the config-management evidence is:
    - The current runtime policy (settings that control posture)
    - The integrity snapshot status (have our binaries / config / signature
      file / runtime policy changed since baseline?)
    - Policy-change events in the audit log
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from deepsecurity import __version__
from deepsecurity.compliance import DateWindow
from deepsecurity.config import settings
from deepsecurity.integrity import check as integrity_check
from deepsecurity.models import AuditLog


TEMPLATE_ID = "iso27001-a-8-9"
TITLE = "ISO 27001 A.8.9 — Configuration management"
CONTROL_REF = "ISO/IEC 27001:2022 Annex A 8.9"
DESCRIPTION = (
    "Baseline-vs-current integrity comparison. Lists the posture-"
    "relevant settings in effect (DLP, watchdog, auto-kill) and runs "
    "the integrity check showing whether any of the package .py files, "
    "the .env file, the signature list, or the runtime policy blob "
    "have drifted from the saved snapshot."
)


def build(session: Session, window: DateWindow) -> dict[str, Any]:
    audit = (
        session.query(AuditLog)
        .filter(AuditLog.timestamp >= window.start)
        .filter(AuditLog.timestamp <= window.end)
        .all()
    )

    # Integrity report — the snapshot itself already exists OR it'll
    # return no_snapshot. Either way, honest state.
    try:
        rep = integrity_check()
        integrity = {
            "status": rep.status,
            "total_files_tracked": rep.total_files,
            "mismatched_count": len(rep.mismatched),
            "missing_count": len(rep.missing),
            "added_count": len(rep.added),
            "mismatched_sample": rep.mismatched[:20],
            "added_sample": rep.added[:20],
            "snapshot_at": rep.snapshot_at,
            "snapshot_path": rep.snapshot_path,
        }
    except Exception as exc:  # noqa: BLE001
        integrity = {
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
        }

    policy_changes = [
        a for a in audit
        if a.action in {"integrity.tampered", "integrity.policy_changed", "config.updated"}
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
        "build_info": {
            "deepsecurity_version": __version__,
            "env": settings.env,
        },
        "posture_settings": {
            "dlp_enabled": settings.dlp_enabled,
            "auto_kill_known_bad": settings.auto_kill_known_bad,
            "ransomware_auto_kill": settings.ransomware_auto_kill,
            "watchdog_autostart": settings.watchdog_autostart,
            "integrity_check_on_boot": settings.integrity_check_on_boot,
            "retention_days": settings.retention_days,
            "ip_reputation_enabled": settings.ip_reputation_enabled,
            "outlook_delete_on_detect": settings.outlook_delete_on_detect,
        },
        "integrity": integrity,
        "config_change_events_in_window": {
            "total": len(policy_changes),
            "by_action": _group(policy_changes, "action"),
        },
    }


def _group(rows: list, attr: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        k = str(getattr(r, attr) or "unknown")
        out[k] = out.get(k, 0) + 1
    return out
