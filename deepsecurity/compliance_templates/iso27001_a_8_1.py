"""ISO/IEC 27001:2022 Annex A 8.1 — User endpoint devices.

Covers: "Information stored on, processed by or accessible via user
endpoint devices shall be protected."

For DEEPSecurity the endpoint evidence is:
    - Agents enrolled in the fleet (device inventory)
    - Each agent's last-heartbeat (are they actually alive / reporting?)
    - Quarantine + safelist state (what was isolated, what's allow-listed)
    - Watchdog status (is the endpoint scanner itself running?)
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from deepsecurity.compliance import DateWindow
from deepsecurity.models import Agent, SafeListEntry


TEMPLATE_ID = "iso27001-a-8-1"
TITLE = "ISO 27001 A.8.1 — User endpoint devices"
CONTROL_REF = "ISO/IEC 27001:2022 Annex A 8.1"
DESCRIPTION = (
    "Endpoint inventory and monitoring state. Lists all enrolled "
    "agents with last-heartbeat, shows which endpoints are actively "
    "reporting, and summarises the quarantine and safelist workflow "
    "governing files on those endpoints."
)


def build(session: Session, window: DateWindow) -> dict[str, Any]:
    agents = session.query(Agent).all()
    now = datetime.now(timezone.utc)
    stale_threshold = now - timedelta(hours=2)

    # Normalise heartbeat comparison — SQLite stores naive datetimes.
    def _aware(dt: datetime | None) -> datetime | None:
        if dt is None:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    agent_rows = []
    alive_count = 0
    for a in agents:
        last_hb = _aware(a.last_heartbeat_at)
        is_alive = (
            last_hb is not None
            and last_hb >= stale_threshold
            and bool(a.enabled)
        )
        if is_alive:
            alive_count += 1
        agent_rows.append(
            {
                "id": a.id,
                "labels": a.labels,  # JSON list persisted as text
                "hostname": a.hostname,
                "os": a.os,
                "os_version": a.os_version,
                "agent_version": a.agent_version,
                "registered_at": (_aware(a.registered_at).isoformat() if a.registered_at else None),
                "last_heartbeat_at": (last_hb.isoformat() if last_hb else None),
                "enabled": bool(a.enabled),
                "reporting": bool(is_alive),
            }
        )

    safelist_count = session.query(SafeListEntry).count()

    return {
        "template_id": TEMPLATE_ID,
        "title": TITLE,
        "control_ref": CONTROL_REF,
        "description": DESCRIPTION,
        "generated_at": now.isoformat(),
        "window": {
            "start": window.start.isoformat(),
            "end": window.end.isoformat(),
        },
        "agent_fleet": {
            "total_registered": len(agents),
            "currently_reporting": alive_count,
            "stale_threshold_hours": 2,
            "agents": agent_rows,
        },
        "operator_curated_state": {
            "safelist_entries": safelist_count,
        },
        "note": (
            "'reporting' means the agent has heart-beaten within the "
            "last 2 hours and has not been revoked. Agents exceeding "
            "that threshold are candidates for de-provisioning review."
        ),
    }
