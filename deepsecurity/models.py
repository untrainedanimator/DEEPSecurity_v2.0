"""SQLAlchemy ORM models.

Schema kept compatible with v2.0's deepscan.db so existing data stays readable.
New columns added where needed for auditability (quarantine_path, sha256,
and — in the SaaS build — agent_id).
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class ScanSession(Base):
    __tablename__ = "scan_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    actor: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(20))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    total_files: Mapped[int] = mapped_column(Integer, default=0)
    total_detections: Mapped[int] = mapped_column(Integer, default=0)
    scan_root: Mapped[str | None] = mapped_column(Text, nullable=True)


class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    session_id: Mapped[int] = mapped_column(Integer, index=True)
    file_path: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    label: Mapped[str] = mapped_column(String(20))
    ml_confidence: Mapped[float] = mapped_column(Float, default=0.0)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    entropy: Mapped[float] = mapped_column(Float, default=0.0)
    file_status: Mapped[str] = mapped_column(String(20))
    detection_reason: Mapped[str] = mapped_column(Text, default="")
    quarantine_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class SafeListEntry(Base):
    __tablename__ = "safe_list"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    file_hash: Mapped[str] = mapped_column(String(64), index=True)
    file_path: Mapped[str] = mapped_column(Text)
    action: Mapped[str] = mapped_column(String(20))
    actor: Mapped[str] = mapped_column(String(50))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    action: Mapped[str] = mapped_column(String(50), index=True)
    status: Mapped[str] = mapped_column(String(50))
    actor: Mapped[str] = mapped_column(String(50), index=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )


class DLPFinding(Base):
    """A secret / PII match produced by deepsecurity.dlp."""

    __tablename__ = "dlp_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    session_id: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)
    agent_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    file_path: Mapped[str] = mapped_column(Text)
    pattern_name: Mapped[str] = mapped_column(String(50), index=True)
    severity: Mapped[str] = mapped_column(String(10), index=True)
    line_number: Mapped[int] = mapped_column(Integer)
    redacted_preview: Mapped[str] = mapped_column(Text)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )


# ---------------------------------------------------------------------------
# SaaS / agent tables. Empty + unused in single-node (default) deployments;
# populated when running the server in SaaS mode with endpoint agents.
# ---------------------------------------------------------------------------


class Agent(Base):
    """A registered endpoint. One row per laptop / host reporting in."""

    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # UUID
    api_key_hash: Mapped[str] = mapped_column(String(128))
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    os: Mapped[str] = mapped_column(String(32))
    os_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    agent_version: Mapped[str] = mapped_column(String(32))
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    labels: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    last_heartbeat_summary: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON


class AgentEnrolmentToken(Base):
    """One-time token used by an agent to bootstrap into the system.

    The plaintext token is shown to the operator exactly once at creation.
    Only the hash is persisted. Tokens expire and burn on first use.
    """

    __tablename__ = "agent_enrolment_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    label: Mapped[str | None] = mapped_column(String(128), nullable=True)
    issued_by: Mapped[str] = mapped_column(String(50))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    used_by_agent_id: Mapped[str | None] = mapped_column(String(36), nullable=True)


class AgentCommand(Base):
    """A command queued by the operator for a specific agent.

    Lifecycle: pending → dispatched → completed | failed | expired
    """

    __tablename__ = "agent_commands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    agent_id: Mapped[str] = mapped_column(String(36), index=True)
    kind: Mapped[str] = mapped_column(String(32))  # 'scan', 'kill', 'watchdog_start', ...
    payload: Mapped[str] = mapped_column(Text)  # JSON
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    issued_by: Mapped[str] = mapped_column(String(50))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON


class AgentEvent(Base):
    """Unsolicited telemetry from an agent (scan finished, detection, integrity, etc.).

    The raw payload is kept verbatim as JSON so new event types don't need
    a schema migration. Typed views are built on top via SQL.
    """

    __tablename__ = "agent_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    agent_id: Mapped[str] = mapped_column(String(36), index=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    payload: Mapped[str] = mapped_column(Text)  # JSON
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, index=True
    )


class AgentPolicy(Base):
    """Operator-pushed policy for a single agent. v2.4 FLEET_POLICY.

    One row per agent_id. ``policy_sha`` is the SHA-256 of the canonical
    JSON form of ``policy_json``; the agent sends its local policy_sha
    with every heartbeat, and if the value returned differs it fetches
    the new policy and applies it.

    ``policy_json`` shape (canonical keys, all optional — missing keys
    fall back to the agent's ``DEEPSEC_*`` environment defaults):

        {
          "exclusion_globs": "**/node_modules/**;**/.venv/**;...",
          "dlp_severity_overrides": {"email_address": "observe", ...},
          "autostart_scope": "user_risk" | "system" | "",
          "signatures_url": "https://policy.example.com/sigs.txt"
        }
    """

    __tablename__ = "agent_policies"

    # One row per agent — id is the FK to agents.id.
    agent_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    policy_sha: Mapped[str] = mapped_column(String(64), index=True)
    policy_json: Mapped[str] = mapped_column(Text)  # canonical JSON
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )
    updated_by: Mapped[str] = mapped_column(String(50))
