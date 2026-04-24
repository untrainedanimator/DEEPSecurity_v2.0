"""Agent fleet endpoints.

Two audiences in one blueprint, split by auth:

    Operator (JWT):
        POST   /api/agents/enrol           → create enrolment token
        GET    /api/agents                 → list registered agents
        GET    /api/agents/<id>            → view one agent
        DELETE /api/agents/<id>            → revoke
        POST   /api/agents/<id>/commands   → queue a command

    Agent (X-DEEPSEC-AGENT-ID + X-DEEPSEC-AGENT-KEY):
        POST   /api/agents/register        → consume enrolment token
        POST   /api/agents/heartbeat       → alive + summary
        GET    /api/agents/commands        → pull pending commands
        POST   /api/agents/results         → report command outcome
        POST   /api/agents/events          → report unsolicited events
"""
from __future__ import annotations

import hashlib
import json
import socket
import uuid
from datetime import datetime, timezone
from typing import Any

from flask import Blueprint, g, jsonify, request

from deepsecurity.agent_auth import (
    consume_enrolment_token,
    generate_agent_key,
    hash_agent_key,
    issue_enrolment_token,
    require_agent,
)
from deepsecurity.api.auth import require_role
from deepsecurity.audit import audit_log
from deepsecurity.db import session_scope
from deepsecurity.logging_config import get_logger
from deepsecurity.models import Agent, AgentCommand, AgentEvent, AgentPolicy

agents_bp = Blueprint("agents", __name__)
_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Operator endpoints (JWT auth)
# ---------------------------------------------------------------------------


@agents_bp.route("/enrol", methods=["POST"])
@require_role("admin")
def enrol() -> Any:
    """Create a single-use enrolment token. Returned plaintext ONCE."""
    from flask_jwt_extended import get_jwt

    data = request.get_json(silent=True) or {}
    label = data.get("label")
    ttl_hours = int(data.get("ttl_hours", 24))
    if ttl_hours < 1 or ttl_hours > 24 * 30:
        return jsonify({"error": "ttl_out_of_range"}), 400

    issuer = str(get_jwt().get("sub", "unknown"))
    token = issue_enrolment_token(issued_by=issuer, label=label, ttl_hours=ttl_hours)
    audit_log(
        actor=issuer,
        action="agent.enrol_token_issued",
        details={"label": label, "ttl_hours": ttl_hours},
    )
    return jsonify({"enrolment_token": token, "ttl_hours": ttl_hours}), 201


@agents_bp.route("", methods=["GET"])
@require_role("admin", "security", "analyst")
def list_agents() -> Any:
    with session_scope() as s:
        rows = s.query(Agent).order_by(Agent.last_heartbeat_at.desc().nullslast()).all()
        return jsonify(
            [
                {
                    "id": a.id,
                    "hostname": a.hostname,
                    "os": a.os,
                    "os_version": a.os_version,
                    "agent_version": a.agent_version,
                    "enabled": a.enabled,
                    "ip_address": a.ip_address,
                    "registered_at": a.registered_at.isoformat() if a.registered_at else None,
                    "last_heartbeat_at": a.last_heartbeat_at.isoformat()
                    if a.last_heartbeat_at
                    else None,
                    "labels": json.loads(a.labels) if a.labels else [],
                }
                for a in rows
            ]
        )


@agents_bp.route("/<string:agent_id>", methods=["GET"])
@require_role("admin", "security", "analyst")
def get_agent(agent_id: str) -> Any:
    with session_scope() as s:
        a = s.query(Agent).filter(Agent.id == agent_id).first()
        if a is None:
            return jsonify({"error": "not_found"}), 404
        return jsonify(
            {
                "id": a.id,
                "hostname": a.hostname,
                "os": a.os,
                "os_version": a.os_version,
                "agent_version": a.agent_version,
                "enabled": a.enabled,
                "ip_address": a.ip_address,
                "registered_at": a.registered_at.isoformat() if a.registered_at else None,
                "last_heartbeat_at": a.last_heartbeat_at.isoformat()
                if a.last_heartbeat_at
                else None,
                "last_heartbeat_summary": json.loads(a.last_heartbeat_summary)
                if a.last_heartbeat_summary
                else None,
                "labels": json.loads(a.labels) if a.labels else [],
            }
        )


@agents_bp.route("/<string:agent_id>", methods=["DELETE"])
@require_role("admin")
def revoke_agent(agent_id: str) -> Any:
    from flask_jwt_extended import get_jwt

    actor = str(get_jwt().get("sub", "unknown"))
    with session_scope() as s:
        a = s.query(Agent).filter(Agent.id == agent_id).first()
        if a is None:
            return jsonify({"error": "not_found"}), 404
        a.enabled = False
    audit_log(actor=actor, action="agent.revoked", details={"agent_id": agent_id})
    return jsonify({"revoked": True, "agent_id": agent_id})


@agents_bp.route("/<string:agent_id>/commands", methods=["POST"])
@require_role("admin", "security")
def queue_command(agent_id: str) -> Any:
    """Queue a command for one agent.

    Body: {"kind": "scan", "payload": {"path": "C:\\\\Apps\\\\Imgs2"}}
          {"kind": "kill", "payload": {"pid": 1234, "reason": "..."}}
          {"kind": "watchdog_start", "payload": {"scope": "system"}}
          {"kind": "watchdog_stop", "payload": {}}
          {"kind": "processes_scan", "payload": {}}
          {"kind": "self_test", "payload": {}}
    """
    from flask_jwt_extended import get_jwt

    KIND_WHITELIST = {
        "scan",
        "kill",
        "watchdog_start",
        "watchdog_stop",
        "processes_scan",
        "self_test",
        "intel_update",
    }

    data = request.get_json(silent=True) or {}
    kind = str(data.get("kind", ""))
    payload = data.get("payload") or {}
    if kind not in KIND_WHITELIST:
        return jsonify({"error": "bad_kind", "allowed": sorted(KIND_WHITELIST)}), 400
    if not isinstance(payload, dict):
        return jsonify({"error": "payload_must_be_object"}), 400

    issuer = str(get_jwt().get("sub", "unknown"))
    with session_scope() as s:
        a = s.query(Agent).filter(Agent.id == agent_id, Agent.enabled.is_(True)).first()
        if a is None:
            return jsonify({"error": "agent_not_found_or_disabled"}), 404
        cmd = AgentCommand(
            agent_id=agent_id,
            kind=kind,
            payload=json.dumps(payload),
            status="pending",
            issued_by=issuer,
        )
        s.add(cmd)
        s.flush()
        cmd_id = cmd.id
    audit_log(
        actor=issuer,
        action="agent.command_queued",
        details={"agent_id": agent_id, "kind": kind, "command_id": cmd_id},
    )
    return jsonify({"command_id": cmd_id, "kind": kind, "status": "pending"}), 201


# ---------------------------------------------------------------------------
# Agent endpoints (X-DEEPSEC-AGENT-ID / X-DEEPSEC-AGENT-KEY)
# ---------------------------------------------------------------------------


@agents_bp.route("/register", methods=["POST"])
def register() -> Any:
    """Bootstrap: consume an enrolment token, return (agent_id, api_key).

    Unauthenticated — the enrolment token IS the credential. One-time use.
    """
    data = request.get_json(silent=True) or {}
    token = str(data.get("enrolment_token", ""))
    hostname = str(data.get("hostname", "")).strip() or "unknown"
    os_name = str(data.get("os", "")).strip() or "unknown"
    os_version = data.get("os_version")
    agent_version = str(data.get("agent_version", "2.2.0"))
    labels = data.get("labels") or []

    if not token:
        return jsonify({"error": "missing_enrolment_token"}), 400
    if not isinstance(labels, list):
        return jsonify({"error": "labels_must_be_list"}), 400

    row = consume_enrolment_token(token)
    if row is None:
        return jsonify({"error": "invalid_or_expired_token"}), 401

    agent_id = str(uuid.uuid4())
    api_key = generate_agent_key()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")

    with session_scope() as s:
        s.add(
            Agent(
                id=agent_id,
                api_key_hash=hash_agent_key(api_key),
                hostname=hostname,
                os=os_name,
                os_version=os_version,
                agent_version=agent_version,
                ip_address=ip,
                labels=json.dumps(labels),
                enabled=True,
                registered_at=datetime.now(timezone.utc),
            )
        )
        # Mark which agent burned the token.
        from deepsecurity.models import AgentEnrolmentToken as _T

        t = s.query(_T).filter(_T.id == row.id).first()
        if t is not None:
            t.used_by_agent_id = agent_id

    audit_log(
        actor="agent:" + agent_id,
        action="agent.registered",
        details={"hostname": hostname, "os": os_name, "ip": ip, "labels": labels},
    )
    return jsonify({"agent_id": agent_id, "api_key": api_key}), 201


@agents_bp.route("/heartbeat", methods=["POST"])
@require_agent
def heartbeat() -> Any:
    data = request.get_json(silent=True) or {}
    agent: Agent = g.agent  # type: ignore[attr-defined]
    with session_scope() as s:
        a = s.query(Agent).filter(Agent.id == agent.id).first()
        if a is None:
            return jsonify({"error": "agent_vanished"}), 404
        a.last_heartbeat_at = datetime.now(timezone.utc)
        a.last_heartbeat_summary = json.dumps(data)[:4000]
        # v2.4 FLEET_POLICY — emit the current policy_sha so the agent
        # can compare with its local copy and fetch the full policy on
        # mismatch. We return an empty string if no policy has ever been
        # set — the agent treats that as "no override, use DEEPSEC_* env".
        policy_row = (
            s.query(AgentPolicy).filter(AgentPolicy.agent_id == agent.id).first()
        )
        policy_sha = policy_row.policy_sha if policy_row else ""
    return jsonify({"ok": True, "policy_sha": policy_sha})


@agents_bp.route("/commands", methods=["GET"])
@require_agent
def pull_commands() -> Any:
    """Agent polls for pending commands, receives up to 10 per call."""
    agent: Agent = g.agent  # type: ignore[attr-defined]
    limit = min(int(request.args.get("limit", 10)), 50)
    out: list[dict[str, Any]] = []
    with session_scope() as s:
        rows = (
            s.query(AgentCommand)
            .filter(AgentCommand.agent_id == agent.id, AgentCommand.status == "pending")
            .order_by(AgentCommand.created_at.asc())
            .limit(limit)
            .all()
        )
        now = datetime.now(timezone.utc)
        for r in rows:
            out.append(
                {
                    "command_id": r.id,
                    "kind": r.kind,
                    "payload": json.loads(r.payload),
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
            )
            r.status = "dispatched"
            r.dispatched_at = now
    return jsonify({"commands": out})


@agents_bp.route("/results", methods=["POST"])
@require_agent
def post_result() -> Any:
    """Agent reports the outcome of a dispatched command."""
    data = request.get_json(silent=True) or {}
    agent: Agent = g.agent  # type: ignore[attr-defined]
    cmd_id = data.get("command_id")
    result = data.get("result")
    success = bool(data.get("success", False))
    if not isinstance(cmd_id, int) or result is None:
        return jsonify({"error": "bad_payload"}), 400

    with session_scope() as s:
        cmd = (
            s.query(AgentCommand)
            .filter(AgentCommand.id == cmd_id, AgentCommand.agent_id == agent.id)
            .first()
        )
        if cmd is None:
            return jsonify({"error": "unknown_command"}), 404
        cmd.status = "completed" if success else "failed"
        cmd.completed_at = datetime.now(timezone.utc)
        cmd.result = json.dumps(result)[:100_000]

    audit_log(
        actor="agent:" + agent.id,
        action=f"agent.command_{'ok' if success else 'failed'}",
        details={"command_id": cmd_id, "kind": cmd.kind},
    )
    return jsonify({"ok": True})


@agents_bp.route("/events", methods=["POST"])
@require_agent
def post_event() -> Any:
    """Agent reports unsolicited telemetry (detection, integrity breach, …)."""
    data = request.get_json(silent=True) or {}
    agent: Agent = g.agent  # type: ignore[attr-defined]
    kind = str(data.get("kind", ""))
    severity = str(data.get("severity", "info"))
    payload = data.get("payload") or {}
    if not kind:
        return jsonify({"error": "missing_kind"}), 400

    with session_scope() as s:
        s.add(
            AgentEvent(
                agent_id=agent.id,
                kind=kind[:32],
                severity=severity[:16],
                payload=json.dumps(payload)[:100_000],
            )
        )

    # Route the high-severity ones into the alert bus.
    if severity in {"critical", "high"}:
        try:
            from deepsecurity.alerts import AlertEvent
            from deepsecurity.alerts import bus as alert_bus

            alert_bus.dispatch(
                AlertEvent(
                    kind=f"agent.{kind}",
                    severity=severity,
                    summary=f"agent {agent.hostname}: {kind}",
                    actor="agent:" + agent.id,
                    details={"agent_id": agent.id, "payload": payload},
                )
            )
        except Exception:
            _log.exception("agent.event_alert_failed")

    return jsonify({"ok": True}), 201


# ---------------------------------------------------------------------------
# FLEET_POLICY — per-agent policy push (v2.4).
#
# Operator (JWT) writes a policy; agent (API key) reads and applies it.
# Policies are JSON blobs covering watchdog exclusions, DLP severity
# overrides, autostart scope and signature-file source.
# ---------------------------------------------------------------------------


_ALLOWED_POLICY_KEYS: frozenset[str] = frozenset(
    {
        "exclusion_globs",
        "dlp_severity_overrides",
        "autostart_scope",
        "signatures_url",
    }
)


def _canonical_policy_json(policy: dict) -> str:
    """Stable JSON form so the SHA is deterministic across re-pushes."""
    return json.dumps(policy, sort_keys=True, separators=(",", ":"))


def _policy_sha(canonical: str) -> str:
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@agents_bp.route("/<string:agent_id>/policy", methods=["POST"])
@require_role("admin", "security")
def set_agent_policy(agent_id: str) -> Any:
    """Upsert the policy for a specific agent.

    Body:
        {
          "exclusion_globs": "**/node_modules/**;…",   (optional)
          "dlp_severity_overrides": {"pat": "observe"}, (optional)
          "autostart_scope": "user_risk" | "system" | "", (optional)
          "signatures_url": "https://…"               (optional)
        }

    Any unknown top-level key is rejected with 400 — keep this schema
    tight so a typo doesn't silently downgrade policy.
    """
    data = request.get_json(silent=True) or {}

    unknown = set(data.keys()) - _ALLOWED_POLICY_KEYS
    if unknown:
        return (
            jsonify(
                {
                    "error": "unknown_policy_keys",
                    "unknown": sorted(unknown),
                    "allowed": sorted(_ALLOWED_POLICY_KEYS),
                }
            ),
            400,
        )

    # Per-field shape checks.
    if "exclusion_globs" in data and not isinstance(data["exclusion_globs"], str):
        return jsonify({"error": "bad_type", "field": "exclusion_globs"}), 400
    if "dlp_severity_overrides" in data and not isinstance(
        data["dlp_severity_overrides"], dict
    ):
        return jsonify({"error": "bad_type", "field": "dlp_severity_overrides"}), 400
    if "autostart_scope" in data and data["autostart_scope"] not in (
        "",
        "user_risk",
        "system",
    ):
        return (
            jsonify(
                {
                    "error": "bad_value",
                    "field": "autostart_scope",
                    "allowed": ["", "user_risk", "system"],
                }
            ),
            400,
        )
    if "signatures_url" in data and not (
        isinstance(data["signatures_url"], str)
        and data["signatures_url"].startswith(("http://", "https://"))
    ):
        return jsonify({"error": "bad_type", "field": "signatures_url"}), 400

    canonical = _canonical_policy_json(data)
    sha = _policy_sha(canonical)

    actor = str(g.jwt_claims.get("sub") if hasattr(g, "jwt_claims") else "admin")
    try:
        from flask_jwt_extended import get_jwt

        actor = str(get_jwt().get("sub", actor))
    except Exception:  # noqa: BLE001
        pass

    with session_scope() as s:
        agent = s.query(Agent).filter(Agent.id == agent_id).first()
        if agent is None:
            return jsonify({"error": "agent_not_found", "agent_id": agent_id}), 404

        existing = (
            s.query(AgentPolicy).filter(AgentPolicy.agent_id == agent_id).first()
        )
        if existing is None:
            s.add(
                AgentPolicy(
                    agent_id=agent_id,
                    policy_sha=sha,
                    policy_json=canonical,
                    updated_by=actor,
                )
            )
        else:
            existing.policy_sha = sha
            existing.policy_json = canonical
            existing.updated_by = actor

    audit_log(
        actor=actor,
        action="agent.policy_set",
        status="ok",
        details={"agent_id": agent_id, "policy_sha": sha, "keys": sorted(data.keys())},
    )

    return jsonify({"ok": True, "agent_id": agent_id, "policy_sha": sha}), 200


@agents_bp.route("/<string:agent_id>/policy", methods=["GET"])
@require_agent
def get_agent_policy(agent_id: str) -> Any:
    """Agent fetches its own policy. Other agents' IDs are refused.

    Returns the canonical policy JSON AND the sha so the agent can
    persist both and avoid re-fetching on every heartbeat.
    """
    agent: Agent = g.agent  # type: ignore[attr-defined]
    if agent.id != agent_id:
        return jsonify({"error": "agent_id_mismatch"}), 403

    with session_scope() as s:
        row = (
            s.query(AgentPolicy).filter(AgentPolicy.agent_id == agent_id).first()
        )
        if row is None:
            return jsonify({"policy_sha": "", "policy": {}}), 200
        return (
            jsonify(
                {
                    "policy_sha": row.policy_sha,
                    "policy": json.loads(row.policy_json),
                    "updated_at": row.updated_at.isoformat() if row.updated_at else None,
                    "updated_by": row.updated_by,
                }
            ),
            200,
        )
