"""Agent-side authentication.

Operators authenticate with JWTs. Agents authenticate with a long-lived
API key passed via the `X-DEEPSEC-AGENT-KEY` header (and the agent's UUID
via `X-DEEPSEC-AGENT-ID`). Two separate auth paths so the same app can
serve both an operator dashboard and a fleet of machines.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Callable

from flask import g, jsonify, request

from deepsecurity.db import session_scope
from deepsecurity.logging_config import get_logger
from deepsecurity.models import Agent, AgentEnrolmentToken

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Key hashing — constant-time equality, salted SHA-256.
#
# API keys are high-entropy random strings (token_urlsafe(32) = ~256 bits).
# Salting isn't cryptographically required but makes DB leaks harder to
# precompute against. We store `sha256(b"deepsec-agent-key" + key)`.
# ---------------------------------------------------------------------------


_AGENT_KEY_SALT = b"deepsec-agent-key-v1"


def generate_agent_key() -> str:
    """Return a fresh random API key, URL-safe, ~43 chars."""
    return secrets.token_urlsafe(32)


def hash_agent_key(key: str) -> str:
    return hashlib.sha256(_AGENT_KEY_SALT + key.encode("utf-8")).hexdigest()


def verify_agent_key(key: str, key_hash: str) -> bool:
    return hmac.compare_digest(hash_agent_key(key), key_hash)


# ---------------------------------------------------------------------------
# Enrolment tokens — one-time, short-lived.
# ---------------------------------------------------------------------------


def generate_enrolment_token() -> str:
    return secrets.token_urlsafe(24)


def hash_enrolment_token(token: str) -> str:
    return hashlib.sha256(b"deepsec-enrol-v1" + token.encode("utf-8")).hexdigest()


def issue_enrolment_token(
    *,
    issued_by: str,
    label: str | None = None,
    ttl_hours: int = 24,
) -> str:
    """Insert a fresh token and return the PLAINTEXT once.

    Plaintext is not persisted. If it's lost before use, issue another.
    """
    token = generate_enrolment_token()
    with session_scope() as s:
        s.add(
            AgentEnrolmentToken(
                token_hash=hash_enrolment_token(token),
                label=label,
                issued_by=issued_by,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=ttl_hours),
            )
        )
    return token


def consume_enrolment_token(token: str) -> AgentEnrolmentToken | None:
    """Validate + mark used. Returns the row on success, None otherwise.

    All validation is on the server to prevent a replay of a previously-
    used token from succeeding silently.
    """
    token_hash = hash_enrolment_token(token)
    with session_scope() as s:
        row = (
            s.query(AgentEnrolmentToken)
            .filter(AgentEnrolmentToken.token_hash == token_hash)
            .first()
        )
        if row is None:
            return None
        if row.used_at is not None:
            _log.warning("enrol.token_replay", token_id=row.id)
            return None
        # SQLite doesn't persist tz info, so the stored value round-trips as
        # naive. We always write UTC, so reattach tzinfo before comparing
        # with the tz-aware now() — otherwise Python raises TypeError.
        expires_at = row.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            _log.info("enrol.token_expired", token_id=row.id)
            return None
        row.used_at = datetime.now(timezone.utc)
        s.flush()
        # Detach from session so caller can read fields safely.
        s.expunge(row)
        return row


# ---------------------------------------------------------------------------
# Agent-auth Flask decorator
# ---------------------------------------------------------------------------


def require_agent(fn: Callable) -> Callable:
    """Validate X-DEEPSEC-AGENT-ID + X-DEEPSEC-AGENT-KEY.

    On success, `g.agent` is the Agent row (detached). On failure → 401.
    """

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        agent_id = request.headers.get("X-DEEPSEC-AGENT-ID", "")
        key = request.headers.get("X-DEEPSEC-AGENT-KEY", "")
        if not agent_id or not key:
            return jsonify({"error": "missing_agent_credentials"}), 401

        with session_scope() as s:
            agent = s.query(Agent).filter(Agent.id == agent_id).first()
            if agent is None or not agent.enabled:
                return jsonify({"error": "unknown_or_disabled_agent"}), 401
            if not verify_agent_key(key, agent.api_key_hash):
                _log.warning("agent.auth_failed", agent_id=agent_id)
                return jsonify({"error": "bad_agent_key"}), 401
            # Touch the heartbeat on every authenticated call.
            agent.last_heartbeat_at = datetime.now(timezone.utc)
            s.flush()
            s.expunge(agent)
        g.agent = agent
        return fn(*args, **kwargs)

    return wrapper
