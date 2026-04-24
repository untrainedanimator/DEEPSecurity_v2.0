"""Audit log writer.

A single, consistent signature — every caller in the codebase uses this:

    audit_log(
        actor="admin",
        action="scan.start",
        status="ok",
        file_path="/some/path",
        details={"scan_type": "full"},
    )

Writes to the `audit_log` table so logs can be queried via the API.
Also emits a structured log line so they show up in stdout / log aggregators.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from deepsecurity.db import session_scope
from deepsecurity.logging_config import get_logger
from deepsecurity.models import AuditLog

_log = get_logger(__name__)


def audit_log(
    *,
    actor: str,
    action: str,
    status: str = "ok",
    file_path: str | Path | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Persist an audit entry and emit a structured log line.

    Semantics: **audit must never crash the audited action.** If the DB
    is unavailable (missing table during a fresh test setup, schema
    drift, connection error, read-only disk), we still emit the
    structured log line and swallow the exception with a warning. The
    alternative — an audit_log raise that kills a running scan or a
    watchdog stop — is worse than losing one DB row.
    """
    fp = str(file_path) if file_path is not None else None
    serialised = json.dumps(details, default=str) if details else None

    try:
        with session_scope() as session:
            session.add(
                AuditLog(
                    actor=actor,
                    action=action,
                    status=status,
                    file_path=fp,
                    details=serialised,
                )
            )
    except Exception as exc:  # noqa: BLE001 — audit must never raise
        _log.warning(
            "audit.persist_failed",
            actor=actor,
            action=action,
            status=status,
            error=f"{type(exc).__name__}: {exc}",
        )

    _log.info(
        "audit",
        actor=actor,
        action=action,
        status=status,
        file_path=fp,
        **(details or {}),
    )
