"""Alert sink visibility + test-fire.

Shows which outbound channels are configured (console / slack / webhook /
syslog / email) and lets the operator push a test event through them.
"""
from __future__ import annotations

from typing import Any

from flask import Blueprint, jsonify

from deepsecurity.alerts import AlertEvent, bus
from deepsecurity.api.auth import require_role
from deepsecurity.audit import audit_log
from deepsecurity.config import settings

sinks_bp = Blueprint("sinks", __name__)


@sinks_bp.route("/status", methods=["GET"])
@require_role("admin", "security", "analyst")
def status() -> Any:
    configured: list[dict[str, Any]] = []

    configured.append({"name": "console", "enabled": True, "detail": "always on"})

    configured.append(
        {
            "name": "slack",
            "enabled": bool(settings.slack_webhook_url),
            "detail": "URL set" if settings.slack_webhook_url else "no DEEPSEC_SLACK_WEBHOOK_URL",
        }
    )
    configured.append(
        {
            "name": "webhook",
            "enabled": bool(settings.alert_webhook_url),
            "detail": "URL set" if settings.alert_webhook_url else "no DEEPSEC_ALERT_WEBHOOK_URL",
        }
    )
    configured.append(
        {
            "name": "syslog",
            "enabled": bool(settings.syslog_host),
            "detail": f"{settings.syslog_host}:{settings.syslog_port}"
            if settings.syslog_host
            else "no DEEPSEC_SYSLOG_HOST",
        }
    )
    configured.append(
        {
            "name": "email",
            "enabled": bool(settings.smtp_host and settings.alert_email_to),
            "detail": f"{settings.smtp_host} → {settings.alert_email_to}"
            if settings.smtp_host and settings.alert_email_to
            else "no DEEPSEC_SMTP_HOST or ALERT_EMAIL_TO",
        }
    )

    return jsonify({"sinks": configured})


@sinks_bp.route("/test", methods=["POST"])
@require_role("admin", "security")
def test_fire() -> Any:
    """Fan out a synthetic alert through every configured sink."""
    from flask_jwt_extended import get_jwt

    actor = str(get_jwt().get("sub", "unknown"))
    ev = AlertEvent(
        kind="alert.test",
        severity="info",
        summary="deepsec alert-sink test event",
        actor=actor,
        details={"source": "api.sinks.test"},
    )
    bus.dispatch(ev)
    audit_log(actor=actor, action="alert.test_fired")
    return jsonify({"dispatched": True, "event": ev.to_dict()})
