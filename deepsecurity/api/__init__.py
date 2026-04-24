"""Flask application factory.

Call `create_app()` to build the app. All config comes from settings; nothing
is read from globals or JSON files on disk.

    from deepsecurity.api import create_app
    app = create_app()

Blueprints are registered in a deterministic order and each owns its URL prefix.
"""
from __future__ import annotations

from datetime import timedelta

from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager

from deepsecurity.api.agents import agents_bp
from deepsecurity.api.audit import audit_bp
from deepsecurity.api.auth import auth_bp
from deepsecurity.api.compliance import compliance_bp
from deepsecurity.api.dlp import dlp_bp
from deepsecurity.api.errors import register_error_handlers
from deepsecurity.api.health import health_bp
from deepsecurity.api.intel import intel_bp
from deepsecurity.api.metrics import metrics_bp
from deepsecurity.api.network import network_bp
from deepsecurity.api.processes import processes_bp
from deepsecurity.api.quarantine import quarantine_bp
from deepsecurity.api.scanner import scanner_bp
from deepsecurity.api.sinks import sinks_bp
from deepsecurity.api.system import system_bp
from deepsecurity.api.watchdog import watchdog_bp
from deepsecurity.config import settings
from deepsecurity.db import init_db
from deepsecurity.logging_config import configure_logging, get_logger
from deepsecurity.rate_limit import register_rate_limit
from deepsecurity.security_headers import register_security_headers

# Module-level logger — used both by create_app() and by the
# _maybe_autostart_watchdog() helper below. Defining it at module scope
# (rather than as a local inside create_app) is the one-line fix for a
# NameError that blocked server boot on v2.3.1.
_log = get_logger(__name__)


def create_app() -> Flask:
    configure_logging()

    app = Flask(__name__)
    app.config["SECRET_KEY"] = settings.secret_key
    app.config["JWT_SECRET_KEY"] = settings.jwt_secret
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=settings.jwt_access_minutes)
    app.config["JSON_SORT_KEYS"] = False
    app.config["PROPAGATE_EXCEPTIONS"] = True

    JWTManager(app)
    CORS(
        app,
        resources={r"/api/*": {"origins": settings.cors_origin_list}},
        supports_credentials=True,
    )

    register_security_headers(app)
    register_rate_limit(
        app,
        anon_per_minute=settings.rate_limit_anon_per_minute,
        auth_per_minute=settings.rate_limit_auth_per_minute,
        max_request_bytes=settings.max_request_bytes,
    )
    register_error_handlers(app)

    app.register_blueprint(health_bp)  # unprefixed: /healthz, /readyz
    app.register_blueprint(metrics_bp)  # unprefixed: /metrics
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(scanner_bp, url_prefix="/api/scanner")
    app.register_blueprint(quarantine_bp, url_prefix="/api/quarantine")
    app.register_blueprint(audit_bp, url_prefix="/api/audit")
    app.register_blueprint(dlp_bp, url_prefix="/api/dlp")
    app.register_blueprint(watchdog_bp, url_prefix="/api/watchdog")
    app.register_blueprint(intel_bp, url_prefix="/api/intel")
    app.register_blueprint(compliance_bp, url_prefix="/api/compliance")
    app.register_blueprint(system_bp, url_prefix="/api/system")
    app.register_blueprint(network_bp, url_prefix="/api/network")
    app.register_blueprint(processes_bp, url_prefix="/api/processes")
    app.register_blueprint(sinks_bp, url_prefix="/api/sinks")
    app.register_blueprint(agents_bp, url_prefix="/api/agents")

    init_db()

    # Self-integrity tripwire fires here if configured.
    try:
        from deepsecurity.integrity import boot_check

        boot_check()
    except Exception:  # noqa: BLE001 — never let integrity block startup
        _log.exception("integrity.boot_check_failed")

    # Auto-start the realtime watchdog so the tool "just works" on boot.
    # Disable by setting DEEPSEC_WATCHDOG_AUTOSTART="" in the environment.
    # Any failure here is logged but never blocks the server from starting.
    _maybe_autostart_watchdog()

    _log.info("api.ready", env=settings.env, cors=settings.cors_origin_list)
    return app


def _maybe_autostart_watchdog() -> None:
    """Kick off the realtime watchdog if the operator has opted in.

    This is the single architectural change that removes the "every time I
    restart the server I have to click watch-user-risk" friction. The
    default is ``user_risk``, so by default the tool works out of the box.
    Operators who want manual control set ``DEEPSEC_WATCHDOG_AUTOSTART=""``.

    Errors never block startup — if watchdog isn't installed, or the
    scope resolves to zero paths, we log and move on.
    """
    scope = (settings.watchdog_autostart or "").strip().lower()
    if not scope:
        _log.info("watchdog.autostart.disabled")
        return
    try:
        from deepsecurity.watchdog_monitor import controller

        if not controller.available:
            _log.warning(
                "watchdog.autostart.skipped",
                reason="watchdog package not installed — "
                "pip install \"deepsecurity[watchdog]\"",
            )
            return
        if controller.running:
            # A previous call (or a test harness, or a reload) already
            # started it. Don't stomp on the live observer.
            _log.info(
                "watchdog.autostart.already_running",
                paths=controller.watching,
            )
            return
        result = controller.start(scope=scope)
        if result.get("started"):
            _log.info(
                "watchdog.autostart.ok",
                scope=scope,
                paths=result.get("paths"),
            )
        else:
            _log.warning(
                "watchdog.autostart.failed",
                scope=scope,
                reason=result.get("reason"),
            )
    except Exception:
        _log.exception("watchdog.autostart.crashed")
