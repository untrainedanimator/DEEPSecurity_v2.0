"""Authentication — JWT issuing + role-gated decorator.

Design decisions:
    - No fallback to a dummy user. If auth fails, you get 401. Full stop.
    - Role is read from the JWT "role" claim, not the request body.
    - Tokens are short-lived (DEEPSEC_JWT_ACCESS_MINUTES, default 60).

The login endpoint here is intentionally tiny — it's a seam you replace with
your real IdP (OAuth, SAML, LDAP) when you're ready. For local development
we verify against a single set of env-driven credentials.
"""
from __future__ import annotations

from functools import wraps
from typing import Any, Callable

from flask import Blueprint, jsonify, request
from flask_jwt_extended import (
    create_access_token,
    get_jwt,
    jwt_required,
    verify_jwt_in_request,
)
from werkzeug.security import check_password_hash, generate_password_hash

from deepsecurity.audit import audit_log
from deepsecurity.config import settings
from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)
auth_bp = Blueprint("auth", __name__)


def _dev_user_hash() -> tuple[str, str, str]:
    """Return (username, password_hash, role) for the dev bootstrap user.

    Reads from `settings` (loaded from .env by pydantic-settings). If the
    password is unset the function returns an empty tuple and the /login
    route replies 503, so the app never silently authenticates a ghost.
    """
    if not settings.dev_password:
        return ("", "", "")
    return (
        settings.dev_user,
        generate_password_hash(settings.dev_password),
        settings.dev_role,
    )


@auth_bp.route("/login", methods=["POST"])
def login() -> Any:
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))

    dev_user, dev_hash, dev_role = _dev_user_hash()
    if not dev_user or not dev_hash:
        return jsonify({"error": "authentication not configured"}), 503

    try:
        ok = username == dev_user and check_password_hash(dev_hash, password)
    except Exception:
        _log.exception("auth.check_failed")
        ok = False

    if not ok:
        try:
            audit_log(
                actor=username or "anonymous",
                action="auth.login",
                status="denied",
                details={"reason": "invalid_credentials"},
            )
        except Exception:
            _log.exception("auth.audit_failed")
        return jsonify({"error": "invalid credentials"}), 401

    # --- success path — each step wrapped so a 500 tells us WHERE it died ---
    try:
        # Flask-JWT-Extended requires the `sub` claim to be a string in recent
        # releases — `identity=username` gives us exactly that.
        token = create_access_token(
            identity=str(username),
            additional_claims={"role": str(dev_role)},
        )
    except Exception as exc:
        _log.exception("auth.token_create_failed")
        return jsonify({"error": "token_issue", "detail": f"{type(exc).__name__}: {exc}"}), 500

    try:
        audit_log(
            actor=username,
            action="auth.login",
            status="ok",
            details={"role": dev_role},
        )
    except Exception:
        # Don't fail the login just because the audit write hiccuped.
        _log.exception("auth.audit_failed_on_ok")

    return jsonify({"access_token": token, "role": dev_role}), 200


@auth_bp.route("/whoami", methods=["GET"])
@jwt_required()
def whoami() -> Any:
    claims = get_jwt()
    return jsonify({"username": claims.get("sub"), "role": claims.get("role")})


# --- Decorator --------------------------------------------------------------


def require_role(*allowed_roles: str) -> Callable:
    """Decorator: require an authenticated user whose role is in allowed_roles.

    Returns 401 if token missing/invalid, 403 if role is insufficient.
    No fallback to a dummy user. Period.
    """

    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                verify_jwt_in_request()
            except Exception as exc:  # noqa: BLE001
                _log.info("auth.denied", reason=str(exc))
                return jsonify({"error": "unauthenticated"}), 401

            claims = get_jwt()
            role = str(claims.get("role", ""))
            if role not in allowed_roles:
                _log.info("auth.forbidden", role=role, allowed=list(allowed_roles))
                return jsonify({"error": "forbidden", "required_roles": list(allowed_roles)}), 403

            return fn(*args, **kwargs)

        return wrapper

    return decorator
