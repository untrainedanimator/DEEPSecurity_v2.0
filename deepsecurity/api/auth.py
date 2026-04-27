"""Authentication — JWT issuing + role-gated decorator + step-up auth.

Design decisions:
    - No fallback to a dummy user. If auth fails, you get 401. Full stop.
    - Role is read from the JWT "role" claim, not the request body.
    - Tokens are short-lived (DEEPSEC_JWT_ACCESS_MINUTES, default 60).
    - Destructive verbs (quarantine restore/delete, audit purge,
      agent revoke) require a SECOND credential check via the
      ``X-Stepup-Token`` header. The step-up token is minted by
      re-presenting credentials at /api/auth/stepup and is valid for
      5 minutes only.

The login endpoint here is intentionally tiny — it's a seam you replace with
your real IdP (OAuth, SAML, LDAP) when you're ready. For local development
we verify against a single set of env-driven credentials.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from functools import wraps
from typing import Any

import jwt as _pyjwt
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
    # v2.5 hardening: in production, refuse to fall back to the env-driven
    # dev user. Production deployments MUST go through the OIDC flow at
    # /api/auth/oidc/login. The endpoint stays mounted so the frontend's
    # error message is "use the SSO login" rather than 404.
    if settings.env == "production" and not getattr(settings, "_allow_dev_login_in_prod", False):
        return (
            jsonify(
                {
                    "error": "dev_login_disabled_in_production",
                    "hint": "use /api/auth/oidc/login (OIDC) — see docs/SECURITY.md",
                }
            ),
            403,
        )

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
            except Exception as exc:
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


# --- Step-up auth (v3.1) ---------------------------------------------------

# Step-up tokens are short-lived second-factor credentials minted at
# /api/auth/stepup. They are NOT a replacement for the access token —
# both must be present on a destructive call. The step-up TTL is short
# (5 minutes) so a stolen token has limited utility, and the operator
# has to actively re-confirm intent for each batch of destructive ops.
_STEPUP_TTL_MINUTES = 5
_STEPUP_CLAIM_NAME = "stepup"


def _mint_stepup_token(username: str) -> str:
    """Issue a HS256 JWT scoped to step-up actions only.

    Use create_access_token with a short expires_delta so flask-jwt
    validation still works if a caller mistakenly passes the step-up
    token as the access token. The ``stepup`` claim disambiguates.
    """
    return create_access_token(
        identity=str(username),
        additional_claims={
            _STEPUP_CLAIM_NAME: True,
            "scope": "stepup",
        },
        expires_delta=timedelta(minutes=_STEPUP_TTL_MINUTES),
    )


@auth_bp.route("/stepup", methods=["POST"])
@jwt_required()
def stepup() -> Any:
    """Mint a 5-minute step-up token after re-confirming credentials.

    Body: {"password": "..."} — the operator's current password.

    Required: a valid access token (the regular JWT) AND a fresh password
    re-confirmation. Returns the step-up token to attach as the
    ``X-Stepup-Token`` header on the next destructive call.
    """
    claims = get_jwt()
    username = str(claims.get("sub") or "")
    if not username:
        return jsonify({"error": "no_subject_in_token"}), 401

    data = request.get_json(silent=True) or {}
    password = str(data.get("password", ""))
    if not password:
        return jsonify({"error": "password_required"}), 400

    dev_user, dev_hash, _ = _dev_user_hash()
    if not dev_user or not dev_hash:
        # OIDC-only deploys can't step up via password — they need to
        # re-auth via the IdP. Document this clearly.
        return jsonify(
            {
                "error": "stepup_unavailable",
                "hint": "OIDC deployments must re-auth via /api/auth/oidc/login",
            }
        ), 503

    if username != dev_user or not check_password_hash(dev_hash, password):
        try:
            audit_log(
                actor=username,
                action="auth.stepup",
                status="denied",
                details={"reason": "invalid_password"},
            )
        except Exception:
            _log.exception("auth.audit_failed")
        return jsonify({"error": "invalid_credentials"}), 401

    token = _mint_stepup_token(username)
    try:
        audit_log(
            actor=username,
            action="auth.stepup",
            status="ok",
            details={"ttl_minutes": _STEPUP_TTL_MINUTES},
        )
    except Exception:
        _log.exception("auth.audit_failed_on_stepup")
    return (
        jsonify(
            {
                "stepup_token": token,
                "ttl_minutes": _STEPUP_TTL_MINUTES,
                "scope": "stepup",
            }
        ),
        200,
    )


def require_stepup() -> Callable:
    """Decorator: require a valid step-up token in ``X-Stepup-Token``.

    Layered on top of @require_role — the access-token check happens
    first (caller is authenticated and has the right role), THEN this
    confirms a fresh credential check happened in the last 5 minutes.

    Returns 401 if step-up token missing, expired, malformed, or
    issued to a different user than the access token.
    """

    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            stepup_token = request.headers.get("X-Stepup-Token", "").strip()
            if not stepup_token:
                return jsonify(
                    {
                        "error": "stepup_required",
                        "hint": "POST /api/auth/stepup with the current password "
                        "and pass the returned token in X-Stepup-Token",
                    }
                ), 401

            access_claims = get_jwt()
            access_user = str(access_claims.get("sub") or "")

            try:
                stepup_claims = _pyjwt.decode(
                    stepup_token,
                    settings.jwt_secret,
                    algorithms=["HS256"],
                )
            except _pyjwt.ExpiredSignatureError:
                return jsonify({"error": "stepup_expired"}), 401
            except _pyjwt.InvalidTokenError as exc:
                _log.info("auth.stepup.invalid", reason=str(exc))
                return jsonify({"error": "stepup_invalid"}), 401

            if not stepup_claims.get(_STEPUP_CLAIM_NAME):
                # A regular access token was passed instead of a step-up.
                return jsonify({"error": "not_a_stepup_token"}), 401
            if str(stepup_claims.get("sub") or "") != access_user:
                # Cross-user step-up reuse — refuse.
                return jsonify({"error": "stepup_user_mismatch"}), 401

            return fn(*args, **kwargs)

        return wrapper

    return decorator
