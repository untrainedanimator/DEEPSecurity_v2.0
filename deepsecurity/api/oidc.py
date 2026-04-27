"""OIDC identity provider — v2.5 replacement for the env-driven dev user.

Generic OIDC. Bring your own provider:
    DEEPSEC_OIDC_DISCOVERY_URL  e.g. https://accounts.google.com/.well-known/openid-configuration
                                e.g. https://login.microsoftonline.com/<tenant>/v2.0/.well-known/openid-configuration
                                e.g. https://your-domain.auth0.com/.well-known/openid-configuration
                                e.g. https://keycloak.example/realms/main/.well-known/openid-configuration
    DEEPSEC_OIDC_CLIENT_ID
    DEEPSEC_OIDC_CLIENT_SECRET
    DEEPSEC_OIDC_REDIRECT_URI   must be registered with the IdP and end in /api/auth/oidc/callback

Role mapping: DEEPSEC_OIDC_ROLE_CLAIM (default "groups") names a list-
valued claim returned by the IdP. The values are matched against
DEEPSEC_OIDC_ADMIN_GROUPS / SECURITY_GROUPS / ANALYST_GROUPS (comma-
separated lists). First match wins, in admin → security → analyst order.
If none match and DEEPSEC_OIDC_DEFAULT_ROLE is empty, the login is
DENIED — strict default that prevents accidental privilege escalation
when an IdP claim shape changes.

The dev-password endpoint at /api/auth/login is now gated by
DEEPSEC_ENV != "production" — production deployments cannot fall back
to it.
"""

from __future__ import annotations

import secrets
from typing import Any

from flask import Blueprint, jsonify, redirect, request, session, url_for
from flask_jwt_extended import create_access_token

from deepsecurity.audit import audit_log
from deepsecurity.config import settings
from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)
oidc_bp = Blueprint("oidc", __name__)


# ---------------------------------------------------------------------------
# OAuth client (lazy — authlib is an optional dep)
# ---------------------------------------------------------------------------


_OAUTH = None  # populated by init_oidc()


def _claim_list(raw: str) -> list[str]:
    return [g.strip() for g in raw.split(",") if g.strip()]


def init_oidc(app: Any) -> None:
    """Register the IdP with authlib if OIDC_ENABLED is set.

    Called from create_app(). No-op when OIDC is disabled — the
    /api/auth/oidc/* routes still register but return 503 explaining the
    config gap. That keeps the URL surface stable for the frontend.
    """
    if not settings.oidc_enabled:
        _log.info("oidc.disabled")
        return

    missing = []
    for k in ("oidc_discovery_url", "oidc_client_id", "oidc_client_secret", "oidc_redirect_uri"):
        if not getattr(settings, k, None):
            missing.append(k.upper())
    if missing:
        _log.warning("oidc.misconfigured", missing=missing)
        return

    try:
        from authlib.integrations.flask_client import OAuth
    except ImportError:
        _log.warning(
            "oidc.authlib_missing",
            hint='pip install "deepsecurity[oidc]"',
        )
        return

    global _OAUTH
    _OAUTH = OAuth(app)
    _OAUTH.register(
        name="deepsec_idp",
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret,
        server_metadata_url=settings.oidc_discovery_url,
        client_kwargs={"scope": settings.oidc_scopes},
    )
    _log.info(
        "oidc.registered",
        discovery=settings.oidc_discovery_url,
        client_id_tail=str(settings.oidc_client_id)[-6:],
    )


# ---------------------------------------------------------------------------
# Role mapping
# ---------------------------------------------------------------------------


def _map_role(claims: dict[str, Any]) -> str:
    """Pick an internal role from the OIDC claims, or "" to deny.

    Priority: admin > security > analyst > default. The role-claim is
    expected to be either a list of strings or a single string; both are
    handled.
    """
    raw = claims.get(settings.oidc_role_claim, [])
    if isinstance(raw, str):
        groups = [raw]
    else:
        groups = list(raw or [])

    admin_groups = set(_claim_list(settings.oidc_admin_groups))
    security_groups = set(_claim_list(settings.oidc_security_groups))
    analyst_groups = set(_claim_list(settings.oidc_analyst_groups))

    g = set(groups)
    if g & admin_groups:
        return "admin"
    if g & security_groups:
        return "security"
    if g & analyst_groups:
        return "analyst"
    return settings.oidc_default_role or ""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@oidc_bp.route("/login", methods=["GET"])
def oidc_login() -> Any:
    """Kick off an OIDC authorization-code flow.

    The IdP will bounce the browser back to /api/auth/oidc/callback with
    a code that we exchange server-side for an ID token + userinfo.
    """
    if not settings.oidc_enabled or _OAUTH is None:
        return jsonify({"error": "oidc_not_configured"}), 503

    nonce = secrets.token_urlsafe(24)
    session["oidc_nonce"] = nonce
    redirect_uri = settings.oidc_redirect_uri or url_for("oidc.oidc_callback", _external=True)
    return _OAUTH.deepsec_idp.authorize_redirect(redirect_uri=redirect_uri, nonce=nonce)


@oidc_bp.route("/callback", methods=["GET"])
def oidc_callback() -> Any:
    """Handle the IdP redirect, mint a DEEPSecurity JWT."""
    if not settings.oidc_enabled or _OAUTH is None:
        return jsonify({"error": "oidc_not_configured"}), 503

    try:
        token = _OAUTH.deepsec_idp.authorize_access_token()
    except Exception as exc:
        _log.warning("oidc.callback_failed", error=str(exc))
        try:
            audit_log(
                actor="anonymous",
                action="auth.oidc_callback",
                status="denied",
                details={"reason": "code_exchange_failed"},
            )
        except Exception:
            _log.exception("auth.audit_failed")
        return jsonify({"error": "oidc_token_exchange_failed"}), 401

    # authlib parses + verifies the ID token if 'nonce' was passed.
    nonce = session.pop("oidc_nonce", None)
    try:
        userinfo = _OAUTH.deepsec_idp.parse_id_token(token, nonce=nonce)
    except Exception:
        _log.exception("oidc.id_token_invalid")
        return jsonify({"error": "oidc_id_token_invalid"}), 401

    claims = dict(userinfo or {})
    # Some providers put group claims in the access-token userinfo endpoint
    # rather than the ID token. Best-effort merge.
    try:
        ui = _OAUTH.deepsec_idp.userinfo(token=token)
        for k, v in (ui or {}).items():
            claims.setdefault(k, v)
    except Exception:
        pass

    subject = (
        claims.get("preferred_username") or claims.get("email") or claims.get("sub") or "oidc-user"
    )
    role = _map_role(claims)
    if not role:
        _log.info(
            "oidc.role_denied",
            sub=subject,
            available_claims=sorted(claims.keys()),
        )
        try:
            audit_log(
                actor=subject,
                action="auth.oidc_callback",
                status="denied",
                details={"reason": "no_matching_role"},
            )
        except Exception:
            _log.exception("auth.audit_failed")
        return jsonify({"error": "oidc_role_denied", "subject": subject}), 403

    access_token = create_access_token(
        identity=str(subject),
        additional_claims={"role": role, "iss": "oidc"},
    )

    try:
        audit_log(
            actor=subject,
            action="auth.oidc_login",
            status="ok",
            details={"role": role, "iss": claims.get("iss")},
        )
    except Exception:
        _log.exception("auth.audit_failed_on_ok")

    # Frontends typically want the token in the URL fragment so the SPA
    # can read it without it landing in server logs.
    if request.args.get("format") == "json":
        return jsonify({"access_token": access_token, "role": role, "subject": subject}), 200
    fe = request.args.get("fe") or "/"
    sep = "&" if "#" in fe else "#"
    return redirect(f"{fe}{sep}access_token={access_token}&role={role}")
