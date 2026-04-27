"""HTTP security headers applied to every response."""

from __future__ import annotations

from typing import Any

from flask import Flask


def register_security_headers(app: Flask) -> None:
    # Resolve HSTS once at boot — the value depends on settings.tls_mode.
    # When TLS is ON (cert or self-signed) we add ``preload`` so a future
    # operator who submits the domain to the HSTS preload list gets the
    # browser-builtin enforcement. When TLS is OFF we still send HSTS
    # (it's free and harmless over plain HTTP) but without preload to
    # avoid a misconfigured edge accidentally locking users out.
    try:
        from deepsecurity.config import settings

        max_age = int(getattr(settings, "tls_hsts_max_age", 31_536_000))
        tls_on = getattr(settings, "tls_mode", "off") != "off"
    except Exception:
        # never fail header registration — fall back to defaults
        max_age = 31_536_000
        tls_on = False
    hsts_value = f"max-age={max_age}; includeSubDomains" + ("; preload" if tls_on else "")

    @app.after_request
    def _apply(resp: Any) -> Any:
        # Frame / clickjacking
        resp.headers.setdefault("X-Frame-Options", "DENY")
        # MIME sniffing
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        # Referrer
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        # Permissions policy — disable every major browser sensor API.
        resp.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), camera=(), microphone=(), payment=(), usb=()",
        )
        # Strict-Transport-Security — reinforced to the configured max-age.
        resp.headers.setdefault("Strict-Transport-Security", hsts_value)
        # CSP — tight default, adjust for the frontend if it needs more.
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'",
        )
        return resp
