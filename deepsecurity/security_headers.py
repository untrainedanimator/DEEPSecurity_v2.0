"""HTTP security headers applied to every response."""
from __future__ import annotations

from typing import Any

from flask import Flask


def register_security_headers(app: Flask) -> None:
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
        # Strict-Transport-Security — only meaningful over HTTPS, cheap to always send.
        resp.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
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
