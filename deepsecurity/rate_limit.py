"""In-process sliding-window rate limiter.

Keeps v2.2 dependency-free. For multi-process deployments, swap this for
flask-limiter backed by Redis.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Any, Callable

from flask import Flask, g, jsonify, request
from flask_jwt_extended import get_jwt, verify_jwt_in_request


class SlidingWindowLimiter:
    """Per-key rate limiter. `key` is usually the client IP or the JWT subject."""

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        self._max = max_requests
        self._window = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds). retry_after_seconds is 0 if allowed."""
        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            q = self._events[key]
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= self._max:
                retry = max(1, int(q[0] + self._window - now))
                return False, retry
            q.append(now)
            return True, 0


def _client_key() -> str:
    """Prefer the authenticated subject; fall back to the connecting IP."""
    try:
        verify_jwt_in_request(optional=True)
        claims = get_jwt() or {}
        sub = claims.get("sub")
        if sub:
            return f"user:{sub}"
    except Exception:
        pass
    return f"ip:{request.headers.get('X-Forwarded-For', request.remote_addr or '-')}"


def register_rate_limit(
    app: Flask,
    *,
    anon_per_minute: int = 30,
    auth_per_minute: int = 120,
    max_request_bytes: int = 10 * 1024 * 1024,
) -> None:
    app.config["MAX_CONTENT_LENGTH"] = max_request_bytes
    limiter_anon = SlidingWindowLimiter(anon_per_minute, 60.0)
    limiter_auth = SlidingWindowLimiter(auth_per_minute, 60.0)

    @app.before_request
    def _guard() -> Any:
        # Never rate-limit health probes — orchestrators need them.
        if request.path in {"/healthz", "/readyz", "/metrics"}:
            return None

        key = _client_key()
        g.rl_key = key
        limiter = limiter_auth if key.startswith("user:") else limiter_anon
        ok, retry = limiter.allow(key)
        if not ok:
            resp = jsonify({"error": "rate_limited", "retry_after_seconds": retry})
            resp.status_code = 429
            resp.headers["Retry-After"] = str(retry)
            return resp
        return None
