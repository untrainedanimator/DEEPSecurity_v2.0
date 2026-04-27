"""Rate limiter — backend-pluggable since v2.5.

The old SlidingWindowLimiter is kept here for backwards compatibility and
for tests that want a deterministic in-process counter, but the live
limiter now goes through ``deepsecurity.state_backend.get_backend()``,
which selects between an in-memory deque (single-node) or Redis
(multi-replica) based on ``DEEPSEC_STATE_BACKEND``.

The semantic the route layer cares about is unchanged: per-key cap of N
requests per window, with ``Retry-After`` set on a 429. The exit point —
``register_rate_limit(app, ...)`` — is API-compatible with v2.4.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Any

from flask import Flask, g, jsonify, request
from flask_jwt_extended import get_jwt, verify_jwt_in_request

from deepsecurity.logging_config import get_logger
from deepsecurity.state_backend import get_backend

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Legacy in-process limiter — retained for tests + back-compat.
# ---------------------------------------------------------------------------


class SlidingWindowLimiter:
    """Per-key rate limiter. `key` is usually the client IP or the JWT subject.

    Retained from v2.4 for backwards compatibility — new code should reach
    for ``state_backend.get_backend().rate_allow(...)`` instead, which is
    distributed-aware.
    """

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


# ---------------------------------------------------------------------------
# Flask integration
# ---------------------------------------------------------------------------


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
    """Install the global rate-limit ``before_request`` hook.

    Backend-agnostic — uses ``state_backend.get_backend()`` which is
    in-memory for single-node deployments (the v2.4 behaviour, byte-for-
    byte) and Redis when ``DEEPSEC_STATE_BACKEND=redis`` so replicas
    share the budget.
    """
    app.config["MAX_CONTENT_LENGTH"] = max_request_bytes

    @app.before_request
    def _guard() -> Any:
        # Never rate-limit health probes — orchestrators need them.
        if request.path in {"/healthz", "/readyz", "/metrics"}:
            return None

        key = _client_key()
        g.rl_key = key
        cap = auth_per_minute if key.startswith("user:") else anon_per_minute
        backend = get_backend()
        ok, retry = backend.rate_allow(key, cap, 60.0)
        if not ok:
            resp = jsonify({"error": "rate_limited", "retry_after_seconds": retry})
            resp.status_code = 429
            resp.headers["Retry-After"] = str(retry)
            return resp
        return None
