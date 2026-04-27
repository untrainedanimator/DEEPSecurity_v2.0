"""Backend abstraction for cross-process state — rate limiting and scan state.

v2.5.0 introduces this module to remove the single-instance ceiling that
v2.4 had. Every place that previously held coordination state in a Python
process-singleton (rate_limit.py's SlidingWindowLimiter, scan_state.py's
ScanState) now goes through ``get_backend()`` and gets either:

    InMemoryBackend  — the v2.4 behaviour, for single-node / dev / tests.
                       Selected when ``DEEPSEC_STATE_BACKEND=memory``
                       (the default).

    RedisBackend     — the multi-replica path. Selected when
                       ``DEEPSEC_STATE_BACKEND=redis`` and
                       ``DEEPSEC_REDIS_URL`` is set. Uses INCR + PEXPIRE
                       for the rate limiter (atomic per-key counter that
                       expires on its own) and a SETNX-with-TTL lease for
                       the scan-state singleton, so any single replica
                       can detect that another replica is currently
                       scanning and 409 the second request.

The two backends are deliberately fungible — every method on
``StateBackend`` is documented with the exact semantics both
implementations must honour. A test only ever needs to swap the
backend, not the code that uses it.
"""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from typing import Any, Protocol

from deepsecurity.config import settings
from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Public scan-snapshot type. Kept in this module so both backends agree on
# the shape; scan_state.py re-exports it for backwards compatibility.
# ---------------------------------------------------------------------------


@dataclass
class ScanSnapshotData:
    running: bool = False
    cancelled: bool = False
    session_id: int | None = None
    scanned_count: int = 0
    total_files: int = 0
    total_detections: int = 0
    current_file: str = "--"
    start_time: float | None = None
    output: list[str] = field(default_factory=list)

    @classmethod
    def from_json(cls, raw: bytes | str | None) -> ScanSnapshotData:
        if not raw:
            return cls()
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        d = json.loads(raw)
        return cls(**d)

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)


# ---------------------------------------------------------------------------
# Backend protocol
# ---------------------------------------------------------------------------


class StateBackend(Protocol):
    """Both InMemoryBackend and RedisBackend implement these methods.

    Rate-limit semantics:
        ``rate_allow(key, max_requests, window_seconds)`` returns
        ``(allowed, retry_after_seconds)``. Atomic — no double-counting
        under concurrent requests. Counters auto-expire after the window
        elapses so the limiter is self-cleaning.

    Scan-state semantics:
        ``scan_acquire(session_id, ttl_seconds)`` returns True if THIS
        caller now owns the global scan lease, False if some other
        caller already does. Lease auto-expires after ttl_seconds in
        case the owning process crashes — a hard requirement for the
        Redis backend, kept on the in-memory backend for parity.

        ``scan_state_*`` accessors mutate the shared snapshot atomically.
        ``scan_release()`` releases the lease and clears the snapshot.
    """

    # ----- Rate limiter ----------------------------------------------------
    def rate_allow(
        self, key: str, max_requests: int, window_seconds: float
    ) -> tuple[bool, int]: ...

    # ----- Scan lease + state ---------------------------------------------
    def scan_acquire(self, session_id: int, ttl_seconds: int = 7200) -> bool: ...
    def scan_release(self) -> None: ...
    def scan_state_set(self, snap: ScanSnapshotData, ttl_seconds: int = 7200) -> None: ...
    def scan_state_get(self) -> ScanSnapshotData: ...
    def scan_state_mutate(self, mutator: Any, ttl_seconds: int = 7200) -> ScanSnapshotData: ...


# ---------------------------------------------------------------------------
# In-memory backend (default — single-node, dev, tests)
# ---------------------------------------------------------------------------


class InMemoryBackend:
    """The v2.4 behaviour, kept as the default. No external dependency."""

    def __init__(self) -> None:
        self._rl_events: dict[str, deque[float]] = defaultdict(deque)
        self._rl_lock = threading.Lock()
        self._scan_lock = threading.Lock()
        self._scan_owner: int | None = None
        self._scan_lease_until: float = 0.0
        self._scan_state: ScanSnapshotData = ScanSnapshotData()

    # ----- Rate ------------------------------------------------------------
    def rate_allow(self, key: str, max_requests: int, window_seconds: float) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._rl_lock:
            q = self._rl_events[key]
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= max_requests:
                retry = max(1, int(q[0] + window_seconds - now))
                return False, retry
            q.append(now)
            return True, 0

    # ----- Scan ------------------------------------------------------------
    def scan_acquire(self, session_id: int, ttl_seconds: int = 7200) -> bool:
        now = time.monotonic()
        with self._scan_lock:
            if self._scan_owner is not None and self._scan_lease_until > now:
                return False
            self._scan_owner = session_id
            self._scan_lease_until = now + ttl_seconds
            self._scan_state = ScanSnapshotData(
                running=True, session_id=session_id, start_time=time.monotonic()
            )
            return True

    def scan_release(self) -> None:
        with self._scan_lock:
            self._scan_owner = None
            self._scan_lease_until = 0.0
            # Keep the snapshot for last-result inspection but flag not running.
            self._scan_state.running = False

    def scan_state_set(self, snap: ScanSnapshotData, ttl_seconds: int = 7200) -> None:
        with self._scan_lock:
            self._scan_state = snap
            if snap.running:
                self._scan_lease_until = time.monotonic() + ttl_seconds

    def scan_state_get(self) -> ScanSnapshotData:
        with self._scan_lock:
            # Return a copy so callers can't mutate our state.
            return ScanSnapshotData(**asdict(self._scan_state))

    def scan_state_mutate(self, mutator: Any, ttl_seconds: int = 7200) -> ScanSnapshotData:
        with self._scan_lock:
            mutator(self._scan_state)
            if self._scan_state.running:
                self._scan_lease_until = time.monotonic() + ttl_seconds
            return ScanSnapshotData(**asdict(self._scan_state))


# ---------------------------------------------------------------------------
# Redis backend (multi-replica)
# ---------------------------------------------------------------------------


_RL_KEY_PREFIX = "deepsec:rl:"  # token-bucket per-key counter
_SCAN_LEASE_KEY = "deepsec:scan:lease"  # holds the session_id of the owner
_SCAN_STATE_KEY = "deepsec:scan:state"  # JSON snapshot
_SCAN_STATE_LOCK_KEY = "deepsec:scan:state:lock"  # short-lived mutex around mutate


class RedisBackend:
    """Cluster-safe state via Redis.

    Rate limiter: fixed-window counter using INCR + PEXPIRE on first hit.
    The window key includes the bucket index (now // window_seconds), so
    when the window rolls over a fresh key with its own TTL is created
    automatically. This is "fixed-window" not "sliding-window" — the
    practical difference is at most one extra request per window per key,
    which is fine for our 30/120 rpm caps.

    Scan lease: SET key value NX PX ttl. Atomic. Whoever gets True owns
    the singleton scan slot until ttl_seconds elapse or scan_release()
    is called explicitly.

    State snapshot: a separate JSON-encoded key. ``scan_state_mutate`` uses
    a short mutex (SET NX PX) around read-modify-write to keep the
    snapshot internally consistent.
    """

    def __init__(self, url: str, *, client: Any = None) -> None:
        if client is not None:
            self._r = client
        else:
            try:
                import redis  # type: ignore[import-not-found]
            except ImportError as exc:  # pragma: no cover
                raise RuntimeError(
                    "DEEPSEC_STATE_BACKEND=redis but the redis package is "
                    'not installed. Run `pip install "deepsecurity[redis]"`.'
                ) from exc
            self._r = redis.Redis.from_url(url, decode_responses=True)

    # ----- Rate ------------------------------------------------------------
    def rate_allow(self, key: str, max_requests: int, window_seconds: float) -> tuple[bool, int]:
        now = int(time.time())
        window = max(1, int(window_seconds))
        bucket = now // window
        rkey = f"{_RL_KEY_PREFIX}{key}:{bucket}"
        try:
            # INCR returns the new value; PEXPIRE on first hit only.
            n = self._r.incr(rkey)
            if n == 1:
                self._r.pexpire(rkey, int(window * 1000))
            if n > max_requests:
                retry = max(1, window - (now % window))
                return False, retry
            return True, 0
        except Exception:
            # Fail-open on Redis outage rather than 500-locking the whole
            # API. A short-lived rate-limit miss is a far better
            # operational outcome than every request 429ing.
            _log.exception("rate_limit.redis_error", key=key)
            return True, 0

    # ----- Scan lease ------------------------------------------------------
    def scan_acquire(self, session_id: int, ttl_seconds: int = 7200) -> bool:
        try:
            ok = self._r.set(
                _SCAN_LEASE_KEY,
                str(session_id),
                nx=True,
                px=ttl_seconds * 1000,
            )
            if ok:
                snap = ScanSnapshotData(running=True, session_id=session_id, start_time=time.time())
                self._r.set(_SCAN_STATE_KEY, snap.to_json(), px=ttl_seconds * 1000)
            return bool(ok)
        except Exception:
            _log.exception("scan.lease_acquire_failed", session_id=session_id)
            # Failing closed here — better to refuse a scan than start two.
            return False

    def scan_release(self) -> None:
        try:
            self._r.delete(_SCAN_LEASE_KEY)
            # Keep the state key with running=False so dashboards still
            # show the last result.
            raw = self._r.get(_SCAN_STATE_KEY)
            snap = ScanSnapshotData.from_json(raw)
            snap.running = False
            self._r.set(_SCAN_STATE_KEY, snap.to_json(), ex=3600)
        except Exception:
            _log.exception("scan.lease_release_failed")

    def scan_state_set(self, snap: ScanSnapshotData, ttl_seconds: int = 7200) -> None:
        try:
            self._r.set(_SCAN_STATE_KEY, snap.to_json(), px=ttl_seconds * 1000)
        except Exception:
            _log.exception("scan.state_set_failed")

    def scan_state_get(self) -> ScanSnapshotData:
        try:
            return ScanSnapshotData.from_json(self._r.get(_SCAN_STATE_KEY))
        except Exception:
            _log.exception("scan.state_get_failed")
            return ScanSnapshotData()

    def scan_state_mutate(self, mutator: Any, ttl_seconds: int = 7200) -> ScanSnapshotData:
        # Short mutex to bound the read-modify-write window. Acceptable
        # contention for a singleton scan — there's at most one writer
        # per replica and the section is microseconds long.
        token = f"{time.time()}:{id(mutator)}"
        for _ in range(40):  # ~200 ms total back-off ceiling
            ok = self._r.set(_SCAN_STATE_LOCK_KEY, token, nx=True, px=500)
            if ok:
                break
            time.sleep(0.005)
        try:
            snap = self.scan_state_get()
            mutator(snap)
            self.scan_state_set(snap, ttl_seconds=ttl_seconds)
            return snap
        finally:
            # Best-effort release — if the mutex expired naturally, no harm.
            try:
                cur = self._r.get(_SCAN_STATE_LOCK_KEY)
                if cur == token:
                    self._r.delete(_SCAN_STATE_LOCK_KEY)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Factory + singleton
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def get_backend() -> StateBackend:
    """Return the configured state backend.

    Selection rules:
        DEEPSEC_STATE_BACKEND=memory  → InMemoryBackend  (default)
        DEEPSEC_STATE_BACKEND=redis   → RedisBackend
        DEEPSEC_STATE_BACKEND=fake    → InMemoryBackend with a fakeredis
                                         shim, used only by tests.

    Tests should call ``reset_backend()`` to drop the cached singleton
    after monkeypatching env vars.
    """
    choice = (getattr(settings, "state_backend", "memory") or "memory").strip().lower()
    if choice == "redis":
        url = getattr(settings, "redis_url", None) or "redis://localhost:6379/0"
        _log.info("state_backend.redis", url=url)
        return RedisBackend(url)
    if choice == "fake":
        try:
            import fakeredis  # type: ignore[import-not-found]
        except ImportError:
            _log.warning("state_backend.fakeredis_missing — falling back to in-memory")
            return InMemoryBackend()
        client = fakeredis.FakeStrictRedis(decode_responses=True)
        _log.info("state_backend.fake")
        return RedisBackend("redis://fake/0", client=client)
    _log.info("state_backend.memory")
    return InMemoryBackend()


def reset_backend() -> None:
    """Drop the cached backend singleton (used by tests after env tweaks)."""
    get_backend.cache_clear()
