"""Tests for the v2.5 backend abstraction.

Both InMemoryBackend and the Redis path (via fakeredis) are exercised so
the contract documented in deepsecurity.state_backend.StateBackend is
proven for both implementations. The behavioural tests run twice via
parametrize.
"""

from __future__ import annotations

import pytest

from deepsecurity.state_backend import (
    InMemoryBackend,
    RedisBackend,
    ScanSnapshotData,
    get_backend,
    reset_backend,
)


def _redis_backend() -> RedisBackend:
    fakeredis = pytest.importorskip("fakeredis")
    client = fakeredis.FakeStrictRedis(decode_responses=True)
    return RedisBackend("redis://fake/0", client=client)


@pytest.fixture(params=["memory", "redis"])
def backend(request):
    if request.param == "memory":
        return InMemoryBackend()
    return _redis_backend()


# ---------- rate limiter ----------------------------------------------------


def test_rate_allow_lets_through_under_cap(backend) -> None:
    for _ in range(5):
        ok, retry = backend.rate_allow("k1", max_requests=5, window_seconds=60.0)
        assert ok is True, "first 5 requests should be allowed"
        assert retry == 0


def test_rate_allow_blocks_over_cap(backend) -> None:
    for _ in range(3):
        backend.rate_allow("k2", max_requests=3, window_seconds=60.0)
    ok, retry = backend.rate_allow("k2", max_requests=3, window_seconds=60.0)
    assert ok is False, "the 4th request should be denied"
    assert retry >= 1


def test_rate_allow_isolates_keys(backend) -> None:
    for _ in range(2):
        backend.rate_allow("alice", max_requests=2, window_seconds=60.0)
    # alice is now at her cap…
    ok_a, _ = backend.rate_allow("alice", max_requests=2, window_seconds=60.0)
    assert ok_a is False
    # …but bob is independent.
    ok_b, _ = backend.rate_allow("bob", max_requests=2, window_seconds=60.0)
    assert ok_b is True


# ---------- scan lease ------------------------------------------------------


def test_scan_acquire_is_singleton(backend) -> None:
    assert backend.scan_acquire(session_id=42, ttl_seconds=10) is True
    assert backend.scan_acquire(session_id=43, ttl_seconds=10) is False


def test_scan_release_lets_next_scan_acquire(backend) -> None:
    assert backend.scan_acquire(session_id=1, ttl_seconds=10) is True
    backend.scan_release()
    assert backend.scan_acquire(session_id=2, ttl_seconds=10) is True


def test_scan_state_get_returns_default_when_unset(backend) -> None:
    snap = backend.scan_state_get()
    assert isinstance(snap, ScanSnapshotData)
    assert snap.running is False
    assert snap.session_id is None


def test_scan_state_set_round_trips(backend) -> None:
    snap = ScanSnapshotData(running=True, session_id=99, scanned_count=7)
    backend.scan_state_set(snap, ttl_seconds=10)
    got = backend.scan_state_get()
    assert got.running is True
    assert got.session_id == 99
    assert got.scanned_count == 7


def test_scan_state_mutate_is_atomic(backend) -> None:
    backend.scan_acquire(session_id=1, ttl_seconds=10)
    for _ in range(10):

        def _inc(s: ScanSnapshotData) -> None:
            s.scanned_count += 1

        backend.scan_state_mutate(_inc)
    assert backend.scan_state_get().scanned_count == 10


# ---------- factory --------------------------------------------------------


def test_factory_default_is_memory(monkeypatch) -> None:
    monkeypatch.delenv("DEEPSEC_STATE_BACKEND", raising=False)
    reset_backend()
    b = get_backend()
    assert isinstance(b, InMemoryBackend)


def test_factory_fake_uses_fakeredis(monkeypatch) -> None:
    pytest.importorskip("fakeredis")
    monkeypatch.setenv("DEEPSEC_STATE_BACKEND", "fake")
    # Bust the settings + backend caches.
    from deepsecurity.config import get_settings

    get_settings.cache_clear()
    reset_backend()
    b = get_backend()
    assert isinstance(b, RedisBackend)
    # Must work end-to-end through the fake client.
    assert b.scan_acquire(session_id=7, ttl_seconds=5) is True
    assert b.scan_acquire(session_id=8, ttl_seconds=5) is False
