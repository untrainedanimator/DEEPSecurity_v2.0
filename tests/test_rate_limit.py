"""In-process sliding-window rate limiter."""
from __future__ import annotations

import time

from deepsecurity.rate_limit import SlidingWindowLimiter


def test_allows_under_limit() -> None:
    lim = SlidingWindowLimiter(max_requests=3, window_seconds=10)
    for _ in range(3):
        ok, retry = lim.allow("k")
        assert ok
        assert retry == 0


def test_blocks_over_limit() -> None:
    lim = SlidingWindowLimiter(max_requests=2, window_seconds=10)
    assert lim.allow("k")[0]
    assert lim.allow("k")[0]
    ok, retry = lim.allow("k")
    assert not ok
    assert retry >= 1


def test_window_slides() -> None:
    lim = SlidingWindowLimiter(max_requests=1, window_seconds=0.05)
    assert lim.allow("k")[0]
    assert not lim.allow("k")[0]
    time.sleep(0.1)
    assert lim.allow("k")[0]


def test_keys_are_independent() -> None:
    lim = SlidingWindowLimiter(max_requests=1, window_seconds=10)
    assert lim.allow("a")[0]
    assert lim.allow("b")[0]
    assert not lim.allow("a")[0]
    assert not lim.allow("b")[0]
