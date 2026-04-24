"""Entropy calculation + MIME-aware baseline + whitelist."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from deepsecurity.scanner import (
    ARCHIVE_MIMES,
    MEDIA_MIMES,
    adaptive_baseline,
    calculate_entropy,
    is_mime_whitelisted,
)


def test_all_zeros_is_zero_entropy(tmp_path: Path) -> None:
    p = tmp_path / "zeros.bin"
    p.write_bytes(b"\x00" * 4096)
    assert calculate_entropy(p) == 0.0


def test_random_bytes_max_entropy(tmp_path: Path) -> None:
    p = tmp_path / "random.bin"
    p.write_bytes(os.urandom(4096))
    ent = calculate_entropy(p)
    # Uniform random should be very close to 8 bits/byte.
    assert 7.5 <= ent <= 8.0


def test_text_file_is_low_entropy(tmp_path: Path) -> None:
    p = tmp_path / "text.txt"
    p.write_text("the quick brown fox jumps over the lazy dog " * 100)
    ent = calculate_entropy(p)
    assert ent < 5.0


def test_missing_file_returns_zero(tmp_path: Path) -> None:
    assert calculate_entropy(tmp_path / "does-not-exist.bin") == 0.0


def test_clamped_between_zero_and_eight(tmp_path: Path) -> None:
    p = tmp_path / "x.bin"
    p.write_bytes(os.urandom(2048))
    ent = calculate_entropy(p)
    assert 0.0 <= ent <= 8.0


@pytest.mark.parametrize(
    "mime,expected_range",
    [
        ("text/plain", (3.5, 4.5)),
        ("application/json", (3.5, 4.5)),
        ("image/jpeg", (5.5, 6.5)),
        ("audio/mpeg", (5.5, 6.5)),
        ("video/mp4", (5.5, 6.5)),
        ("application/octet-stream", (4.5, 5.5)),
    ],
)
def test_baseline_adapts_to_mime(mime: str, expected_range: tuple[float, float]) -> None:
    b = adaptive_baseline(mime)
    low, high = expected_range
    assert low <= b <= high


def test_baseline_respects_override() -> None:
    assert adaptive_baseline("text/plain", override=7.0) == 7.0


def test_mime_whitelist_covers_common_media() -> None:
    assert is_mime_whitelisted("image/jpeg")
    assert is_mime_whitelisted("audio/mpeg")
    assert is_mime_whitelisted("video/mp4")
    assert is_mime_whitelisted("application/zip")
    assert not is_mime_whitelisted("application/octet-stream")
    assert not is_mime_whitelisted("text/plain")


def test_mime_whitelist_exhaustive() -> None:
    """Guard against accidentally emptying the whitelist."""
    assert len(MEDIA_MIMES) >= 10
    assert len(ARCHIVE_MIMES) >= 5
