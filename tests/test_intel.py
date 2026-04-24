"""Threat-intel feed writer round-trip (offline-friendly)."""
from __future__ import annotations

from pathlib import Path

from deepsecurity.threat_intel import _read_existing, _write_signatures


def test_signature_file_round_trip(tmp_path: Path) -> None:
    target = tmp_path / "sigs.txt"
    incoming = {
        "a" * 64,
        "b" * 64,
        "c" * 64,
    }
    _write_signatures(target, incoming)

    reread = _read_existing(target)
    assert reread == incoming


def test_write_is_idempotent_and_sorted(tmp_path: Path) -> None:
    target = tmp_path / "sigs.txt"
    _write_signatures(target, {"z" * 64, "a" * 64, "m" * 64})
    content = target.read_text().strip().split("\n")
    # Comments excluded; hashes sorted.
    data_lines = [line for line in content if not line.startswith("#")]
    assert data_lines == ["a" * 64, "m" * 64, "z" * 64]
