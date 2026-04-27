"""Smoke tests for the YARA memory-scan module.

These tests don't require ``yara-python`` to be installed — when the
module is missing, ``compile_rules`` returns None and the tests verify
that fall-through behaviour. When YARA *is* installed, additional tests
exercise the actual matching path.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from deepsecurity.memory_scan import yara_scan


def test_compile_rules_returns_none_without_yara_module(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """If ``import yara`` fails, compile_rules degrades gracefully."""
    # Hide any installed yara module from this import attempt.
    monkeypatch.setitem(sys.modules, "yara", None)
    rules = yara_scan.compile_rules(tmp_path)
    assert rules is None


def test_compile_rules_returns_none_when_dir_missing(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "does-not-exist"
    rules = yara_scan.compile_rules(missing)
    assert rules is None


def test_compile_rules_returns_none_when_dir_empty(tmp_path: Path) -> None:
    # Empty dir → no rule files → no compiled object.
    rules = yara_scan.compile_rules(tmp_path)
    assert rules is None


def test_match_bytes_handles_none_rules() -> None:
    assert yara_scan.match_bytes(None, b"anything") == []


def test_match_bytes_handles_empty_blob() -> None:
    fake_rules = MagicMock()
    fake_rules.match.return_value = ["unused"]
    assert yara_scan.match_bytes(fake_rules, b"") == []
    fake_rules.match.assert_not_called()


def test_match_bytes_returns_matches_from_rules() -> None:
    fake_match = MagicMock()
    fake_rules = MagicMock()
    fake_rules.match.return_value = [fake_match]
    out = yara_scan.match_bytes(fake_rules, b"some bytes")
    assert out == [fake_match]
    fake_rules.match.assert_called_once()


def test_match_bytes_swallows_exceptions() -> None:
    """A YARA timeout or rule-error must not crash the scan."""
    fake_rules = MagicMock()
    fake_rules.match.side_effect = RuntimeError("timeout / bad rule / etc.")
    assert yara_scan.match_bytes(fake_rules, b"data") == []


@pytest.mark.skipif(
    "yara" not in sys.modules and not __import__(
        "importlib"
    ).util.find_spec("yara"),
    reason="yara-python not installed — install via pip install deepsecurity[memory-yara]",
)
def test_compile_rules_loads_starter_pack() -> None:
    """When yara-python IS installed, the shipped starter.yar compiles."""
    starter_dir = Path("data/yara_rules")
    if not starter_dir.exists():
        pytest.skip("starter rules dir not present (run from repo root)")
    rules = yara_scan.compile_rules(starter_dir)
    assert rules is not None
