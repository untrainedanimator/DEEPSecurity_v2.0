"""v3.1 — production-hardening defaults applied by the model validator.

When ``DEEPSEC_ENV=production`` and the operator did NOT explicitly set
the protection switches, the Settings model should flip them ON. When
the operator did explicitly set them, the explicit value wins.
"""

from __future__ import annotations

import importlib

import pytest


def _fresh_settings(monkeypatch: pytest.MonkeyPatch) -> object:
    """Reload deepsecurity.config to pick up the current env state."""
    import deepsecurity.config as cfg

    importlib.reload(cfg)
    return cfg.Settings()


def test_dev_keeps_protection_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEEPSEC_ENV", "development")
    monkeypatch.setenv("DEEPSEC_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("DEEPSEC_JWT_SECRET", "y" * 32)
    monkeypatch.delenv("DEEPSEC_PROTECTION_TWIN_ENABLED", raising=False)
    monkeypatch.delenv("DEEPSEC_PROTECTION_SERVICE_INSTALL", raising=False)
    s = _fresh_settings(monkeypatch)
    assert s.protection_twin_enabled is False  # type: ignore[attr-defined]
    assert s.protection_service_install is False  # type: ignore[attr-defined]


def test_production_hardens_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEEPSEC_ENV", "production")
    monkeypatch.setenv("DEEPSEC_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("DEEPSEC_JWT_SECRET", "y" * 32)
    # Explicitly NOT setting the two protection knobs so the validator
    # gets to apply prod defaults.
    monkeypatch.delenv("DEEPSEC_PROTECTION_TWIN_ENABLED", raising=False)
    monkeypatch.delenv("DEEPSEC_PROTECTION_SERVICE_INSTALL", raising=False)
    s = _fresh_settings(monkeypatch)
    assert s.protection_twin_enabled is True  # type: ignore[attr-defined]
    assert s.protection_service_install is True  # type: ignore[attr-defined]


def test_production_respects_explicit_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """An operator who explicitly sets the env var to ``false`` in prod
    keeps it off — the validator must respect explicit operator intent."""
    monkeypatch.setenv("DEEPSEC_ENV", "production")
    monkeypatch.setenv("DEEPSEC_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("DEEPSEC_JWT_SECRET", "y" * 32)
    monkeypatch.setenv("DEEPSEC_PROTECTION_TWIN_ENABLED", "false")
    monkeypatch.setenv("DEEPSEC_PROTECTION_SERVICE_INSTALL", "false")
    s = _fresh_settings(monkeypatch)
    assert s.protection_twin_enabled is False  # type: ignore[attr-defined]
    assert s.protection_service_install is False  # type: ignore[attr-defined]
