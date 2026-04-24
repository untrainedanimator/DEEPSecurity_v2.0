"""Settings validation — we want the app to refuse to boot with bad config."""
from __future__ import annotations

import pytest
from pydantic import ValidationError


def test_refuses_wildcard_cors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEEPSEC_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("DEEPSEC_JWT_SECRET", "x" * 32)
    monkeypatch.setenv("DEEPSEC_CORS_ORIGINS", "*")

    from deepsecurity.config import Settings

    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_refuses_placeholder_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEEPSEC_SECRET_KEY", "change-me-to-a-32-char-random-string")
    monkeypatch.setenv("DEEPSEC_JWT_SECRET", "x" * 32)
    from deepsecurity.config import Settings

    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_accepts_explicit_origin_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEEPSEC_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("DEEPSEC_JWT_SECRET", "y" * 32)
    monkeypatch.setenv(
        "DEEPSEC_CORS_ORIGINS",
        "http://localhost:5173,https://deepsec.example",
    )

    from deepsecurity.config import Settings

    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.cors_origin_list == ["http://localhost:5173", "https://deepsec.example"]


def test_jwt_access_minutes_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEEPSEC_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("DEEPSEC_JWT_SECRET", "y" * 32)
    monkeypatch.setenv("DEEPSEC_JWT_ACCESS_MINUTES", "0")

    from deepsecurity.config import Settings

    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # type: ignore[call-arg]
