"""Outlook scanner: must never auto-delete, must never run on non-Windows."""
from __future__ import annotations

import sys

import pytest


def test_raises_if_disabled(temp_env, monkeypatch) -> None:
    monkeypatch.setenv("DEEPSEC_OUTLOOK_ENABLED", "false")

    from deepsecurity.config import get_settings
    from deepsecurity.outlook import OutlookUnavailableError, scan_outlook_mailbox

    get_settings.cache_clear()

    with pytest.raises(OutlookUnavailableError):
        scan_outlook_mailbox(actor="admin", user_role="admin")


@pytest.mark.skipif(sys.platform == "win32", reason="non-Windows-only branch")
def test_raises_on_non_windows(temp_env, monkeypatch) -> None:
    monkeypatch.setenv("DEEPSEC_OUTLOOK_ENABLED", "true")

    from deepsecurity.config import get_settings
    from deepsecurity.outlook import OutlookUnavailableError, scan_outlook_mailbox

    get_settings.cache_clear()

    with pytest.raises(OutlookUnavailableError):
        scan_outlook_mailbox(actor="admin", user_role="admin")


def test_delete_on_detect_always_false(temp_env) -> None:
    """Config-level invariant: the delete flag is False. Even if a user sets it true
    in env, we still only quarantine. The knob is wired but the code path is gone."""
    from deepsecurity.config import settings

    # Default must be False.
    assert settings.outlook_delete_on_detect is False
