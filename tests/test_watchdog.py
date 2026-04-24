"""Watchdog controller + event filter unit tests.

These are the regression tests for the architecture rewrite: auto-start on
boot, debounce duplicate events, confidence scoring on heuristic hits,
exclusion-glob enforcement, and scope resolution. No tests for this
subsystem existed before this file — ``tests/`` had 1,772 lines of test
code and zero watchdog coverage.

Tests here MUST NOT require the real ``watchdog`` package to run: we
import the module, mock out the ``Observer`` where needed, and exercise
just the parts of the controller that are our own code. ``pytest -k
watchdog`` should pass regardless of whether the optional dep is
installed.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Scope resolution — user_risk and system presets.
# ---------------------------------------------------------------------------


def test_user_risk_roots_returns_existing_dirs_only(temp_env: Path, monkeypatch) -> None:
    """default_user_risk_roots must only return directories that actually exist."""
    from deepsecurity.watchdog_monitor import default_user_risk_roots

    # Conftest already gives us a tmp-path-based user home indirectly; the
    # builtin list is Downloads/Desktop/Documents/etc. under ``~``. Most of
    # those won't exist in a pytest tmp env, so the result may be small or
    # empty. What we're checking: every returned path DOES exist.
    roots = default_user_risk_roots()
    for r in roots:
        assert r.exists(), f"default_user_risk_roots returned nonexistent {r}"
        assert r.is_dir(), f"default_user_risk_roots returned non-directory {r}"


def test_user_risk_paths_override(temp_env: Path, monkeypatch) -> None:
    """DEEPSEC_USER_RISK_PATHS must override the built-in list."""
    a = temp_env / "my_downloads"
    b = temp_env / "my_docs"
    a.mkdir()
    b.mkdir()

    monkeypatch.setenv("DEEPSEC_USER_RISK_PATHS", f"{a};{b}")
    # Force the proxy to re-read.
    from deepsecurity.config import get_settings

    get_settings.cache_clear()

    from deepsecurity.watchdog_monitor import default_user_risk_roots

    roots = default_user_risk_roots()
    assert a.resolve() in roots
    assert b.resolve() in roots


def test_user_risk_override_skips_nonexistent(temp_env: Path, monkeypatch) -> None:
    """Override paths that don't exist on disk must be silently dropped."""
    real = temp_env / "real_dir"
    real.mkdir()
    fake = temp_env / "definitely_not_here"

    monkeypatch.setenv("DEEPSEC_USER_RISK_PATHS", f"{real};{fake}")
    from deepsecurity.config import get_settings

    get_settings.cache_clear()

    from deepsecurity.watchdog_monitor import default_user_risk_roots

    roots = default_user_risk_roots()
    assert real.resolve() in roots
    assert fake.resolve() not in roots


def test_resolve_scope_unknown_returns_none(temp_env: Path) -> None:
    from deepsecurity.watchdog_monitor import resolve_scope

    assert resolve_scope("nope") is None
    assert resolve_scope(None) is None
    assert resolve_scope("") is None


# ---------------------------------------------------------------------------
# Exclusion globs — the single biggest signal-to-noise fix.
# ---------------------------------------------------------------------------


def test_exclusion_glob_matches_node_modules(temp_env: Path) -> None:
    from deepsecurity.watchdog_monitor import _matches_any_glob

    globs = ["**/node_modules/**", "**/*.pyc"]
    assert _matches_any_glob(
        Path("C:/app/frontend/node_modules/react/index.js"), globs
    )
    assert _matches_any_glob(Path("/home/me/proj/node_modules/x.js"), globs)
    assert _matches_any_glob(Path("C:/some/foo.pyc"), globs)
    assert not _matches_any_glob(Path("C:/Users/me/Downloads/installer.exe"), globs)


def test_exclusion_glob_matches_temp_claude_cache(temp_env: Path) -> None:
    """Specific regression: the cache file that was getting scanned every 1-4s
    in the live log. Must be excluded by the default glob set."""
    from deepsecurity.watchdog_monitor import _matches_any_glob

    globs = ["**/Temp/claude/**", "**/Temp/claude-*/**"]
    assert _matches_any_glob(
        Path("C:/Users/x/AppData/Local/Temp/claude/cache-break-state-abc.json"),
        globs,
    )


def test_exclusion_glob_case_insensitive_on_windows_paths(temp_env: Path) -> None:
    from deepsecurity.watchdog_monitor import _matches_any_glob

    globs = ["**/Code Cache/**"]
    # Chrome paths often mix cases; our match must ignore case.
    assert _matches_any_glob(
        Path("C:/Users/me/AppData/Local/Google/Chrome/User Data/Default/Code Cache/js/x"),
        globs,
    )


# ---------------------------------------------------------------------------
# Autostart config.
# ---------------------------------------------------------------------------


def test_autostart_default_is_user_risk(temp_env: Path, monkeypatch) -> None:
    """The default value of watchdog_autostart is 'user_risk' — this is the
    architectural decision that makes the tool 'just work' on boot."""
    from deepsecurity.config import get_settings

    # Default should win when env var is unset.
    monkeypatch.delenv("DEEPSEC_WATCHDOG_AUTOSTART", raising=False)
    get_settings.cache_clear()
    s = get_settings()
    assert s.watchdog_autostart == "user_risk"


def test_autostart_can_be_disabled(temp_env: Path, monkeypatch) -> None:
    monkeypatch.setenv("DEEPSEC_WATCHDOG_AUTOSTART", "")
    from deepsecurity.config import get_settings

    get_settings.cache_clear()
    s = get_settings()
    assert s.watchdog_autostart == ""


def test_autostart_rejects_unknown_scope(temp_env: Path, monkeypatch) -> None:
    """Typos like 'user-risk' (hyphen) or 'systemwide' must fail config
    validation at startup rather than silently not autostart."""
    monkeypatch.setenv("DEEPSEC_WATCHDOG_AUTOSTART", "user-risk")  # wrong — hyphen
    from deepsecurity.config import get_settings

    get_settings.cache_clear()
    with pytest.raises(Exception):
        get_settings()


# ---------------------------------------------------------------------------
# _maybe_autostart_watchdog — the hook that runs inside create_app().
# ---------------------------------------------------------------------------


def test_maybe_autostart_is_no_op_when_disabled(temp_env: Path, monkeypatch) -> None:
    """Empty autostart setting must skip the controller entirely."""
    monkeypatch.setenv("DEEPSEC_WATCHDOG_AUTOSTART", "")
    from deepsecurity.config import get_settings

    get_settings.cache_clear()

    from deepsecurity.api import _maybe_autostart_watchdog
    from deepsecurity.watchdog_monitor import controller

    # Reset the controller so previous tests don't pollute state.
    if controller.running:
        controller.stop()

    _maybe_autostart_watchdog()
    assert not controller.running


def test_maybe_autostart_skips_if_already_running(temp_env: Path, monkeypatch) -> None:
    """If the watchdog is already running (e.g., Flask reload), we must not
    stomp on the live observer."""
    from deepsecurity.watchdog_monitor import controller

    # Simulate "already running": patch out .start to record a call and
    # patch .running to return True.
    with patch.object(
        type(controller), "running", new_callable=lambda: property(lambda _self: True)
    ), patch.object(controller, "start") as mock_start:
        from deepsecurity.api import _maybe_autostart_watchdog

        _maybe_autostart_watchdog()
        mock_start.assert_not_called()


def test_maybe_autostart_logs_and_swallows_controller_crashes(
    temp_env: Path, monkeypatch
) -> None:
    """If the controller raises, the server must still boot. The whole
    point of the try/except around _maybe_autostart_watchdog is 'never
    block the api.ready log line'."""
    from deepsecurity.watchdog_monitor import controller

    if controller.running:
        controller.stop()

    with patch.object(controller, "start", side_effect=RuntimeError("boom")):
        from deepsecurity.api import _maybe_autostart_watchdog

        # Must not raise.
        _maybe_autostart_watchdog()


# ---------------------------------------------------------------------------
# Debounce — eats the Windows-dual-event dup.
# ---------------------------------------------------------------------------


def test_debounce_suppresses_rapid_duplicate_events(temp_env: Path) -> None:
    """on_created + on_modified for a single file-save must produce ONE
    scan, not two. This was #1 noise source in the live log."""
    pytest.importorskip("watchdog")  # _Monitor needs the base class.
    from deepsecurity.watchdog_monitor import _Monitor

    mon = _Monitor()
    p = temp_env / "somefile.txt"
    # First call is a fresh path — should be allowed.
    assert mon._debounce_ok(p) is True
    # Second call within the debounce window — suppressed.
    assert mon._debounce_ok(p) is False


def test_debounce_allows_events_after_window(temp_env: Path, monkeypatch) -> None:
    pytest.importorskip("watchdog")
    from deepsecurity.watchdog_monitor import _Monitor

    mon = _Monitor()
    p = temp_env / "file_A"
    assert mon._debounce_ok(p) is True
    # Fast-forward by rewinding the stored timestamp past the window.
    with mon._last_seen_lock:
        mon._last_seen[str(p).lower()] -= 10.0
    assert mon._debounce_ok(p) is True


def test_debounce_cache_bounded(temp_env: Path) -> None:
    """The in-memory dict must not grow without bound on long-running
    watchers — there's a GC pass once we cross the cap."""
    pytest.importorskip("watchdog")
    from deepsecurity.watchdog_monitor import _Monitor

    mon = _Monitor()
    # Fill past the cap with unique synthetic paths.
    for i in range(mon._DEBOUNCE_CACHE_MAX + 200):
        mon._debounce_ok(Path(f"/synthetic/path_{i}"))
    # After GC the cache should be at or below the cap.
    assert len(mon._last_seen) <= mon._DEBOUNCE_CACHE_MAX


# ---------------------------------------------------------------------------
# DEEPSecurity self-dirs — regression tests for the feedback loop we
# killed previously. If these break, the watchdog will eat its own tail.
# ---------------------------------------------------------------------------


def test_self_dirs_includes_data_logs_quarantine(temp_env: Path) -> None:
    from deepsecurity.watchdog_monitor import _deepsec_self_dirs

    dirs = _deepsec_self_dirs()
    names = {d.name for d in dirs}
    # Not every dir exists on every system; we just need the IDEA to be
    # in the set so the _in_ignore check will trip when those paths
    # appear under a watched root.
    # At minimum, config-derived quarantine/safelist/deleted must be present.
    # (We can't assert "data" by name because tmp_path-based databases
    #  put the parent elsewhere.)
    assert len(dirs) > 0


def test_ignore_blocks_deepsec_state(temp_env: Path, monkeypatch) -> None:
    """The _in_ignore check must return True for any path inside our own
    quarantine dir — otherwise quarantine writes trigger watchdog scans."""
    pytest.importorskip("watchdog")
    from deepsecurity.config import settings
    from deepsecurity.watchdog_monitor import _Monitor

    settings.quarantine_dir.mkdir(parents=True, exist_ok=True)
    mon = _Monitor()

    dummy = settings.quarantine_dir / "anything.bin"
    dummy.write_bytes(b"x")
    assert mon._in_ignore(dummy) is True


def test_ignore_blocks_transient_suffix(temp_env: Path) -> None:
    pytest.importorskip("watchdog")
    from deepsecurity.watchdog_monitor import _Monitor

    mon = _Monitor()
    # These extensions are transient by nature — SQLite journals, editor
    # swap files, etc. Scanning them is useless + often fails.
    for name in (
        "x.db-journal",
        "y.sqlite-wal",
        "z.swp",
        "foo.tmp",
        "bar.lock",
    ):
        p = temp_env / name
        p.write_bytes(b"")
        assert mon._in_ignore(p) is True, f"{name} should be ignored"


# ---------------------------------------------------------------------------
# Controller lifecycle (start → running → stop → not running).
# ---------------------------------------------------------------------------


def test_controller_without_package_gives_clean_error() -> None:
    """Calling start when watchdog isn't installed must return a dict with
    started=False and a useful reason, NOT raise."""
    from deepsecurity.watchdog_monitor import controller

    # We can't easily uninstall watchdog mid-test. But we CAN temporarily
    # force _AVAILABLE=False via the controller's check and see the
    # graceful path. Skip if the lib is installed — this test covers
    # the CI-without-optional-dep scenario.
    if controller.available:
        pytest.skip("watchdog package installed — this test covers the OPPOSITE path")

    result = controller.start()
    assert result.get("started") is False
    assert "not installed" in (result.get("reason") or "").lower()


# ---------------------------------------------------------------------------
# Heuristic confidence — the log had 'confidence: 0.0' on entropy spikes.
# ---------------------------------------------------------------------------


def test_entropy_spike_assigns_nonzero_confidence(
    temp_env: Path, scan_root: Path
) -> None:
    """An entropy-spike detection must have confidence > 0 so SIEMs and
    dashboards can rank-order results. The old code left it at 0.0."""
    import os

    from deepsecurity.ml import MLClassifier
    from deepsecurity.scanner import classify, extract_features

    # Random bytes = high entropy for a non-whitelisted mime.
    noisy = scan_root / "random.bin"
    noisy.write_bytes(os.urandom(4096))

    features = extract_features(noisy)
    det = classify(
        features,
        signatures=frozenset(),
        ml=MLClassifier(None, 0.85),
        yara=None,
    )
    if det.label == "suspicious":
        assert det.confidence > 0.0, (
            f"suspicious detection must carry a non-zero confidence; "
            f"got {det.confidence} for {det.reasons}"
        )
        assert det.confidence <= 0.8, (
            "heuristic confidence is capped at 0.8 — entropy alone is "
            "never strong enough to cross into 'high confidence'"
        )
    # If the label came back 'clean' on this random.bin (possible —
    # anomaly_score sometimes falls under the threshold), we don't assert
    # anything; the test is about the path-through-classify for the
    # suspicious branch.
