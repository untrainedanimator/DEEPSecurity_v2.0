"""Real-time file-system monitor.

Wraps `watchdog` (optional dep). On a create-or-modify event inside
any watched path, dispatch a single-file scan.

Honest scope disclaimer: this is a user-space file-event watcher. It
can see every file create/modify under folders the running user can
read. It does NOT see:
  - system-protected paths without admin/root
  - in-memory malware (no file write)
  - files opened by other users' processes

Kernel-level visibility is what EDR products (CrowdStrike / SentinelOne /
MS Defender / etc.) ship. We stay in user-space on purpose: no signed
driver, no elevated install, no kernel complexity.
"""
from __future__ import annotations

import os
import string
import sys
import threading
from pathlib import Path
from typing import Any

from deepsecurity.audit import audit_log
from deepsecurity.config import settings
from deepsecurity.logging_config import get_logger
from deepsecurity.ml import MLClassifier
from deepsecurity.scanner import load_signatures, scan_file

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Scope resolution — "system" expands to sensible per-OS roots.
# ---------------------------------------------------------------------------


def _windows_drive_roots() -> list[Path]:
    """Every currently attached drive letter, existing and accessible."""
    roots: list[Path] = []
    for letter in string.ascii_uppercase:
        p = Path(f"{letter}:\\")
        try:
            if p.exists() and p.is_dir():
                roots.append(p)
        except OSError:
            continue
    return roots


def _unix_user_roots() -> list[Path]:
    """Common user-writable paths on Linux/macOS."""
    candidates = [Path("/home"), Path("/Users"), Path("/tmp"), Path("/var/tmp"),
                  Path(os.path.expanduser("~"))]
    return [p for p in candidates if p.exists() and p.is_dir()]


def default_system_roots() -> list[Path]:
    """Every path worth watching for 'system-wide' coverage, de-duplicated.

    Returns resolved absolute paths. Excludes DEEPSecurity's own
    quarantine / safelist / deleted dirs so we don't self-recurse.
    """
    if sys.platform == "win32":
        roots = _windows_drive_roots()
    else:
        roots = _unix_user_roots()

    excluded = {
        p.resolve()
        for p in (settings.quarantine_dir, settings.safelist_dir, settings.deleted_dir)
        if p.exists()
    }
    seen: set[Path] = set()
    out: list[Path] = []
    for r in roots:
        rr = r.resolve()
        if rr in excluded:
            continue
        if rr in seen:
            continue
        seen.add(rr)
        out.append(rr)
    return out


def _parse_path_list(raw: str) -> list[Path]:
    """Parse a semicolon- or comma-separated path list from config."""
    if not raw:
        return []
    for sep in (";", ","):
        if sep in raw:
            parts = raw.split(sep)
            break
    else:
        parts = [raw]
    return [Path(p.strip()).expanduser() for p in parts if p.strip()]


def default_user_risk_roots() -> list[Path]:
    """The 'user_risk' scope — the five or six folders where malicious or
    policy-violating files actually land on a typical workstation.

    This is what we recommend in docs/WEDGE.md as the default for realtime
    monitoring. Covers 90% of realistic attack surface (browser downloads,
    user-staged files, Office attachments, temp drops) without the CPU and
    event-volume cost of watching every drive.

    Operators can override the built-in list by setting
    DEEPSEC_USER_RISK_PATHS to a semicolon- or comma-separated list of
    paths — the default is just an opinion, not a hardcode.
    """
    # Config override wins over the built-in preset.
    override = _parse_path_list(settings.user_risk_paths)
    if override:
        out: list[Path] = []
        seen: set[Path] = set()
        for c in override:
            try:
                if not c.exists() or not c.is_dir():
                    continue
                rc = c.resolve()
            except OSError:
                continue
            if rc in seen:
                continue
            seen.add(rc)
            out.append(rc)
        return out

    home = Path(os.path.expanduser("~"))
    candidates: list[Path] = []

    if sys.platform == "win32":
        candidates += [
            home / "Downloads",
            home / "Desktop",
            home / "Documents",
            # Outlook attachment cache (exact path depends on the Outlook version).
            home / "AppData" / "Local" / "Microsoft" / "Windows" / "INetCache" / "Content.Outlook",
            home / "AppData" / "Local" / "Temp",
            Path(os.environ.get("TEMP", str(home / "AppData" / "Local" / "Temp"))),
            # Public Downloads/Desktop (shared workstation edge case).
            Path("C:/Users/Public/Downloads"),
        ]
    elif sys.platform == "darwin":
        candidates += [
            home / "Downloads",
            home / "Desktop",
            home / "Documents",
            home / "Library" / "Mail Downloads",
            Path("/tmp"),
            Path("/var/folders"),  # macOS per-user temp
        ]
    else:  # Linux / BSD
        candidates += [
            home / "Downloads",
            home / "Desktop",
            home / "Documents",
            Path("/tmp"),
            Path("/var/tmp"),
        ]

    excluded = {
        p.resolve()
        for p in (settings.quarantine_dir, settings.safelist_dir, settings.deleted_dir)
        if p.exists()
    }
    seen: set[Path] = set()
    out: list[Path] = []
    for c in candidates:
        try:
            if not c.exists() or not c.is_dir():
                continue
            rc = c.resolve()
        except OSError:
            continue
        if rc in excluded or rc in seen:
            continue
        seen.add(rc)
        out.append(rc)
    return out


_SCOPE_PRESETS = {
    "system": default_system_roots,
    "user_risk": default_user_risk_roots,
}


def resolve_scope(scope: str | None) -> list[Path] | None:
    """Return the paths for a named scope, or None for an unknown scope."""
    fn = _SCOPE_PRESETS.get(scope) if scope else None
    return fn() if fn else None

try:  # pragma: no cover — optional dep
    from watchdog.events import FileSystemEventHandler  # type: ignore[import-not-found]
    from watchdog.observers import Observer  # type: ignore[import-not-found]

    _AVAILABLE = True
except ImportError:
    FileSystemEventHandler = object  # type: ignore[misc,assignment]
    Observer = None  # type: ignore[assignment]
    _AVAILABLE = False


# Suffixes of transient files that shouldn't trigger a scan. These come
# from SQLite's rollback/write-ahead journaling, editor swap files, and the
# like — scanning them is useless, they often disappear before stat()
# returns, and on Windows they can be open-locked.
_IGNORE_SUFFIXES: frozenset[str] = frozenset(
    {
        ".db-journal",
        ".sqlite-journal",
        ".db-wal",
        ".db-shm",
        ".sqlite-wal",
        ".sqlite-shm",
        ".swp",
        ".swx",
        ".tmp",
        ".lock",
        "~",
    }
)

# Any filename containing one of these markers is treated as transient.
_IGNORE_NAME_MARKERS: tuple[str, ...] = (".~lock.",)  # LibreOffice


def _parse_glob_list(raw: str) -> list[str]:
    """Split a ``;`` or ``,``-separated glob list from config."""
    if not raw:
        return []
    for sep in (";", ","):
        if sep in raw:
            parts = raw.split(sep)
            break
    else:
        parts = [raw]
    return [p.strip() for p in parts if p.strip()]


def _matches_any_glob(path: Path, globs: list[str]) -> bool:
    """True if ``path`` (or any of its parents as a string) matches any
    glob. We match both the full path and the stem so patterns like
    ``**/node_modules/**`` and ``*.pyc`` both work.
    """
    if not globs:
        return False
    s = str(path).replace("\\", "/")
    for g in globs:
        # pathlib.PurePath.match is glob-y but anchors weirdly; fnmatch
        # plus our own prefix normalisation is more predictable.
        from fnmatch import fnmatch

        if fnmatch(s, g) or fnmatch(s.lower(), g.lower()):
            return True
        # Also try just the basename for ``*.pyc``-style patterns.
        if fnmatch(path.name, g):
            return True
    return False


def _deepsec_self_dirs() -> set[Path]:
    """DEEPSecurity's own state directories — never scan these or we
    feedback-loop ourselves into a meltdown."""
    repo_root = Path(__file__).resolve().parent.parent
    dirs: set[Path] = {
        # Repo-relative
        repo_root / "data",
        repo_root / "logs",
        repo_root / "quarantine",
        repo_root / "deleted",
        repo_root / "safelist",
        repo_root / ".venv",
        repo_root / "__pycache__",
        repo_root / ".pytest_cache",
        repo_root / ".mypy_cache",
        repo_root / ".ruff_cache",
        repo_root / "htmlcov",
        repo_root / "frontend" / "node_modules",
        repo_root / "frontend" / "dist",
    }
    # Config-derived
    try:
        dirs.update(
            {
                settings.quarantine_dir,
                settings.safelist_dir,
                settings.deleted_dir,
            }
        )
        # DB parent, if file-based SQLite
        url = settings.database_url or ""
        if url.startswith("sqlite:") and ":memory:" not in url:
            _, _, tail = url.partition(":///")
            if tail:
                dirs.add(Path(tail).expanduser().parent.resolve())
    except Exception:
        pass
    return {d.resolve() for d in dirs if str(d)}


class _Monitor(FileSystemEventHandler):  # type: ignore[misc]
    # Debounce window: if we already scanned a path in this many seconds,
    # suppress the duplicate event. On Windows a single atomic file-save
    # fires on_created AND on_modified back-to-back (and editors often
    # write-then-rename-then-modify), so the raw event stream is 2-5×
    # redundant. 0.75s eats the dupes without hiding genuine resaves.
    _DEBOUNCE_SECONDS = 0.75
    # Cap the debounce-cache size so long-running watchers don't leak.
    _DEBOUNCE_CACHE_MAX = 8192

    def __init__(self) -> None:
        super().__init__()
        self._ml = MLClassifier(settings.ml_model_path, settings.ml_confidence_threshold)
        self._sigs = load_signatures(settings.signature_path)
        self._ignore = _deepsec_self_dirs()
        self._exclude_globs = _parse_glob_list(settings.watch_exclude_globs)
        # path (normalised) → monotonic timestamp of last scan dispatch.
        self._last_seen: dict[str, float] = {}
        self._last_seen_lock = threading.Lock()

    def _debounce_ok(self, path: Path) -> bool:
        """Return True if we should scan this path, False if it's a dup.

        Uses monotonic time + an in-memory dict. Thread-safe. Caps the
        cache at ``_DEBOUNCE_CACHE_MAX`` entries; a time-window GC
        doesn't cut it when a burst of unique paths arrives inside the
        window (seen in testing, and plausible on a big tarball extract).
        We keep the most-recently-seen half when we overflow.
        """
        import time as _time

        now = _time.monotonic()
        key = str(path).lower()  # Windows is case-insensitive; normalise.
        with self._last_seen_lock:
            last = self._last_seen.get(key, 0.0)
            if now - last < self._DEBOUNCE_SECONDS:
                return False
            self._last_seen[key] = now
            # Size-based GC: when we exceed the cap, keep only the
            # newest CACHE_MAX/2 entries. Sort by timestamp descending
            # then dict-slice. Amortised O(N log N) per cap-cross,
            # which is fine because a cap-cross is rare.
            if len(self._last_seen) > self._DEBOUNCE_CACHE_MAX:
                keep = self._DEBOUNCE_CACHE_MAX // 2
                items_sorted = sorted(
                    self._last_seen.items(),
                    key=lambda kv: kv[1],
                    reverse=True,
                )
                self._last_seen = dict(items_sorted[:keep])
        return True

    def _in_ignore(self, path: Path) -> bool:
        try:
            rp = path.resolve()
        except OSError:
            return False
        name = rp.name.lower()
        # Fast-path the transient-filename rules first — no IO needed.
        for suffix in _IGNORE_SUFFIXES:
            if name.endswith(suffix):
                return True
        for marker in _IGNORE_NAME_MARKERS:
            if marker in name:
                return True
        # Then the dir-prefix check (DEEPSecurity's own state).
        for d in self._ignore:
            try:
                if rp.is_relative_to(d):
                    return True
            except (ValueError, OSError):
                continue
        # Finally the operator-configured / default exclusion globs —
        # node_modules, .venv, browser caches, etc. This is what lets a
        # realtime watch on ``C:\Users\me`` not melt your CPU while Vite
        # rebuilds node_modules for the thousandth time.
        if _matches_any_glob(rp, self._exclude_globs):
            return True
        return False

    def on_created(self, event: Any) -> None:
        self._handle(event)

    def on_modified(self, event: Any) -> None:
        self._handle(event)

    def _handle(self, event: Any) -> None:
        if event.is_directory:
            return
        path = Path(event.src_path)
        if self._in_ignore(path):
            return
        if not self._debounce_ok(path):
            # Same file scanned very recently — Windows fires on_created
            # and on_modified for a single atomic save, so we'd double
            # everything without this check.
            return
        # Rate monitor first — even if the scan fails, we still counted the event.
        try:
            from deepsecurity.ransomware_guard import guard

            guard.record_write(str(path))
        except Exception:
            _log.exception("ransomware.guard_failed", path=str(path))

        try:
            det = scan_file(
                path,
                signatures=self._sigs,
                ml=self._ml,
                quarantine_enabled=True,
            )
            audit_log(
                actor="watchdog",
                action="watchdog.file_event",
                status=det.label,
                file_path=path,
                details={
                    "reasons": list(det.reasons),
                    "mitre_tags": list(det.mitre_tags),
                    "confidence": det.confidence,
                },
            )
        except FileNotFoundError:
            # Transient file — disappeared between the event firing and our
            # stat. Nothing to do. Don't audit-log it either: if we did,
            # that log write could itself trip a watchdog event and we'd be
            # back in feedback-loop territory.
            return
        except OSError as exc:
            # Permission denied, locked by another process, etc. Record it
            # quietly at debug level — spamming errors for every locked
            # Chrome sqlite file would bury the real signal.
            _log.debug("watchdog.scan_skipped", path=str(path), error=str(exc))
        except Exception:
            _log.exception("watchdog.scan_failed", path=str(path))


class WatchdogController:
    def __init__(self) -> None:
        self._observer: Any = None
        self._paths: list[str] = []
        self._lock = threading.Lock()

    @property
    def available(self) -> bool:
        return _AVAILABLE

    @property
    def running(self) -> bool:
        with self._lock:
            return self._observer is not None and self._observer.is_alive()

    @property
    def watching(self) -> list[str]:
        with self._lock:
            return list(self._paths)

    def start(
        self,
        paths: list[str | Path] | None = None,
        *,
        scope: str | None = None,
    ) -> dict[str, Any]:
        """Start watching.

        scope values:
            "system"     — every drive (Windows) / every common user-writable
                           path (Unix). Broad coverage, high event volume.
            "user_risk"  — just the folders where malware and policy
                           violations actually land (Downloads, Desktop,
                           Documents, Outlook cache, %TEMP%). The
                           recommended default for realtime on a laptop.

        paths  = explicit list. Used as-is after validation.

        If neither is supplied, fall back to settings.scan_roots (the
        configured allow-list, if any). If that's also empty, refuse.
        """
        if not _AVAILABLE:
            return {
                "started": False,
                "reason": "watchdog package not installed. "
                          "pip install \"deepsecurity[watchdog]\"",
            }

        # Resolve the target list.
        resolved: list[Path] = []
        if scope in _SCOPE_PRESETS:
            resolved = resolve_scope(scope) or []
            if not resolved:
                return {
                    "started": False,
                    "reason": f"scope={scope!r} resolved to zero paths on this host",
                }
        elif paths:
            for p in paths:
                rp = Path(p).expanduser().resolve(strict=False)
                if not rp.exists() or not rp.is_dir():
                    return {
                        "started": False,
                        "reason": f"path does not exist or is not a directory: {rp}",
                    }
                resolved.append(rp)
        else:
            resolved = [r for r in settings.scan_roots if r.exists() and r.is_dir()]

        if not resolved:
            return {
                "started": False,
                "reason": "no path/scope supplied and no DEEPSEC_SCAN_ROOT configured. "
                          "Pick a path, use scope=\"system\", or set DEEPSEC_SCAN_ROOT.",
            }

        with self._lock:
            if self._observer is not None and self._observer.is_alive():
                return {"started": False, "reason": "already running"}
            obs = Observer()
            monitor = _Monitor()
            for p in resolved:
                obs.schedule(monitor, str(p), recursive=True)
            obs.daemon = True
            obs.start()
            self._observer = obs
            self._paths = [str(p) for p in resolved]
            audit_log(
                actor="system",
                action="watchdog.started",
                details={"paths": self._paths},
            )
            _log.info("watchdog.started", paths=self._paths)
            return {"started": True, "paths": self._paths}

    def stop(self) -> dict[str, Any]:
        with self._lock:
            obs = self._observer
            if obs is None:
                return {"stopped": False, "reason": "not running"}
            obs.stop()
            obs.join(timeout=5.0)
            self._observer = None
            stopped_paths = list(self._paths)
            self._paths = []
            audit_log(
                actor="system", action="watchdog.stopped",
                details={"paths": stopped_paths},
            )
            _log.info("watchdog.stopped")
            return {"stopped": True, "paths": stopped_paths}


controller = WatchdogController()
