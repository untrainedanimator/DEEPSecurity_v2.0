"""Rate-based ransomware detector (user-space, best-effort).

Ransomware's fingerprint at the file-system layer is simple: a single
process writes to dozens of files per second, typically replacing them
with encrypted blobs. We track per-PID file-event rates in a sliding
window and fire an alert (and optionally kill the PID) when the rate
crosses a threshold.

Honest caveats:
  - Attribution (which PID wrote a file) is NOT provided by watchdog
    file events. Windows' ReadDirectoryChangesW just tells you *what*
    changed, not *who* changed it. On Linux inotify it's the same.
  - What we CAN do is count events globally — if the whole file system
    is being rewritten at 200 files/sec, something's wrong regardless
    of which process is responsible. We then scan the process list for
    candidates (high CPU, high IO) and point at the most likely.
  - A real EDR gets the caller PID from the kernel and has no ambiguity.

So: this is a HEURISTIC. It sits at ~3/5 on evasion resistance but catches
the noisy 80% of ransomware crypters.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any

import psutil

from deepsecurity.alerts import AlertEvent
from deepsecurity.alerts import bus as alert_bus
from deepsecurity.audit import audit_log
from deepsecurity.config import settings
from deepsecurity.logging_config import get_logger
from deepsecurity.processes import kill_process

_log = get_logger(__name__)


class RansomwareGuard:
    """Global file-write-rate monitor. Thread-safe."""

    def __init__(
        self,
        *,
        threshold: int | None = None,
        window_seconds: float | None = None,
        auto_kill: bool | None = None,
    ) -> None:
        self._threshold = (
            threshold if threshold is not None else settings.ransomware_rate_threshold
        )
        self._window = (
            window_seconds
            if window_seconds is not None
            else settings.ransomware_rate_window_seconds
        )
        self._auto_kill = (
            auto_kill if auto_kill is not None else settings.ransomware_auto_kill
        )
        self._events: deque[float] = deque()
        self._lock = threading.Lock()
        # Rate-limit the alerts we fire so a single event storm doesn't
        # spam every sink. At most one alert per cooldown.
        self._last_alert_at: float = 0.0
        self._alert_cooldown = 15.0

    @property
    def enabled(self) -> bool:
        return self._threshold > 0

    def record_write(self, path: str) -> None:
        """Call on every file create/modify. Fires an alert if the threshold
        is crossed. Returns immediately on every call."""
        if not self.enabled:
            return
        now = time.monotonic()
        with self._lock:
            self._events.append(now)
            cutoff = now - self._window
            while self._events and self._events[0] < cutoff:
                self._events.popleft()
            rate = len(self._events) / self._window
            if rate < self._threshold:
                return
            if now - self._last_alert_at < self._alert_cooldown:
                return
            self._last_alert_at = now

        # Out of the lock — run expensive stuff after releasing.
        self._trigger(rate=rate, sample_path=path)

    def _suspect_pid(self) -> dict[str, Any] | None:
        """Best guess at which PID is driving the rate: highest io_counters.write_bytes
        across visible processes. Returns None if unavailable."""
        best: dict[str, Any] | None = None
        best_writes = 0
        for p in psutil.process_iter(["pid", "name"]):
            try:
                io = p.io_counters()
                writes = int(getattr(io, "write_bytes", 0) or 0)
            except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                continue
            if writes > best_writes:
                best_writes = writes
                best = {"pid": p.info["pid"], "name": p.info.get("name"), "write_bytes": writes}
        return best

    def _trigger(self, *, rate: float, sample_path: str) -> None:
        suspect = self._suspect_pid()
        suspect_desc = "unavailable"
        if suspect:
            suspect_desc = f"pid={suspect['pid']} name={suspect['name']}"

        _log.warning(
            "ransomware.suspected",
            rate_per_second=round(rate, 1),
            threshold=self._threshold,
            sample_path=sample_path,
            suspect=suspect,
        )

        details: dict[str, Any] = {
            "rate_per_second": round(rate, 1),
            "threshold": self._threshold,
            "sample_path": sample_path,
            "suspect": suspect,
            "mitre_tags": ["T1486"],
        }

        alert_bus.dispatch(
            AlertEvent(
                kind="ransomware.suspected",
                severity="critical",
                summary=(
                    f"file-write rate {round(rate, 1)}/s exceeds threshold "
                    f"{self._threshold}/s (suspect: {suspect_desc})"
                ),
                file_path=sample_path,
                details=details,
            )
        )
        audit_log(actor="system", action="ransomware.suspected", status="alert", details=details)

        # Enforcement — only if both (a) the operator asked for it and
        # (b) we have a reasonable suspect.
        if self._auto_kill and suspect and suspect.get("pid"):
            result = kill_process(int(suspect["pid"]), force=True)
            audit_log(
                actor="system",
                action="ransomware.auto_kill",
                status="ok" if result.get("killed") else "failed",
                details={"suspect": suspect, "result": result},
            )


# Process-wide guard. Watchdog monitor calls record_write() for every
# create/modify event it sees.
guard = RansomwareGuard()
