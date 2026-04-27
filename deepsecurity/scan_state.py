"""Scan state — backend-pluggable since v2.5.

The public surface (``state.start(...)``, ``state.snapshot()``, etc.) is
preserved for backwards compatibility, but the storage is delegated to
``deepsecurity.state_backend.get_backend()``. That makes the module
distributed-safe when ``DEEPSEC_STATE_BACKEND=redis`` and identical to
v2.4 in default ``memory`` mode.

Concurrency contract (unchanged from v2.4):
    - Only one scan runs at a time across the whole deployment. Calling
      ``state.start(session_id)`` while another scan owns the lease
      raises RuntimeError; the API layer translates that to a 409.
    - ``state.snapshot()`` is a read-only view, safe to call from any
      thread or process.
"""

from __future__ import annotations

import time
from typing import TypedDict

from deepsecurity.state_backend import ScanSnapshotData, get_backend


class ScanSnapshot(TypedDict):
    running: bool
    session_id: int | None
    scanned_count: int
    total_files: int
    total_detections: int
    current_file: str
    start_time: float | None
    elapsed_seconds: int
    output_tail: list[str]
    cancelled: bool


class ScanLeaseError(RuntimeError):
    """Raised when ``state.start()`` is called while another scan owns the lease."""


class ScanState:
    """Thin wrapper around ``state_backend`` so existing call-sites keep working."""

    def __init__(self, *, lease_ttl_seconds: int = 7200) -> None:
        self._lease_ttl = lease_ttl_seconds

    # --- lease ----------------------------------------------------------
    def start(self, session_id: int, total_files: int = 0) -> None:
        """Acquire the global scan lease and reset the snapshot.

        Raises:
            ScanLeaseError if another scan currently holds the lease.
        """
        backend = get_backend()
        if not backend.scan_acquire(session_id, ttl_seconds=self._lease_ttl):
            raise ScanLeaseError(
                f"another scan is already running (cannot start session {session_id})"
            )
        # Replace the snapshot wholesale — scan_acquire seeded a fresh one,
        # but we want total_files = caller's argument.
        snap = ScanSnapshotData(
            running=True,
            cancelled=False,
            session_id=session_id,
            scanned_count=0,
            total_files=total_files,
            total_detections=0,
            current_file="--",
            start_time=time.monotonic(),
            output=[],
        )
        backend.scan_state_set(snap, ttl_seconds=self._lease_ttl)

    def mark_file(self, path: str, detected: bool = False) -> None:
        def _mut(s: ScanSnapshotData) -> None:
            s.scanned_count += 1
            s.current_file = path
            if detected:
                s.total_detections += 1

        get_backend().scan_state_mutate(_mut, ttl_seconds=self._lease_ttl)

    def append_output(self, line: str) -> None:
        def _mut(s: ScanSnapshotData) -> None:
            s.output.append(line)
            if len(s.output) > 500:
                s.output = s.output[-500:]

        get_backend().scan_state_mutate(_mut, ttl_seconds=self._lease_ttl)

    def cancel(self) -> None:
        def _mut(s: ScanSnapshotData) -> None:
            s.cancelled = True

        get_backend().scan_state_mutate(_mut, ttl_seconds=self._lease_ttl)

    def finish(self) -> None:
        backend = get_backend()

        def _mut(s: ScanSnapshotData) -> None:
            s.running = False

        backend.scan_state_mutate(_mut, ttl_seconds=self._lease_ttl)
        backend.scan_release()

    # --- read -----------------------------------------------------------
    def snapshot(self) -> ScanSnapshot:
        s = get_backend().scan_state_get()
        elapsed = int(time.monotonic() - s.start_time) if s.start_time else 0
        return ScanSnapshot(
            running=s.running,
            session_id=s.session_id,
            scanned_count=s.scanned_count,
            total_files=s.total_files,
            total_detections=s.total_detections,
            current_file=s.current_file,
            start_time=s.start_time,
            elapsed_seconds=elapsed,
            output_tail=list(s.output[-10:]),
            cancelled=s.cancelled,
        )


# Process-level singleton — same name as in v2.4 so existing imports work.
state = ScanState()
