"""Process-wide scan state, guarded by a lock.

This is intentionally narrow. The API layer reads a snapshot via `snapshot()`
rather than the dictionary directly, so the schema is fixed and typed.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import TypedDict


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


@dataclass
class ScanState:
    lock: threading.Lock = field(default_factory=threading.Lock)
    running: bool = False
    cancelled: bool = False
    session_id: int | None = None
    scanned_count: int = 0
    total_files: int = 0
    total_detections: int = 0
    current_file: str = "--"
    start_time: float | None = None
    output: list[str] = field(default_factory=list)
    _max_output_lines: int = 500

    def start(self, session_id: int, total_files: int = 0) -> None:
        with self.lock:
            self.running = True
            self.cancelled = False
            self.session_id = session_id
            self.scanned_count = 0
            self.total_files = total_files
            self.total_detections = 0
            self.current_file = "--"
            self.start_time = time.monotonic()
            self.output = []

    def mark_file(self, path: str, detected: bool = False) -> None:
        with self.lock:
            self.scanned_count += 1
            self.current_file = path
            if detected:
                self.total_detections += 1

    def append_output(self, line: str) -> None:
        with self.lock:
            self.output.append(line)
            if len(self.output) > self._max_output_lines:
                self.output = self.output[-self._max_output_lines :]

    def cancel(self) -> None:
        with self.lock:
            self.cancelled = True

    def finish(self) -> None:
        with self.lock:
            self.running = False

    def snapshot(self) -> ScanSnapshot:
        with self.lock:
            elapsed = int(time.monotonic() - self.start_time) if self.start_time else 0
            return ScanSnapshot(
                running=self.running,
                session_id=self.session_id,
                scanned_count=self.scanned_count,
                total_files=self.total_files,
                total_detections=self.total_detections,
                current_file=self.current_file,
                start_time=self.start_time,
                elapsed_seconds=elapsed,
                output_tail=list(self.output[-10:]),
                cancelled=self.cancelled,
            )


# Process singleton. Tests reset via state.__init__() or a fixture.
state = ScanState()
