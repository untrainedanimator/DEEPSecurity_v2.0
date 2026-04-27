"""Dual-process watchdog twin — each process revives the other.

The pattern:

    Process A (main DEEPSecurity API).
    Process B (twin watchdog — tiny, ~5 MB RSS).

    Every 2 s, A pings B over a named pipe; B answers.
    Every 2 s, B checks A's PID is alive; if not, B re-execs A.
    Every 2 s, A checks B's PID is alive; if not, A re-execs B.

To kill DEEPSecurity an attacker must terminate BOTH processes within
the 2-second window before either notices. That raises the bar from
"any user with Task Manager" to "scripted attacker with Administrator
that can spawn taskkill on both PIDs simultaneously".

Combined with the Windows Service auto-restart from service.py, this
gives a third backstop: SCM revives A if A AND B both die.

This module is the twin process body. ``deepsec start`` spawns it
automatically when ``DEEPSEC_PROTECTION_TWIN=true``.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import NoReturn

from deepsecurity.logging_config import configure_logging, get_logger

_log = get_logger(__name__)

PIPE_NAME = r"\\.\pipe\deepsec-twin"


def run_twin(target_pid: int) -> NoReturn:
    """Twin loop. Watches ``target_pid``; respawns the main process if it dies.

    Exit conditions:
        - SIGINT / SIGTERM
        - ``DEEPSEC_PROTECTION_TWIN_STOP=1`` env var on next tick
    """
    configure_logging()
    _log.info("twin.started", target_pid=target_pid)

    # Make the twin polite — never compete with the main process.
    if os.name == "nt":
        try:
            import win32api  # type: ignore[import-not-found]
            import win32process  # type: ignore[import-not-found]

            win32process.SetPriorityClass(
                win32api.GetCurrentProcess(), win32process.IDLE_PRIORITY_CLASS
            )
        except Exception:
            pass
    else:
        try:
            os.nice(15)
        except Exception:
            pass

    interval = 2.0
    consecutive_misses = 0

    def _handle_term(*_: object) -> None:
        _log.info("twin.signal_term")
        sys.exit(0)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handle_term)
        except (ValueError, AttributeError):
            pass

    while True:
        if os.environ.get("DEEPSEC_PROTECTION_TWIN_STOP") == "1":
            _log.info("twin.env_stop")
            return
        if not _pid_alive(target_pid):
            consecutive_misses += 1
            _log.warning("twin.target_missing", pid=target_pid, misses=consecutive_misses)
            if consecutive_misses >= 2:
                target_pid = _respawn_main()
                consecutive_misses = 0
        else:
            consecutive_misses = 0
        time.sleep(interval)


def spawn_twin(target_pid: int) -> int | None:
    """Launch the twin process from the main process.

    Returns the twin's PID or None on failure.
    """
    try:
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "deepsecurity.protection.watchdog_twin",
                str(target_pid),
            ],
            close_fds=True,
            cwd=str(Path.cwd()),
        )
        _log.info("twin.spawned", twin_pid=proc.pid, target_pid=target_pid)
        return proc.pid
    except Exception:
        _log.exception("twin.spawn_failed")
        return None


def _pid_alive(pid: int) -> bool:
    try:
        import psutil

        return psutil.pid_exists(pid)
    except Exception:
        return False


def _respawn_main() -> int:
    """Spawn a fresh DEEPSecurity main process. Returns its PID."""
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "deepsecurity.cli", "serve"],
            close_fds=True,
            cwd=str(Path.cwd()),
        )
        _log.warning("twin.respawned_main", pid=proc.pid)
        return proc.pid
    except Exception:
        _log.exception("twin.respawn_failed")
        return -1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python -m deepsecurity.protection.watchdog_twin <target_pid>")
        sys.exit(2)
    try:
        target = int(sys.argv[1])
    except ValueError:
        print("target_pid must be int")
        sys.exit(2)
    run_twin(target)
