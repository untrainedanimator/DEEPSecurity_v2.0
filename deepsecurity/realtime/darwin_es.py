"""macOS Endpoint Security listener — v3.0.0 stub, real in v3.1.

The Apple Endpoint Security framework requires a notarised helper
binary signed by an Apple Developer account, which we can't generate
in this repo. The full path is:

    1. Write a Swift-based helper that links against
       ``/System/Library/Frameworks/EndpointSecurity.framework``.
    2. Notarise it with ``xcrun notarytool submit`` against an Apple
       Developer Team ID.
    3. Ship the notarised binary as a wheel data file.
    4. The Python listener spawns it as a subprocess, reads JSON event
       lines from its stdout, translates to SysmonEvent / EtwEvent.

Until v3.1 ships, this stub is what we expose. Same shape as the Linux
stub: ``start()`` logs a warning and returns False. The correlator
continues to function with no events.

Subscribed events (v3.1 plan):

    ES_EVENT_TYPE_NOTIFY_EXEC          ↔ Sysmon EID 1 / ETW process_create
    ES_EVENT_TYPE_NOTIFY_EXIT          ↔ Sysmon EID 5
    ES_EVENT_TYPE_NOTIFY_OPEN          ↔ Sysmon EID 11 (filtered)
    ES_EVENT_TYPE_NOTIFY_KEXTLOAD      ↔ Sysmon EID 6
    ES_EVENT_TYPE_NOTIFY_MMAP          ↔ Sysmon EID 7 (image load)
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)


class DarwinEndpointSecurityListener:
    """v3.0.0 stub for the macOS Endpoint Security realtime listener."""

    def __init__(self, on_event: Callable[[Any], None]) -> None:
        self._on_event = on_event
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> bool:
        _log.warning(
            "darwin_es.unimplemented",
            hint=(
                "macOS realtime ships in v3.1 alongside a notarised helper "
                "binary; use the scanner CLI for now"
            ),
        )
        return False

    def stop(self, timeout: float = 5.0) -> None:
        del timeout  # interface compat — stub has nothing to wait on
        self._stop.set()
