"""ETW provider subscription — real-time process / image / network events.

Why ETW:
    Polling psutil every N seconds (the v2.4 / v2.5 behaviour) misses
    short-lived processes and adds latency that defeats the point of
    "real-time". Event Tracing for Windows is the OS's own kernel-level
    event stream and is exposed to user-space without a driver. We
    subscribe to the providers we care about and react in milliseconds.

Providers consumed:
    - Microsoft-Windows-Kernel-Process     (process_create / process_term /
                                            image_load / thread_start)
    - Microsoft-Windows-Kernel-File         (file create / write)
    - Microsoft-Windows-Kernel-Network      (TCP/UDP connect)

Optional dep:
    pip install "deepsecurity[windows-edr]"  # pulls pywintrace (FireEye, MIT).
    The PyPI package is ``pywintrace``; its import module is just ``etw``.

Consumer pattern:

    from deepsecurity.realtime.etw import EtwListener
    listener = EtwListener(on_event=handle)
    listener.start()      # spawns a daemon thread
    # ... runtime ...
    listener.stop()

The on_event callback receives a typed ``EtwEvent`` dataclass and is
invoked from the listener thread. Keep it fast — defer heavy work to a
queue.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)


@dataclass
class EtwEvent:
    """One typed ETW event. Fields are best-effort — providers vary."""

    kind: str  # "process_create" | "process_term" | "image_load" | "net_connect" | "file_create"
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    pid: int | None = None
    parent_pid: int | None = None
    image: str | None = None
    cmdline: str | None = None
    user: str | None = None
    remote_ip: str | None = None
    remote_port: int | None = None
    file_path: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


# Type alias for the user callback.
OnEvent = Callable[[EtwEvent], None]


class EtwListener:
    """Subscribe to the configured ETW providers and dispatch typed events.

    The listener spawns a single daemon thread per provider. ``on_event``
    is called from inside that thread, so the callback MUST be quick
    (push to a queue and let a worker drain it).

    On platforms that aren't Windows, or when the optional ETW deps
    aren't installed, ``start()`` no-ops with a logged warning. That
    keeps DEEPSecurity bootable on Linux for tests.
    """

    PROVIDERS = (
        "Microsoft-Windows-Kernel-Process",
        "Microsoft-Windows-Kernel-File",
        "Microsoft-Windows-Kernel-Network",
    )

    def __init__(self, on_event: OnEvent) -> None:
        self._on_event = on_event
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []
        self._running = False

    # ------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._running

    # ------------------------------------------------------------------
    def start(self) -> bool:
        """Begin streaming. Returns True iff at least one provider attached."""
        if self._running:
            return True

        try:
            import etw  # type: ignore[import-not-found]  # from pywintrace
        except ImportError:
            _log.warning(
                "etw.unavailable",
                hint='pip install "deepsecurity[windows-edr]" '
                "(pywintrace — needs Windows + pywin32)",
            )
            return False

        self._stop_event.clear()
        attached = 0
        for provider in self.PROVIDERS:
            t = threading.Thread(
                target=self._consume,
                name=f"etw-{provider.split('-')[-1]}",
                args=(etw, provider),
                daemon=True,
            )
            t.start()
            self._threads.append(t)
            attached += 1

        self._running = attached > 0
        _log.info("etw.started", providers=attached)
        return self._running

    # ------------------------------------------------------------------
    def stop(self, timeout: float = 5.0) -> None:
        if not self._running:
            return
        self._stop_event.set()
        for t in self._threads:
            t.join(timeout=timeout)
        self._threads.clear()
        self._running = False
        _log.info("etw.stopped")

    # ------------------------------------------------------------------
    def _consume(self, etw_mod: Any, provider: str) -> None:
        """Provider consumption loop. Runs in a daemon thread."""
        try:
            session = etw_mod.ETW(
                providers=[etw_mod.ProviderInfo(provider, etw_mod.GUID(provider))],
                event_callback=lambda raw: self._dispatch(provider, raw),
            )
            session.start()
            while not self._stop_event.is_set():
                self._stop_event.wait(timeout=0.5)
            session.stop()
        except Exception:
            _log.exception("etw.consumer_failed", provider=provider)

    # ------------------------------------------------------------------
    def _dispatch(self, provider: str, raw: dict[str, Any]) -> None:
        """Translate a raw ETW event into a typed EtwEvent and forward."""
        kind = self._classify(provider, raw)
        if kind is None:
            return
        event = EtwEvent(
            kind=kind,
            pid=_int_or_none(raw.get("ProcessId") or raw.get("PID")),
            parent_pid=_int_or_none(raw.get("ParentProcessId")),
            image=raw.get("ImageFileName") or raw.get("Image"),
            cmdline=raw.get("CommandLine"),
            user=raw.get("UserSid") or raw.get("UserName"),
            remote_ip=raw.get("daddr") or raw.get("DestinationIp"),
            remote_port=_int_or_none(raw.get("dport") or raw.get("DestinationPort")),
            file_path=raw.get("FileName") or raw.get("FilePath"),
            raw=raw,
        )
        try:
            self._on_event(event)
        except Exception:
            _log.exception("etw.callback_failed", kind=kind)

    @staticmethod
    def _classify(provider: str, raw: dict[str, Any]) -> str | None:
        """Map (provider, raw event ID) → our event kind, or None to skip."""
        opcode = raw.get("Opcode") or raw.get("EventName") or ""
        opcode = str(opcode).lower()
        if "process" in provider.lower():
            if "start" in opcode or "create" in opcode:
                return "process_create"
            if "end" in opcode or "stop" in opcode or "term" in opcode:
                return "process_term"
            if "image" in opcode or "load" in opcode:
                return "image_load"
        if "file" in provider.lower() and ("create" in opcode or "write" in opcode):
            return "file_create"
        if "network" in provider.lower() and ("connect" in opcode or "send" in opcode):
            return "net_connect"
        return None


def _int_or_none(v: Any) -> int | None:
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None
