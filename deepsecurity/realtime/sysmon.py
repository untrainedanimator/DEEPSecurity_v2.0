"""Sysmon Event Log consumer — Microsoft's signed kernel-level sensor.

Sysmon (Sysinternals) is a free, Microsoft-signed Windows driver that
emits rich behavioural telemetry to the Windows Event Log under
``Microsoft-Windows-Sysmon/Operational``. It's the de-facto open-source
EDR sensor — used by every Windows-defender SOC pipeline and almost
every commercial EDR-on-top product.

DEEPSecurity v3.0 doesn't ship its own kernel driver (we'd need WHQL
signing + months of hardening). Instead we **delegate the kernel
slice to Sysmon** and consume its events as our EDR feed. Sysmon is
the sensor; DEEPSecurity is the policy / correlation / response /
audit layer.

Event IDs we care about (default Sysmon config covers all of these):
    1   Process Create
    3   Network Connection
    5   Process Terminate
    7   Image Loaded
    8   CreateRemoteThread
    10  ProcessAccess
    11  FileCreate
    12  RegistryEvent (CreateKey/DeleteKey)
    13  RegistryEvent (SetValue)
    17  Pipe Created
    18  Pipe Connected
    22  DnsQuery
    25  ProcessTampering

We poll the Event Log via ``win32evtlog`` from a daemon thread; new
events are dispatched to the operator callback within ~100 ms of write.

Usage:

    from deepsecurity.realtime.sysmon import SysmonConsumer
    c = SysmonConsumer(on_event=handle)
    c.start()  # daemon thread
    ...
    c.stop()

If Sysmon isn't installed, ``start()`` returns False with a logged hint.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)

CHANNEL = "Microsoft-Windows-Sysmon/Operational"


@dataclass
class SysmonEvent:
    event_id: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    pid: int | None = None
    parent_pid: int | None = None
    image: str | None = None
    parent_image: str | None = None
    cmdline: str | None = None
    user: str | None = None
    rule_name: str | None = None  # the rule that fired in Sysmon's config
    raw: dict[str, Any] = field(default_factory=dict)


OnSysmon = Callable[[SysmonEvent], None]


# Map of common Sysmon event-data keys we surface as typed fields.
_FIELD_ALIASES = {
    "ProcessId": "pid",
    "ParentProcessId": "parent_pid",
    "Image": "image",
    "ParentImage": "parent_image",
    "CommandLine": "cmdline",
    "User": "user",
    "RuleName": "rule_name",
}


class SysmonConsumer:
    """Stream new Sysmon events as they appear in the Windows Event Log."""

    def __init__(self, on_event: OnSysmon, poll_interval_s: float = 0.25) -> None:
        self._on_event = on_event
        self._poll = poll_interval_s
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_record_id = 0

    # ------------------------------------------------------------------
    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------
    def start(self) -> bool:
        """Begin streaming. Returns False if Sysmon is not installed."""
        try:
            import win32evtlog  # type: ignore[import-not-found]  # pywin32
        except ImportError:
            _log.warning(
                "sysmon.unavailable",
                hint='pip install "deepsecurity[windows-edr]" (needs pywin32)',
            )
            return False

        if not _channel_exists(win32evtlog, CHANNEL):
            _log.warning(
                "sysmon.not_installed",
                hint=f"channel {CHANNEL} missing — install Sysmon with a config "
                "(see deploy/sysmon-config.xml)",
            )
            return False

        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="sysmon-consumer", daemon=True)
        self._thread.start()
        _log.info("sysmon.started", channel=CHANNEL)
        return True

    # ------------------------------------------------------------------
    def stop(self, timeout: float = 5.0) -> None:
        if not self.running:
            return
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        _log.info("sysmon.stopped")

    # ------------------------------------------------------------------
    def _loop(self) -> None:
        import win32evtlog  # type: ignore[import-not-found]

        while not self._stop.is_set():
            try:
                self._drain(win32evtlog)
            except Exception:
                _log.exception("sysmon.drain_failed")
            self._stop.wait(timeout=self._poll)

    # ------------------------------------------------------------------
    def _drain(self, win32evtlog: Any) -> None:
        """Read every record newer than ``_last_record_id`` and dispatch."""
        query = f"*[System[EventRecordID > {self._last_record_id}]]"
        h = win32evtlog.EvtQuery(
            CHANNEL,
            win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection,
            query,
            None,
        )
        try:
            while True:
                events = win32evtlog.EvtNext(h, 64, 1000, 0)
                if not events:
                    break
                for ev in events:
                    # We don't render the human-friendly message — _parse_xml
                    # extracts everything we need from the raw event XML.
                    # ``EvtFormatMessage(EvtFormatMessageEvent)`` would fail
                    # on Sysmon events with Win32 error 15027 because the
                    # publisher's message resource isn't loaded into us.
                    record = self._parse_xml(win32evtlog, ev, "")
                    if record is None:
                        continue
                    if record.raw.get("_record_id"):
                        self._last_record_id = max(
                            self._last_record_id, int(record.raw["_record_id"])
                        )
                    try:
                        self._on_event(record)
                    except Exception:
                        _log.exception("sysmon.callback_failed", event_id=record.event_id)
        finally:
            try:
                win32evtlog.EvtClose(h)
            except Exception:
                pass

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_xml(win32evtlog: Any, evt_handle: Any, rendered_msg: str) -> SysmonEvent | None:
        """Render a single event handle to typed SysmonEvent."""
        try:
            xml = _evt_render_xml(win32evtlog, evt_handle)
        except Exception:
            return None

        # Best-effort XML parse — keeps us off lxml as a hard dep.
        from xml.etree import ElementTree as ET

        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return None

        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        sysid = root.findtext("e:System/e:EventID", default="0", namespaces=ns)
        rec_id = root.findtext("e:System/e:EventRecordID", default="0", namespaces=ns)

        data: dict[str, str] = {}
        for d in root.findall("e:EventData/e:Data", ns):
            name = d.attrib.get("Name", "")
            if name:
                data[name] = d.text or ""

        ev = SysmonEvent(
            event_id=int(sysid),
            raw={**data, "_record_id": rec_id, "_msg": rendered_msg or ""},
        )
        for k, attr in _FIELD_ALIASES.items():
            v = data.get(k)
            if v is None:
                continue
            if attr in {"pid", "parent_pid"}:
                try:
                    setattr(ev, attr, int(v))
                except ValueError:
                    pass
            else:
                setattr(ev, attr, v)
        return ev


def _evt_render_xml(win32evtlog: Any, evt_handle: Any) -> str:
    """Render an event handle as raw XML.

    Uses ``EvtRender`` (NOT ``EvtFormatMessage``) so we don't depend on
    the publisher's message resource being loaded into our process.
    For Sysmon events that resource is owned by Sysmon64.exe; calling
    ``EvtFormatMessage`` from a Python host fails with Win32 error 15027
    ('message resource is present but the message was not found in the
    message table'). ``EvtRender`` returns the system+EventData XML
    directly, which is all we need to populate ``SysmonEvent``.
    """
    render_xml = getattr(win32evtlog, "EvtRenderEventXml", 1)
    # pywin32 311 form: EvtRender(Context, Fragment, Flags).
    try:
        result = win32evtlog.EvtRender(None, evt_handle, render_xml)
    except TypeError:
        # Legacy form: EvtRender(Fragment, Flags).
        result = win32evtlog.EvtRender(evt_handle, render_xml)
    if isinstance(result, bytes):
        result = result.decode("utf-16-le", errors="replace").rstrip("\x00")
    return result


def _evt_format_message(win32evtlog: Any, evt_handle: Any, flags: int) -> str:
    """Render an event handle, tolerating pywin32 API changes.

    pywin32 311 signature is ``EvtFormatMessage(PublisherMetadata, Event, Flags)``
    — 3 positional args required. Older builds accepted ``(Event, Flags)``.
    Try the modern form first, fall back to the legacy 2-arg call.
    """
    try:
        return win32evtlog.EvtFormatMessage(None, evt_handle, flags)
    except TypeError:
        return win32evtlog.EvtFormatMessage(evt_handle, flags)


def _channel_exists(win32evtlog: Any, channel: str) -> bool:
    # Strategy 1 — issue an EvtQuery against the channel. This is the same
    # primitive ``_drain`` uses to actually read events, so it's
    # guaranteed to be exposed in whatever pywin32 build we're running on.
    # If the channel is registered the query succeeds; if not, it raises.
    try:
        flags = win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection
        h = win32evtlog.EvtQuery(channel, flags, "*", None)
        try:
            return True
        finally:
            try:
                win32evtlog.EvtClose(h)
            except Exception:
                pass
    except Exception:
        pass

    # Strategy 2 — enumerate channels. Older pywin32 builds expose this
    # path reliably; newer ones occasionally drop entries.
    try:
        h = win32evtlog.EvtOpenChannelEnum()
        try:
            while True:
                name = win32evtlog.EvtNextChannelPath(h, 256)
                if not name:
                    break
                if name == channel:
                    return True
        finally:
            win32evtlog.EvtClose(h)
    except Exception:
        return False
    return False
