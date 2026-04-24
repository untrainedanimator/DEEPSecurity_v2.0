"""Alert bus routing + non-blocking dispatch + CEF formatting."""
from __future__ import annotations

import threading
import time

from deepsecurity.alerts import (
    AlertBus,
    AlertEvent,
    AlertRule,
    AlertSink,
    CefSyslogSink,
)


class _RecordingSink(AlertSink):
    name = "recording"

    def __init__(self, fail: bool = False) -> None:
        self.events: list[AlertEvent] = []
        self.fail = fail
        self._ev = threading.Event()

    def send(self, ev: AlertEvent) -> None:  # noqa: D401
        if self.fail:
            raise RuntimeError("sink boom")
        self.events.append(ev)
        self._ev.set()

    def wait(self, timeout: float = 1.0) -> bool:
        return self._ev.wait(timeout)


def test_rule_matches_and_dispatches() -> None:
    sink = _RecordingSink()
    bus = AlertBus()
    bus.add_rule(AlertRule("crit", lambda e: e.severity == "critical", [sink]))

    bus.dispatch(AlertEvent(kind="x", severity="critical", summary="boom"))
    assert sink.wait()
    assert sink.events[0].severity == "critical"


def test_first_match_stops_unless_fan_out() -> None:
    a = _RecordingSink()
    b = _RecordingSink()
    bus = AlertBus()
    bus.add_rule(AlertRule("one", lambda e: True, [a]))
    bus.add_rule(AlertRule("two", lambda e: True, [b]))

    bus.dispatch(AlertEvent(kind="x", severity="info", summary="s"))
    assert a.wait()
    # Second rule must not fire because fan_out=False.
    time.sleep(0.05)
    assert b.events == []


def test_fan_out_fires_every_matching_rule() -> None:
    a = _RecordingSink()
    b = _RecordingSink()
    bus = AlertBus()
    bus.add_rule(AlertRule("one", lambda e: True, [a], fan_out=True))
    bus.add_rule(AlertRule("two", lambda e: True, [b], fan_out=True))

    bus.dispatch(AlertEvent(kind="x", severity="info", summary="s"))
    assert a.wait()
    assert b.wait()


def test_failing_sink_does_not_break_bus() -> None:
    good = _RecordingSink()
    bad = _RecordingSink(fail=True)
    bus = AlertBus()
    bus.add_rule(AlertRule("all", lambda e: True, [bad, good]))

    # Must not raise.
    bus.dispatch(AlertEvent(kind="x", severity="info", summary="s"))
    assert good.wait()


def test_failing_predicate_is_skipped() -> None:
    sink = _RecordingSink()
    bus = AlertBus()

    def _boom(_ev: AlertEvent) -> bool:
        raise ValueError("boom")

    bus.add_rule(AlertRule("boom", _boom, [sink]))
    bus.add_rule(AlertRule("ok", lambda e: True, [sink]))

    bus.dispatch(AlertEvent(kind="x", severity="info", summary="s"))
    assert sink.wait()


# ---------------------------------------------------------------------------
# CEF formatting — makes sure the format the SIEM will parse stays stable.
# Don't hit the network here; format-only.
# ---------------------------------------------------------------------------


def _cef() -> CefSyslogSink:
    # Host/port irrelevant — we only call _cef_line().
    return CefSyslogSink("127.0.0.1", 514, device_version="test-0")


def test_cef_header_shape_and_severity_mapping() -> None:
    sink = _cef()
    ev = AlertEvent(
        kind="dlp.critical",
        severity="critical",
        summary="aws_access_key_id in secrets.env",
        actor="admin",
        file_path="C:\\Apps\\repo\\secrets.env",
        details={"mitre_tags": ["T1552.001"], "confidence": 0.95},
    )
    line = sink._cef_line(ev)
    # Header: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|
    assert line.startswith("CEF:0|DEEPSecurity|deepsecurity|test-0|dlp.critical|")
    # Severity 10 for critical per our mapping.
    assert "|10|" in line
    # Extension fields — the stuff SIEMs extract.
    assert "fname=C:\\\\Apps\\\\repo\\\\secrets.env" in line
    assert "src=admin" in line or "suser=admin" in line
    assert "cs1Label=MitreTags" in line
    assert "cs1=T1552.001" in line


def test_cef_escapes_pipes_and_equals() -> None:
    sink = _cef()
    ev = AlertEvent(
        kind="weird|kind",
        severity="info",
        summary="value=with=equals and | pipes",
        file_path="C:\\path\\with=equals",
    )
    line = sink._cef_line(ev)
    # Pipes in the header must be escaped as \|, not bare | (which would
    # break the header/extension boundary for the SIEM parser).
    header_end = line.find("|cs1Label=")
    header_portion = line[: header_end if header_end != -1 else len(line)]
    # The first un-escaped | is the one between header fields; anything in
    # field text should have been escaped.
    escaped_pipes = header_portion.count("\\|")
    assert escaped_pipes >= 1
    # Equals sign inside an extension value must be escaped as \=.
    assert "fname=C:\\\\path\\\\with\\=equals" in line


def test_cef_line_is_newline_free() -> None:
    sink = _cef()
    ev = AlertEvent(
        kind="t",
        severity="low",
        summary="multi\nline\nsummary",
        details={"reasons": ["a\nb", "c"]},
    )
    line = sink._cef_line(ev)
    # Newlines in values would terminate the syslog message early at the
    # collector — we strip them during escaping.
    assert "\n" not in line
    assert "\r" not in line
