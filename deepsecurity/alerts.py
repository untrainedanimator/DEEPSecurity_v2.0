"""Pluggable alert sinks — fire detection + DLP + audit events outbound.

Channels:
    - console      → structlog (always on)
    - webhook      → POST JSON to a URL
    - slack        → Slack incoming webhook (subset of webhook)
    - teams        → Microsoft Teams incoming webhook
    - syslog       → RFC-5424 UDP to a remote syslog collector
    - email        → SMTP (if DEEPSEC_SMTP_HOST is set)

Routing is a list of rules evaluated in order. The first match dispatches
(and then we stop, unless `fan_out=True`). Non-blocking: every dispatch
is fired on a worker thread; a failing sink never affects the caller.
"""
from __future__ import annotations

import json
import smtplib
import socket
import ssl
import threading
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.mime.text import MIMEText
from typing import Any, Callable

from deepsecurity.config import settings
from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Event model
# ---------------------------------------------------------------------------


@dataclass
class AlertEvent:
    """A single alert — what happened, how bad, anything useful to investigate."""

    kind: str  # e.g. "detection.malicious", "dlp.critical", "auth.denied"
    severity: str  # "info" | "low" | "medium" | "high" | "critical"
    summary: str
    actor: str | None = None
    file_path: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "summary": self.summary,
            "actor": self.actor,
            "file_path": self.file_path,
            "details": self.details,
            "timestamp": self.timestamp,
            "source": "deepsecurity",
        }


# ---------------------------------------------------------------------------
# Sinks
# ---------------------------------------------------------------------------


class AlertSink:
    """Base class. Subclasses implement `send()` and handle their own errors."""

    name: str = "base"

    def send(self, ev: AlertEvent) -> None:  # pragma: no cover — abstract
        raise NotImplementedError


class ConsoleSink(AlertSink):
    name = "console"

    def send(self, ev: AlertEvent) -> None:
        _log.info("alert", **ev.to_dict())


class WebhookSink(AlertSink):
    """Fire-and-forget HTTPS POST with a JSON body."""

    name = "webhook"

    def __init__(self, url: str, timeout: float = 5.0) -> None:
        self._url = url
        self._timeout = timeout

    def send(self, ev: AlertEvent) -> None:
        body = json.dumps(ev.to_dict()).encode("utf-8")
        req = urllib.request.Request(
            self._url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=self._timeout, context=ctx) as resp:
                resp.read()
        except Exception:  # noqa: BLE001 — a failing sink never breaks the caller
            _log.exception("alert.webhook_failed", url=self._url)


class SlackSink(WebhookSink):
    name = "slack"

    def send(self, ev: AlertEvent) -> None:
        # Slack prefers a `text` field. Compose a compact message.
        emoji = {
            "critical": ":rotating_light:",
            "high": ":warning:",
            "medium": ":eyes:",
            "low": ":information_source:",
            "info": ":memo:",
        }.get(ev.severity, ":bell:")
        body = {
            "text": f"{emoji} *DEEPSecurity* `{ev.kind}` — {ev.summary}",
            "attachments": [
                {
                    "color": {"critical": "#c0392b", "high": "#e67e22"}.get(
                        ev.severity, "#3498db"
                    ),
                    "fields": [
                        {"title": "actor", "value": ev.actor or "—", "short": True},
                        {
                            "title": "file",
                            "value": f"`{ev.file_path}`" if ev.file_path else "—",
                            "short": True,
                        },
                    ],
                    "ts": int(
                        datetime.fromisoformat(ev.timestamp.replace("Z", "+00:00")).timestamp()
                    ),
                }
            ],
        }
        req = urllib.request.Request(
            self._url,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                resp.read()
        except Exception:
            _log.exception("alert.slack_failed")


class SyslogSink(AlertSink):
    """RFC 5424 UDP syslog."""

    name = "syslog"

    FACILITY_LOCAL0 = 16

    _SEV_MAP = {
        "critical": 2,
        "high": 3,
        "medium": 4,
        "low": 5,
        "info": 6,
    }

    def __init__(self, host: str, port: int = 514) -> None:
        self._addr = (host, port)

    def _pri(self, severity: str) -> int:
        return self.FACILITY_LOCAL0 * 8 + self._SEV_MAP.get(severity, 6)

    def send(self, ev: AlertEvent) -> None:
        msg = (
            f"<{self._pri(ev.severity)}>1 {ev.timestamp} {socket.gethostname()} "
            f"deepsecurity - {ev.kind} - {json.dumps(ev.to_dict())}"
        )
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(msg.encode("utf-8"), self._addr)
        except OSError:
            _log.exception("alert.syslog_failed", host=self._addr[0])


class CefSyslogSink(AlertSink):
    """CEF-over-syslog sink for SIEM ingestion.

    Emits Common Event Format (ArcSight CEF v0) wrapped in an RFC-3164 / 5424
    syslog envelope. Splunk, Elastic, Microsoft Sentinel, ArcSight, QRadar,
    Exabeam and LogRhythm all auto-parse the CEF body into typed fields, so
    the operator gets extractable attributes without a custom parser.

    CEF header:
        CEF:Version|Vendor|Product|DeviceVersion|SignatureID|Name|Severity|

    Extension is space-separated ``key=value`` pairs. Values with spaces
    need not be quoted, but ``\\``, ``|``, ``=`` and newlines MUST be
    escaped (``\\\\``, ``\\|``, ``\\=``, stripped).

    We send UDP by default (fire-and-forget — a stuck SIEM must never block
    our main loop). Set ``cef_protocol=tcp`` if your collector doesn't
    accept UDP.
    """

    name = "cef"

    FACILITY_LOCAL0 = 16

    _SEV_MAP: dict[str, int] = {
        # CEF severity is 0-10. Map our severity labels accordingly.
        "info": 2,
        "low": 4,
        "medium": 6,
        "high": 8,
        "critical": 10,
    }

    # Syslog severity for the envelope (separate from CEF body severity).
    _SYSLOG_SEV: dict[str, int] = {
        "critical": 2,
        "high": 3,
        "medium": 4,
        "low": 5,
        "info": 6,
    }

    def __init__(
        self,
        host: str,
        port: int = 514,
        *,
        protocol: str = "udp",
        device_vendor: str = "DEEPSecurity",
        device_product: str = "deepsecurity",
        device_version: str | None = None,
    ) -> None:
        self._addr = (host, port)
        self._proto = protocol.lower()
        self._vendor = device_vendor
        self._product = device_product
        if device_version is None:
            try:
                from deepsecurity import __version__

                device_version = __version__
            except Exception:
                device_version = "0"
        self._version = device_version

    # -- CEF formatting ------------------------------------------------------

    @staticmethod
    def _escape_header(v: str) -> str:
        """CEF header fields: escape backslash and pipe, strip newlines.

        A CEF line is single-line by spec — the syslog envelope terminates
        on the first newline. A multi-line summary (e.g. a stack trace in
        ``summary``) would otherwise poison every downstream parser that
        reads one-line-per-event, which is essentially all of them.
        Newlines/CR get replaced with spaces before the pipe/backslash
        escape runs.
        """
        s = str(v).replace("\r", " ").replace("\n", " ")
        return s.replace("\\", "\\\\").replace("|", "\\|")

    @staticmethod
    def _escape_ext(v: object) -> str:
        """CEF extension values: escape backslash, equals, and drop newlines."""
        s = str(v)
        s = s.replace("\\", "\\\\").replace("=", "\\=")
        s = s.replace("\r", " ").replace("\n", " ")
        return s

    def _cef_line(self, ev: AlertEvent) -> str:
        sev = self._SEV_MAP.get(ev.severity, 4)
        # Name: short human label, Signature: the event kind.
        signature_id = self._escape_header(ev.kind or "deepsec.event")
        name = self._escape_header(
            (ev.summary or ev.kind or "detection")[:120]
        )

        # Build extension. Map known fields onto standard CEF keys where we
        # can so SIEMs get extracted attributes; fall back to cs1..cs6 for
        # anything custom.
        ext_parts: list[str] = []

        def add(key: str, value: object) -> None:
            if value is None or value == "":
                return
            ext_parts.append(f"{key}={self._escape_ext(value)}")

        add("rt", ev.timestamp)  # Receipt time
        add("src", ev.actor)  # The actor/user/subject
        add("suser", ev.actor)
        add("fname", ev.file_path)
        add("msg", ev.summary)

        # Custom strings for MITRE tags + reasons. cs1Label tells the SIEM
        # what the field is.
        details = dict(ev.details or {})
        tags = details.get("mitre_tags") or []
        if tags:
            add("cs1Label", "MitreTags")
            add("cs1", ",".join(str(t) for t in tags))
        reasons = details.get("reasons") or []
        if reasons:
            add("cs2Label", "Reasons")
            add("cs2", ",".join(str(r) for r in reasons))
        sha = details.get("sha256") or details.get("hash")
        if sha:
            add("fileHash", sha)
        pid = details.get("pid")
        if pid:
            add("dpid", pid)
        confidence = details.get("confidence")
        if confidence is not None:
            add("cn1Label", "Confidence")
            add("cn1", confidence)

        header = (
            f"CEF:0|{self._escape_header(self._vendor)}"
            f"|{self._escape_header(self._product)}"
            f"|{self._escape_header(self._version)}"
            f"|{signature_id}"
            f"|{name}"
            f"|{sev}"
        )
        return header + "|" + " ".join(ext_parts)

    # -- Transport -----------------------------------------------------------

    def _pri(self, severity: str) -> int:
        return self.FACILITY_LOCAL0 * 8 + self._SYSLOG_SEV.get(severity, 6)

    def send(self, ev: AlertEvent) -> None:
        envelope = (
            f"<{self._pri(ev.severity)}>1 {ev.timestamp} {socket.gethostname()} "
            f"deepsecurity - - - "
        )
        payload = (envelope + self._cef_line(ev)).encode("utf-8", errors="replace")

        try:
            if self._proto == "tcp":
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(3.0)
                    sock.connect(self._addr)
                    sock.sendall(payload + b"\n")
            else:  # udp default
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.sendto(payload, self._addr)
        except OSError:
            _log.exception("alert.cef_failed", host=self._addr[0])


class EmailSink(AlertSink):
    """SMTP. Only sends if settings.smtp_host is configured."""

    name = "email"

    def __init__(
        self,
        host: str,
        port: int,
        from_addr: str,
        to_addrs: list[str],
        username: str | None = None,
        password: str | None = None,
        use_tls: bool = True,
    ) -> None:
        self._host = host
        self._port = port
        self._from = from_addr
        self._to = to_addrs
        self._user = username
        self._pass = password
        self._tls = use_tls

    def send(self, ev: AlertEvent) -> None:
        msg = MIMEText(json.dumps(ev.to_dict(), indent=2))
        msg["Subject"] = f"[DEEPSecurity][{ev.severity.upper()}] {ev.kind}: {ev.summary[:80]}"
        msg["From"] = self._from
        msg["To"] = ", ".join(self._to)
        try:
            with smtplib.SMTP(self._host, self._port, timeout=10) as s:
                if self._tls:
                    s.starttls(context=ssl.create_default_context())
                if self._user:
                    s.login(self._user, self._pass or "")
                s.sendmail(self._from, self._to, msg.as_string())
        except Exception:
            _log.exception("alert.email_failed", host=self._host)


# ---------------------------------------------------------------------------
# Bus
# ---------------------------------------------------------------------------


@dataclass
class AlertRule:
    name: str
    predicate: Callable[[AlertEvent], bool]
    sinks: list[AlertSink]
    fan_out: bool = False


class AlertBus:
    """Central dispatch. Rules evaluated in insertion order."""

    def __init__(self) -> None:
        self._rules: list[AlertRule] = []
        self._lock = threading.Lock()

    def add_rule(self, rule: AlertRule) -> None:
        with self._lock:
            self._rules.append(rule)

    def clear(self) -> None:
        with self._lock:
            self._rules.clear()

    def dispatch(self, ev: AlertEvent) -> None:
        """Non-blocking. Every matching sink is invoked on a daemon thread."""
        with self._lock:
            rules = list(self._rules)

        fired = False
        for rule in rules:
            try:
                if not rule.predicate(ev):
                    continue
            except Exception:
                _log.exception("alert.predicate_failed", rule=rule.name)
                continue

            for sink in rule.sinks:
                # Wrap the sink invocation so an exception in one sink never
                # escapes the dispatch thread. Without this wrapper, pytest's
                # thread-exception collector (Python 3.12+) sees the bare
                # RuntimeError from a failing sink and fails the NEXT test's
                # setup, which is exactly what happened to test_login_issues_token.
                def _safe_send(_sink: AlertSink = sink, _ev: AlertEvent = ev) -> None:
                    try:
                        _sink.send(_ev)
                    except Exception:  # noqa: BLE001 — a failing sink never breaks the bus
                        _log.exception("alert.sink_failed", sink=_sink.name)

                threading.Thread(
                    target=_safe_send, daemon=True, name=f"alert-{sink.name}"
                ).start()
            fired = True
            if not rule.fan_out:
                break

        if not fired:
            # Always keep an audit trail in logs even when no rule matches.
            _log.info("alert.no_rule_matched", **ev.to_dict())


# ---------------------------------------------------------------------------
# Default bus construction from settings
# ---------------------------------------------------------------------------


def build_default_bus() -> AlertBus:
    """Assemble an AlertBus from environment settings.

    Always registers the console sink. Optionally adds slack/webhook/syslog/email
    if the corresponding settings are present.
    """
    bus = AlertBus()
    console = ConsoleSink()
    sinks: list[AlertSink] = [console]

    if settings.slack_webhook_url:
        sinks.append(SlackSink(settings.slack_webhook_url))
    if settings.alert_webhook_url:
        sinks.append(WebhookSink(settings.alert_webhook_url))
    if settings.syslog_host:
        sinks.append(SyslogSink(settings.syslog_host, settings.syslog_port))
    if settings.cef_host:
        sinks.append(
            CefSyslogSink(
                settings.cef_host,
                settings.cef_port,
                protocol=settings.cef_protocol,
            )
        )
    if settings.smtp_host and settings.alert_email_to:
        sinks.append(
            EmailSink(
                settings.smtp_host,
                settings.smtp_port,
                settings.alert_email_from or f"deepsecurity@{socket.gethostname()}",
                [e.strip() for e in settings.alert_email_to.split(",") if e.strip()],
                settings.smtp_username,
                settings.smtp_password,
                settings.smtp_starttls,
            )
        )

    # Default rules:
    #   critical + high → everything.
    #   medium        → everything except email.
    #   low/info      → console only.
    bus.add_rule(
        AlertRule(
            "critical",
            lambda ev: ev.severity in {"critical", "high"},
            sinks,
            fan_out=True,
        )
    )
    bus.add_rule(
        AlertRule(
            "medium",
            lambda ev: ev.severity == "medium",
            [s for s in sinks if s.name != "email"],
            fan_out=True,
        )
    )
    bus.add_rule(AlertRule("default", lambda _ev: True, [console]))
    return bus


# Process-wide bus. Rebuild in tests via `bus = build_default_bus()`.
bus = build_default_bus()
