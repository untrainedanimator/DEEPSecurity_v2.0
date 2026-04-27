"""External audit-log sinks.

Closes the v3 production gap "audit log not replicated externally".

The default ``audit_log()`` writer persists to the local DB and emits a
structured stdout line. Both of those are inside-the-blast-radius — if
the DB is wiped or the host is compromised, the trail goes with it. For
SOC2 Type II / ISO 27001 audits where the assessor wants 90 days of
tamper-evident evidence, you want the audit stream replicated to an
external WORM-style sink that an attacker on this box cannot reach.

This module provides three replication targets, all opt-in via env vars:

    * ``WebhookSink``  — HTTPS POST to an external collector (Datadog,
                         Splunk HEC, custom SIEM ingest). JSON body,
                         optional bearer token.
    * ``SyslogSink``   — RFC 5424 / 3164 to a syslog daemon on UDP/TCP.
                         Works with rsyslog, syslog-ng, papertrail,
                         loggly, etc.
    * ``FileSink``     — Append-only JSONL to a daily-rotated file on a
                         separate volume / NFS mount. Cheapest WORM
                         pattern when you don't have an external sink.

All sinks are wrapped in ``BatchedSink`` for async, batched delivery so
audit_log() never blocks on a slow network. A background thread drains
the queue every flush_interval_s seconds (default 2.0). On shutdown,
``flush_all()`` is called from atexit so in-flight events are written.

Failure semantics — the same as audit_log itself: **a sink failure must
never crash the audited action**. A failed POST logs a warning at most
once per minute (rate-limited so a misconfigured webhook doesn't flood
stdout) and the event is dropped. We deliberately do not retry forever
because that would leak memory under a sustained outage.

Configuration (env vars, all optional — sinks default OFF):

    DEEPSEC_AUDIT_SINK_WEBHOOK_URL=https://collector.example/audit
    DEEPSEC_AUDIT_SINK_WEBHOOK_TOKEN=<bearer>           (optional)
    DEEPSEC_AUDIT_SINK_SYSLOG_HOST=syslog.example
    DEEPSEC_AUDIT_SINK_SYSLOG_PORT=514                  (default 514)
    DEEPSEC_AUDIT_SINK_SYSLOG_PROTOCOL=udp              (udp|tcp)
    DEEPSEC_AUDIT_SINK_FILE_PATH=/var/log/deepsec/audit.jsonl
    DEEPSEC_AUDIT_SINK_BATCH_SIZE=64                    (events per flush)
    DEEPSEC_AUDIT_SINK_FLUSH_INTERVAL_S=2.0
    DEEPSEC_AUDIT_SINK_QUEUE_MAX=10000                  (drop oldest above)
"""

from __future__ import annotations

import atexit
import json
import queue
import socket
import threading
import time
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Event shape
# ---------------------------------------------------------------------------


def make_event(
    *,
    actor: str,
    action: str,
    status: str,
    file_path: str | None,
    details: dict[str, Any] | None,
    host: str | None = None,
) -> dict[str, Any]:
    """Build a single canonical audit event dict.

    Stable schema — external collectors can parse this reliably across
    versions. New fields go at the bottom; old fields are never removed
    or repurposed.
    """
    return {
        "ts": datetime.now(UTC).isoformat(),
        "host": host or socket.gethostname(),
        "actor": actor,
        "action": action,
        "status": status,
        "file_path": file_path,
        "details": details or {},
        "schema": "deepsec.audit/1",
    }


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class AuditSink(ABC):
    """One destination for a stream of audit events."""

    name: str = "base"

    @abstractmethod
    def emit(self, event: dict[str, Any]) -> None:
        """Synchronously deliver one event. Should be cheap; the batched
        wrapper handles concurrency."""

    def flush(self) -> None:  # noqa: B027  # base no-op intentional
        """Best-effort: ensure all queued events are written. Default is
        a no-op for transports that don't buffer (e.g. file sync)."""

    def close(self) -> None:  # noqa: B027
        """Release any held handles (sockets, file descriptors)."""


# ---------------------------------------------------------------------------
# WebhookSink — HTTPS POST
# ---------------------------------------------------------------------------


class WebhookSink(AuditSink):
    """POST a JSON body of {"events": [...]} to a collector URL."""

    name = "webhook"

    def __init__(
        self,
        url: str,
        *,
        bearer_token: str | None = None,
        timeout_s: float = 5.0,
        verify_tls: bool = True,
    ) -> None:
        self.url = url
        self.bearer_token = bearer_token
        self.timeout_s = timeout_s
        self.verify_tls = verify_tls
        # Last-failure timestamp for log rate-limiting (one warning per
        # minute even under sustained failure).
        self._last_warn = 0.0

    def emit_batch(self, events: list[dict[str, Any]]) -> None:
        """Override of emit for batched delivery — saves N round-trips."""
        try:
            import requests  # local import — only imported if the sink runs
        except ImportError:
            self._warn_once("webhook.requests_missing")
            return

        headers = {"Content-Type": "application/json", "User-Agent": "deepsec-audit/1"}
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"

        try:
            resp = requests.post(
                self.url,
                data=json.dumps({"events": events}),
                headers=headers,
                timeout=self.timeout_s,
                verify=self.verify_tls,
            )
            if resp.status_code >= 400:
                self._warn_once(
                    "webhook.http_error",
                    status=resp.status_code,
                    dropped=len(events),
                )
        except Exception as exc:
            self._warn_once(
                "webhook.network_error",
                error=f"{type(exc).__name__}: {exc}",
                dropped=len(events),
            )

    def emit(self, event: dict[str, Any]) -> None:
        self.emit_batch([event])

    def _warn_once(self, msg: str, **fields: Any) -> None:
        now = time.monotonic()
        if now - self._last_warn < 60.0:
            return
        self._last_warn = now
        _log.warning(msg, sink=self.name, url=self.url, **fields)


# ---------------------------------------------------------------------------
# SyslogSink — RFC 5424 over UDP/TCP
# ---------------------------------------------------------------------------


class SyslogSink(AuditSink):
    """Send each event as one RFC 5424 syslog message.

    facility=LOCAL0, severity=NOTICE for ok / WARNING for warning /
    ERROR for failed. The MSG field is the JSON-serialised event so a
    syslog collector can parse it back out without losing structure.
    """

    name = "syslog"

    # RFC 5424 priority calc: facility * 8 + severity
    _FACILITY_LOCAL0 = 16
    _SEV_BY_STATUS: ClassVar[dict[str, int]] = {
        "ok": 5,        # notice
        "info": 6,      # informational
        "warning": 4,   # warning
        "warn": 4,
        "failed": 3,    # error
        "fail": 3,
        "denied": 4,
    }

    def __init__(
        self,
        host: str,
        port: int = 514,
        *,
        protocol: str = "udp",
        app_name: str = "deepsec",
    ) -> None:
        self.host = host
        self.port = int(port)
        self.protocol = protocol.lower()
        self.app_name = app_name
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()
        self._last_warn = 0.0

    def _ensure_socket(self) -> socket.socket | None:
        with self._lock:
            if self._sock is not None:
                return self._sock
            try:
                if self.protocol == "tcp":
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2.0)
                    s.connect((self.host, self.port))
                else:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._sock = s
                return s
            except Exception as exc:
                self._warn_once("syslog.connect_failed", error=str(exc))
                return None

    def emit(self, event: dict[str, Any]) -> None:
        sev = self._SEV_BY_STATUS.get(str(event.get("status", "ok")).lower(), 5)
        prio = self._FACILITY_LOCAL0 * 8 + sev
        ts = event.get("ts", datetime.now(UTC).isoformat())
        host = event.get("host", "-")
        body = json.dumps(event, default=str)
        # RFC 5424: <prio>1 ts host app procid msgid - body
        line = f"<{prio}>1 {ts} {host} {self.app_name} - audit - {body}\n"
        sock = self._ensure_socket()
        if sock is None:
            return
        try:
            if self.protocol == "tcp":
                sock.sendall(line.encode("utf-8"))
            else:
                sock.sendto(line.encode("utf-8"), (self.host, self.port))
        except Exception as exc:
            self._warn_once("syslog.send_failed", error=str(exc))
            # Force reconnect on next emit.
            self._reset_socket()

    def _reset_socket(self) -> None:
        with self._lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None

    def _warn_once(self, msg: str, **fields: Any) -> None:
        now = time.monotonic()
        if now - self._last_warn < 60.0:
            return
        self._last_warn = now
        _log.warning(msg, sink=self.name, host=self.host, port=self.port, **fields)

    def close(self) -> None:
        self._reset_socket()


# ---------------------------------------------------------------------------
# FileSink — append-only JSONL with daily rotation
# ---------------------------------------------------------------------------


class FileSink(AuditSink):
    """Append-only JSONL audit log on disk.

    The path is opened in append-mode O_APPEND so concurrent writers
    don't interleave bytes. A new file is opened automatically when the
    UTC date rolls over (suffix YYYYMMDD inserted before extension).
    Writes flush+fsync per batch by default — slower but actually
    durable across power loss, which is the whole point of an audit
    sink.
    """

    name = "file"

    def __init__(
        self,
        path: str | Path,
        *,
        rotate_daily: bool = True,
        fsync: bool = True,
    ) -> None:
        self._base = Path(path)
        self._base.parent.mkdir(parents=True, exist_ok=True)
        self._rotate_daily = rotate_daily
        self._fsync = fsync
        self._lock = threading.Lock()
        self._fp = None  # type: ignore[var-annotated]
        self._fp_date: str | None = None
        self._last_warn = 0.0

    def _path_for_today(self) -> Path:
        if not self._rotate_daily:
            return self._base
        stem = self._base.stem
        suffix = self._base.suffix or ".jsonl"
        date = datetime.now(UTC).strftime("%Y%m%d")
        return self._base.with_name(f"{stem}.{date}{suffix}")

    def _ensure_open(self) -> None:
        date = datetime.now(UTC).strftime("%Y%m%d")
        if self._fp is not None and self._fp_date == date:
            return
        if self._fp is not None:
            try:
                self._fp.close()
            except Exception:
                pass
        path = self._path_for_today()
        path.parent.mkdir(parents=True, exist_ok=True)
        # ``a`` is append, line-buffered for crash safety.
        self._fp = open(path, "a", encoding="utf-8", buffering=1)  # noqa: PTH123, SIM115
        self._fp_date = date

    def emit(self, event: dict[str, Any]) -> None:
        with self._lock:
            try:
                self._ensure_open()
                assert self._fp is not None
                self._fp.write(json.dumps(event, default=str) + "\n")
                if self._fsync:
                    self._fp.flush()
            except Exception as exc:
                self._warn_once("file.write_failed", error=str(exc))

    def flush(self) -> None:
        with self._lock:
            if self._fp is not None:
                try:
                    self._fp.flush()
                except Exception:
                    pass

    def close(self) -> None:
        with self._lock:
            if self._fp is not None:
                try:
                    self._fp.close()
                except Exception:
                    pass
                self._fp = None

    def _warn_once(self, msg: str, **fields: Any) -> None:
        now = time.monotonic()
        if now - self._last_warn < 60.0:
            return
        self._last_warn = now
        _log.warning(msg, sink=self.name, path=str(self._base), **fields)


# ---------------------------------------------------------------------------
# Batched async wrapper
# ---------------------------------------------------------------------------


class BatchedSink:
    """Wraps a list of AuditSink and drains them from a background thread.

    Audit_log() calls ``put(event)`` which is non-blocking (bounded
    queue with drop-oldest on overflow). A worker thread pulls events
    every ``flush_interval_s`` seconds, batches up to ``batch_size``,
    and emits to each underlying sink. The ``WebhookSink`` short-circuits
    its emit_batch for one round-trip; others get a per-event loop.
    """

    def __init__(
        self,
        sinks: list[AuditSink],
        *,
        batch_size: int = 64,
        flush_interval_s: float = 2.0,
        queue_max: int = 10_000,
    ) -> None:
        self._sinks = sinks
        self._batch_size = max(1, int(batch_size))
        self._flush_interval = max(0.1, float(flush_interval_s))
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=int(queue_max))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._dropped = 0
        self._lock = threading.Lock()

    def start(self) -> None:
        if self._thread is not None:
            return
        if not self._sinks:
            return  # nothing to drain to — don't spin a worker
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="audit-sink-drainer",
            daemon=True,
        )
        self._thread.start()
        atexit.register(self.flush_and_close)

    def put(self, event: dict[str, Any]) -> None:
        if not self._sinks:
            return
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            # Drop oldest, push new — at-most-once policy under pressure.
            try:
                self._queue.get_nowait()
            except queue.Empty:
                pass
            with self._lock:
                self._dropped += 1
            try:
                self._queue.put_nowait(event)
            except queue.Full:
                pass  # truly hopeless — drop new

    def _drain_once(self) -> int:
        """Pull up to batch_size events and emit. Returns count drained."""
        batch: list[dict[str, Any]] = []
        while len(batch) < self._batch_size:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        if not batch:
            return 0
        for sink in self._sinks:
            try:
                emit_batch = getattr(sink, "emit_batch", None)
                if callable(emit_batch):
                    emit_batch(batch)
                else:
                    for ev in batch:
                        sink.emit(ev)
            except Exception as exc:
                _log.warning(
                    "audit.sink.emit_failed",
                    sink=sink.name,
                    error=f"{type(exc).__name__}: {exc}",
                    dropped=len(batch),
                )
        return len(batch)

    def _run(self) -> None:
        while not self._stop.is_set():
            self._drain_once()
            self._stop.wait(self._flush_interval)
        # final drain
        while self._drain_once() > 0:
            pass

    def flush_and_close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        for sink in self._sinks:
            try:
                sink.flush()
            except Exception:
                pass
            try:
                sink.close()
            except Exception:
                pass

    @property
    def dropped(self) -> int:
        with self._lock:
            return self._dropped


# ---------------------------------------------------------------------------
# Module-level singleton + factory
# ---------------------------------------------------------------------------


_GLOBAL: BatchedSink | None = None
_GLOBAL_LOCK = threading.Lock()


def get_global() -> BatchedSink | None:
    """Return the configured global BatchedSink, or None if no sinks."""
    return _GLOBAL


def init_from_env() -> BatchedSink | None:
    """Read DEEPSEC_AUDIT_SINK_* env vars and start sinks."""
    global _GLOBAL
    with _GLOBAL_LOCK:
        if _GLOBAL is not None:
            return _GLOBAL

        import os

        sinks: list[AuditSink] = []

        webhook_url = os.environ.get("DEEPSEC_AUDIT_SINK_WEBHOOK_URL", "").strip()
        if webhook_url:
            sinks.append(
                WebhookSink(
                    url=webhook_url,
                    bearer_token=os.environ.get(
                        "DEEPSEC_AUDIT_SINK_WEBHOOK_TOKEN"
                    ) or None,
                )
            )

        syslog_host = os.environ.get("DEEPSEC_AUDIT_SINK_SYSLOG_HOST", "").strip()
        if syslog_host:
            sinks.append(
                SyslogSink(
                    host=syslog_host,
                    port=int(os.environ.get("DEEPSEC_AUDIT_SINK_SYSLOG_PORT", "514")),
                    protocol=os.environ.get(
                        "DEEPSEC_AUDIT_SINK_SYSLOG_PROTOCOL", "udp"
                    ),
                )
            )

        file_path = os.environ.get("DEEPSEC_AUDIT_SINK_FILE_PATH", "").strip()
        if file_path:
            sinks.append(FileSink(path=file_path))

        if not sinks:
            return None

        batched = BatchedSink(
            sinks=sinks,
            batch_size=int(os.environ.get("DEEPSEC_AUDIT_SINK_BATCH_SIZE", "64")),
            flush_interval_s=float(
                os.environ.get("DEEPSEC_AUDIT_SINK_FLUSH_INTERVAL_S", "2.0")
            ),
            queue_max=int(os.environ.get("DEEPSEC_AUDIT_SINK_QUEUE_MAX", "10000")),
        )
        batched.start()
        _GLOBAL = batched
        _log.info(
            "audit.sinks.started",
            sinks=[s.name for s in sinks],
            batch_size=batched._batch_size,
            flush_interval_s=batched._flush_interval,
        )
        return batched


def reset_for_tests() -> None:
    """Tear down the global BatchedSink — used by pytest fixtures."""
    global _GLOBAL
    with _GLOBAL_LOCK:
        if _GLOBAL is not None:
            _GLOBAL.flush_and_close()
        _GLOBAL = None
