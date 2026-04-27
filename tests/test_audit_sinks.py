"""Smoke tests for the audit-sink replication module."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from deepsecurity import audit_sinks


@pytest.fixture(autouse=True)
def _reset_global() -> None:
    """Each test gets a clean global sink registry."""
    audit_sinks.reset_for_tests()
    yield
    audit_sinks.reset_for_tests()


def test_make_event_has_stable_schema() -> None:
    ev = audit_sinks.make_event(
        actor="alice",
        action="scan.start",
        status="ok",
        file_path="/tmp/x",
        details={"k": 1},
    )
    assert ev["actor"] == "alice"
    assert ev["action"] == "scan.start"
    assert ev["status"] == "ok"
    assert ev["file_path"] == "/tmp/x"
    assert ev["details"] == {"k": 1}
    assert ev["schema"] == "deepsec.audit/1"
    assert "ts" in ev
    assert "host" in ev


def test_file_sink_writes_jsonl(tmp_path: Path) -> None:
    sink_path = tmp_path / "audit.jsonl"
    sink = audit_sinks.FileSink(path=sink_path, rotate_daily=False)
    ev = audit_sinks.make_event(
        actor="bob", action="scan.done", status="ok",
        file_path=None, details={"hits": 3},
    )
    sink.emit(ev)
    sink.flush()
    sink.close()

    content = sink_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(content) == 1
    parsed = json.loads(content[0])
    assert parsed["actor"] == "bob"
    assert parsed["details"] == {"hits": 3}


def test_batched_sink_drains_to_underlying(tmp_path: Path) -> None:
    sink_path = tmp_path / "audit.jsonl"
    file_sink = audit_sinks.FileSink(path=sink_path, rotate_daily=False)
    batched = audit_sinks.BatchedSink(
        sinks=[file_sink],
        batch_size=4,
        flush_interval_s=0.05,
    )
    batched.start()
    try:
        for i in range(10):
            batched.put(audit_sinks.make_event(
                actor="batch", action=f"step.{i}", status="ok",
                file_path=None, details=None,
            ))
        # Wait for the drain thread to flush (deadline 2s, should be far less).
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if sink_path.exists() and len(
                sink_path.read_text(encoding="utf-8").strip().splitlines()
            ) >= 10:
                break
            time.sleep(0.05)
    finally:
        batched.flush_and_close()

    lines = sink_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 10
    actions = [json.loads(line)["action"] for line in lines]
    assert actions == [f"step.{i}" for i in range(10)]


def test_init_from_env_returns_none_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    for k in (
        "DEEPSEC_AUDIT_SINK_WEBHOOK_URL",
        "DEEPSEC_AUDIT_SINK_SYSLOG_HOST",
        "DEEPSEC_AUDIT_SINK_FILE_PATH",
    ):
        monkeypatch.delenv(k, raising=False)
    assert audit_sinks.init_from_env() is None
    assert audit_sinks.get_global() is None


def test_init_from_env_starts_file_sink(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sink_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("DEEPSEC_AUDIT_SINK_FILE_PATH", str(sink_path))
    monkeypatch.setenv("DEEPSEC_AUDIT_SINK_FLUSH_INTERVAL_S", "0.05")

    batched = audit_sinks.init_from_env()
    assert batched is not None

    # FileSink defaults to ``rotate_daily=True``, so the actual file written
    # is ``audit.YYYYMMDD.jsonl`` next to the configured path. Look for any
    # match in the parent directory rather than the literal path.
    def _find_written() -> Path | None:
        if sink_path.exists() and sink_path.read_text(encoding="utf-8").strip():
            return sink_path
        for p in sink_path.parent.glob("audit.*.jsonl"):
            try:
                if p.read_text(encoding="utf-8").strip():
                    return p
            except OSError:
                continue
        return None

    try:
        batched.put(audit_sinks.make_event(
            actor="env", action="boot", status="ok",
            file_path=None, details=None,
        ))
        # Wait for the drain.
        deadline = time.monotonic() + 2.0
        written: Path | None = None
        while time.monotonic() < deadline:
            written = _find_written()
            if written is not None:
                break
            time.sleep(0.05)
    finally:
        batched.flush_and_close()

    written = _find_written()
    assert written is not None, (
        f"no JSONL written under {sink_path.parent} — "
        f"contents: {list(sink_path.parent.iterdir())}"
    )
    parsed = json.loads(written.read_text(encoding="utf-8").strip().splitlines()[0])
    assert parsed["actor"] == "env"
    assert parsed["action"] == "boot"


def test_drop_oldest_under_pressure() -> None:
    """Sink with queue_max=2 must drop oldest events under sustained pressure."""

    class _CountingSink(audit_sinks.AuditSink):
        name = "count"

        def __init__(self) -> None:
            self.received: list[dict] = []

        def emit(self, event: dict) -> None:
            self.received.append(event)

    counter = _CountingSink()
    batched = audit_sinks.BatchedSink(
        sinks=[counter],
        batch_size=1,
        flush_interval_s=10.0,  # never auto-drains during the test
        queue_max=2,
    )
    batched.start()
    try:
        for i in range(5):
            batched.put({"i": i})
        # No drain has happened yet — _dropped should reflect overflow.
        assert batched.dropped >= 1
    finally:
        batched.flush_and_close()
