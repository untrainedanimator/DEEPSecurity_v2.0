"""Prometheus-compatible text metrics.

Tiny zero-dependency exporter. We don't pull `prometheus_client` — everything
we need is a handful of atomic counters and a single format helper. If you
prefer the official client library, swap `render()` for `prometheus_client.generate_latest`.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass
class _Counter:
    value: float = 0.0

    def inc(self, by: float = 1.0) -> None:
        self.value += by


@dataclass
class _Gauge:
    value: float = 0.0

    def set(self, v: float) -> None:
        self.value = v


@dataclass
class _Histogram:
    # Cheap approximation — we keep count + sum + a small set of bucket counters.
    buckets: tuple[float, ...] = (0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 60.0)
    bucket_counts: list[int] = field(default_factory=lambda: [0] * 8)
    total_count: int = 0
    total_sum: float = 0.0

    def observe(self, value: float) -> None:
        self.total_count += 1
        self.total_sum += value
        for i, b in enumerate(self.buckets):
            if value <= b:
                self.bucket_counts[i] += 1


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.scans_started = _Counter()
        self.scans_completed = _Counter()
        self.scans_failed = _Counter()
        self.files_scanned = _Counter()
        self.detections_total = _Counter()
        self.dlp_findings_total = _Counter()
        self.quarantine_actions = _Counter()
        self.active_scans = _Gauge()
        self.scan_duration_seconds = _Histogram()
        self.alerts_sent = _Counter()
        self.auth_denied = _Counter()
        self._started_at = time.time()

    # -- mutators (thread-safe) ----------------------------------------
    def inc(self, name: str, by: float = 1.0) -> None:
        with self._lock:
            obj = getattr(self, name, None)
            if isinstance(obj, _Counter):
                obj.inc(by)

    def set(self, name: str, v: float) -> None:
        with self._lock:
            obj = getattr(self, name, None)
            if isinstance(obj, _Gauge):
                obj.set(v)

    def observe(self, name: str, value: float) -> None:
        with self._lock:
            obj = getattr(self, name, None)
            if isinstance(obj, _Histogram):
                obj.observe(value)

    # -- rendering ------------------------------------------------------
    def render(self) -> str:
        with self._lock:
            out: list[str] = []

            out.append("# HELP deepsec_build_info Build metadata")
            out.append("# TYPE deepsec_build_info gauge")
            out.append('deepsec_build_info{version="2.2.0"} 1')

            out.append("# HELP deepsec_uptime_seconds Process uptime")
            out.append("# TYPE deepsec_uptime_seconds gauge")
            out.append(f"deepsec_uptime_seconds {time.time() - self._started_at:.2f}")

            for name, metric in (
                ("deepsec_scans_started_total", self.scans_started),
                ("deepsec_scans_completed_total", self.scans_completed),
                ("deepsec_scans_failed_total", self.scans_failed),
                ("deepsec_files_scanned_total", self.files_scanned),
                ("deepsec_detections_total", self.detections_total),
                ("deepsec_dlp_findings_total", self.dlp_findings_total),
                ("deepsec_quarantine_actions_total", self.quarantine_actions),
                ("deepsec_alerts_sent_total", self.alerts_sent),
                ("deepsec_auth_denied_total", self.auth_denied),
            ):
                out.append(f"# TYPE {name} counter")
                out.append(f"{name} {metric.value:.0f}")

            out.append("# TYPE deepsec_active_scans gauge")
            out.append(f"deepsec_active_scans {self.active_scans.value:.0f}")

            # Histogram
            h = self.scan_duration_seconds
            cumulative = 0
            out.append("# TYPE deepsec_scan_duration_seconds histogram")
            for b, c in zip(h.buckets, h.bucket_counts, strict=True):
                cumulative += c
                out.append(f'deepsec_scan_duration_seconds_bucket{{le="{b}"}} {cumulative}')
            out.append(
                f'deepsec_scan_duration_seconds_bucket{{le="+Inf"}} {h.total_count}'
            )
            out.append(f"deepsec_scan_duration_seconds_sum {h.total_sum:.3f}")
            out.append(f"deepsec_scan_duration_seconds_count {h.total_count}")

            out.append("")
            return "\n".join(out)


# Process singleton.
metrics = Metrics()
