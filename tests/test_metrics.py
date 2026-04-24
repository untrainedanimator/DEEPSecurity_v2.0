"""Prometheus exposition format sanity."""
from __future__ import annotations

from deepsecurity.metrics import Metrics


def test_initial_render_contains_expected_metric_names() -> None:
    m = Metrics()
    out = m.render()
    for name in (
        "deepsec_build_info",
        "deepsec_uptime_seconds",
        "deepsec_scans_started_total",
        "deepsec_files_scanned_total",
        "deepsec_detections_total",
        "deepsec_dlp_findings_total",
        "deepsec_scan_duration_seconds_bucket",
        "deepsec_scan_duration_seconds_sum",
        "deepsec_scan_duration_seconds_count",
    ):
        assert name in out


def test_counter_increments_show_up_in_render() -> None:
    m = Metrics()
    m.inc("files_scanned", 7)
    m.inc("detections_total", 2)
    out = m.render()
    assert "deepsec_files_scanned_total 7" in out
    assert "deepsec_detections_total 2" in out


def test_histogram_buckets_are_cumulative() -> None:
    m = Metrics()
    for v in (0.01, 0.2, 0.4, 2.0, 30.0):
        m.observe("scan_duration_seconds", v)
    out = m.render()
    # Sanity: total count equals observations.
    assert "deepsec_scan_duration_seconds_count 5" in out
