"""Soak-loop metrics collector and pass/fail evaluator.

Closes the v3 production gap "24-hour soak loop not yet run". The
existing ``scripts/loop_24h.py`` runs the work; this module gives it a
metrics dimension so the soak run produces an objective PASS / FAIL
verdict instead of a wall of cycle logs.

Captures per cycle (best-effort, never raises):

    * RSS in MB of every running deepsec process (sum + max)
    * open file count (psutil) — proxy for FD leaks
    * thread count (psutil)
    * audit_log row count (single SQL count(*) — cheap)
    * /healthz status code (None if backend down)
    * /readyz status code

Writes:

    metrics.csv      — one row per cycle, easy spreadsheet import
    metrics.jsonl    — same data structured for grep / jq
    summary.md       — verdict + baseline + final + ASCII chart
    summary.json     — machine-readable verdict for CI gating

Pass/fail thresholds (default, override via env vars):

    DEEPSEC_SOAK_RSS_GROWTH_PCT       — fail if RSS grows > this % from
                                        the median of the first 5 cycles.
                                        Default 25 %.
    DEEPSEC_SOAK_FD_LEAK_THRESHOLD    — fail if final - baseline FD count
                                        exceeds this. Default 50.
    DEEPSEC_SOAK_AUDIT_MUST_INCREASE  — fail if audit count never grew.
                                        Default true.

Usage from loop_24h.py: import soak_metrics, snapshot per cycle, finalize
on exit. Standalone CLI also supported for ad-hoc runs:

    python scripts/soak_metrics.py --finalize logs/loop_24h_<stamp>/
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Metric snapshot
# ---------------------------------------------------------------------------


def snapshot(*, deepsec_proc_filter: str = "deepsec") -> dict[str, Any]:
    """Take a single metrics snapshot. Best-effort — never raises."""
    rec: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(),
        "rss_total_mb": 0.0,
        "rss_max_mb": 0.0,
        "process_count": 0,
        "open_files": 0,
        "thread_count": 0,
        "healthz_status": None,
        "readyz_status": None,
        "audit_count": None,
    }

    rec.update(_process_stats(filter_substr=deepsec_proc_filter))
    rec.update(_http_stats())
    rec["audit_count"] = _audit_count()
    return rec


def _process_stats(*, filter_substr: str) -> dict[str, Any]:
    out = {"rss_total_mb": 0.0, "rss_max_mb": 0.0, "process_count": 0,
           "open_files": 0, "thread_count": 0}
    try:
        import psutil  # already a runtime dep
    except Exception:
        return out

    me = os.getpid()
    rss_total = 0.0
    rss_max = 0.0
    open_files = 0
    thread_count = 0
    count = 0
    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            cmdline = " ".join(p.info.get("cmdline") or [])
            name = (p.info.get("name") or "").lower()
            if p.info.get("pid") == me:
                continue
            if filter_substr not in name and filter_substr not in cmdline.lower():
                continue
            mi = p.memory_info()
            rss_mb = mi.rss / (1024 * 1024)
            rss_total += rss_mb
            rss_max = max(rss_max, rss_mb)
            count += 1
            try:
                open_files += len(p.open_files())
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            try:
                thread_count += p.num_threads()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    out["rss_total_mb"] = round(rss_total, 1)
    out["rss_max_mb"] = round(rss_max, 1)
    out["process_count"] = count
    out["open_files"] = open_files
    out["thread_count"] = thread_count
    return out


def _http_stats() -> dict[str, Any]:
    out: dict[str, Any] = {"healthz_status": None, "readyz_status": None}
    try:
        import urllib.error
        import urllib.request
    except Exception:
        return out

    base_http = os.environ.get("DEEPSEC_SOAK_BACKEND_URL", "http://127.0.0.1:5000")

    def probe(path: str) -> int | None:
        try:
            ctx = None
            if base_http.startswith("https://"):
                import ssl

                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(
                base_http.rstrip("/") + path,
                timeout=2.0,
                context=ctx,
            ) as r:
                return int(r.status)
        except urllib.error.HTTPError as exc:
            return int(exc.code)
        except Exception:
            return None

    out["healthz_status"] = probe("/healthz")
    out["readyz_status"] = probe("/readyz")
    return out


def _audit_count() -> int | None:
    """Return audit_log row count, or None if DB not reachable."""
    try:
        from deepsecurity.db import session_scope
        from deepsecurity.models import AuditLog
        with session_scope() as session:
            return int(session.query(AuditLog).count())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Streaming writer
# ---------------------------------------------------------------------------


_CSV_FIELDS = [
    "ts", "rss_total_mb", "rss_max_mb", "process_count",
    "open_files", "thread_count", "healthz_status", "readyz_status",
    "audit_count",
]


class MetricsRecorder:
    """Append-only metrics writer (CSV + JSONL) safe for crash mid-soak."""

    def __init__(self, out_dir: Path) -> None:
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.csv_path = self.out_dir / "metrics.csv"
        self.jsonl_path = self.out_dir / "metrics.jsonl"
        self.summary_md = self.out_dir / "summary.md"
        self.summary_json = self.out_dir / "summary.json"
        # Write CSV header once.
        if not self.csv_path.exists():
            with self.csv_path.open("w", encoding="utf-8", newline="") as fp:
                csv.DictWriter(fp, fieldnames=_CSV_FIELDS).writeheader()

    def record(self, snap: dict[str, Any]) -> None:
        with self.csv_path.open("a", encoding="utf-8", newline="") as fp:
            csv.DictWriter(fp, fieldnames=_CSV_FIELDS).writerow(
                {k: snap.get(k) for k in _CSV_FIELDS}
            )
        with self.jsonl_path.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(snap, default=str) + "\n")

    def load_all(self) -> list[dict[str, Any]]:
        if not self.jsonl_path.exists():
            return []
        out: list[dict[str, Any]] = []
        with self.jsonl_path.open("r", encoding="utf-8") as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    # JSONL is append-only; a partial last line at the
                    # tail is normal during an active soak run. Drop it
                    # silently — it'll be complete on the next read.
                    continue
        return out


# ---------------------------------------------------------------------------
# Pass / fail evaluator
# ---------------------------------------------------------------------------


def evaluate(snapshots: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute the PASS/FAIL verdict from a list of snapshots."""
    rss_growth_threshold = float(os.environ.get("DEEPSEC_SOAK_RSS_GROWTH_PCT", "25"))
    fd_leak_threshold = int(os.environ.get("DEEPSEC_SOAK_FD_LEAK_THRESHOLD", "50"))
    audit_must_increase = (
        os.environ.get("DEEPSEC_SOAK_AUDIT_MUST_INCREASE", "true").lower()
        in ("1", "true", "yes", "on")
    )

    n = len(snapshots)
    if n == 0:
        return {
            "verdict": "FAIL",
            "reason": "no snapshots recorded",
            "snapshots": 0,
        }

    # Baseline = median of first min(5, n) snapshots — robust to one-off
    # spikes during initial warm-up.
    baseline_n = max(1, min(5, n))
    baseline_rss = statistics.median(s["rss_total_mb"] or 0 for s in snapshots[:baseline_n])
    baseline_fd = statistics.median(s["open_files"] or 0 for s in snapshots[:baseline_n])
    baseline_audit = snapshots[0].get("audit_count") or 0

    final = snapshots[-1]
    final_rss = float(final.get("rss_total_mb") or 0)
    final_fd = int(final.get("open_files") or 0)
    final_audit = final.get("audit_count") or 0

    # Growth metrics — guard against div-by-zero.
    rss_growth_pct = (
        ((final_rss - baseline_rss) / baseline_rss * 100.0) if baseline_rss > 0 else 0.0
    )
    fd_delta = int(final_fd - baseline_fd)
    audit_delta = int(final_audit - baseline_audit)

    failures: list[str] = []
    if rss_growth_pct > rss_growth_threshold:
        failures.append(
            f"RSS grew {rss_growth_pct:.1f}% from baseline (threshold {rss_growth_threshold}%)"
        )
    if fd_delta > fd_leak_threshold:
        failures.append(
            f"open file count grew by {fd_delta} from baseline (threshold {fd_leak_threshold})"
        )
    if audit_must_increase and audit_delta <= 0 and final.get("audit_count") is not None:
        failures.append(
            f"audit_log row count did not increase ({baseline_audit} → {final_audit})"
        )

    # Server up at end?
    final_healthz = final.get("healthz_status")
    if final_healthz is None or not (200 <= int(final_healthz) < 400):
        failures.append(f"backend /healthz not OK at end (status={final_healthz})")

    return {
        "verdict": "FAIL" if failures else "PASS",
        "snapshots": n,
        "baseline_rss_mb": round(baseline_rss, 1),
        "final_rss_mb": round(final_rss, 1),
        "rss_growth_pct": round(rss_growth_pct, 2),
        "rss_growth_threshold_pct": rss_growth_threshold,
        "baseline_fd": int(baseline_fd),
        "final_fd": final_fd,
        "fd_delta": fd_delta,
        "fd_leak_threshold": fd_leak_threshold,
        "baseline_audit_count": int(baseline_audit),
        "final_audit_count": int(final_audit),
        "audit_delta": audit_delta,
        "final_healthz": final_healthz,
        "failures": failures,
    }


def render_summary(snapshots: list[dict[str, Any]], verdict: dict[str, Any]) -> str:
    """Render summary.md content for human readers."""
    lines: list[str] = []
    lines.append(f"# Soak verdict — **{verdict['verdict']}**")
    lines.append("")
    lines.append(f"- Snapshots: {verdict['snapshots']}")
    lines.append(
        f"- RSS: baseline {verdict['baseline_rss_mb']} MB → final "
        f"{verdict['final_rss_mb']} MB  "
        f"(growth {verdict['rss_growth_pct']:.1f}% / threshold "
        f"{verdict['rss_growth_threshold_pct']}%)"
    )
    lines.append(
        f"- Open files: baseline {verdict['baseline_fd']} → final "
        f"{verdict['final_fd']}  (Δ {verdict['fd_delta']} / threshold "
        f"{verdict['fd_leak_threshold']})"
    )
    lines.append(
        f"- audit_log rows: {verdict['baseline_audit_count']} → "
        f"{verdict['final_audit_count']}  (Δ {verdict['audit_delta']})"
    )
    lines.append(f"- Final /healthz: {verdict['final_healthz']}")
    lines.append("")
    if verdict["failures"]:
        lines.append("## Failures")
        for f in verdict["failures"]:
            lines.append(f"- {f}")
        lines.append("")

    # ASCII RSS chart — last 60 points max, normalised to 40 cols.
    pts = [s.get("rss_total_mb") or 0 for s in snapshots[-60:]]
    if pts:
        peak = max(pts) or 1
        lines.append("## RSS over time (MB)")
        lines.append("```")
        for v in pts:
            n_filled = round(v / peak * 40)
            lines.append(f"{v:6.1f} MB │{'█' * n_filled}")
        lines.append("```")
    return "\n".join(lines) + "\n"


def finalize(out_dir: Path) -> int:
    """Compute verdict and write summary.md + summary.json. Returns exit code."""
    rec = MetricsRecorder(out_dir)
    snaps = rec.load_all()
    verdict = evaluate(snaps)
    rec.summary_md.write_text(render_summary(snaps, verdict), encoding="utf-8")
    rec.summary_json.write_text(json.dumps(verdict, indent=2), encoding="utf-8")
    print(f"\n=== Soak verdict: {verdict['verdict']} ===")
    print(f"  RSS growth: {verdict['rss_growth_pct']:.1f}%")
    print(f"  FD delta:   {verdict['fd_delta']}")
    print(f"  audit Δ:    {verdict['audit_delta']}")
    print(f"  summary:    {rec.summary_md}")
    return 0 if verdict["verdict"] == "PASS" else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    p = argparse.ArgumentParser(description="Soak-loop metrics collector + verdict")
    sub = p.add_subparsers(dest="cmd", required=True)
    p_snap = sub.add_parser("snapshot", help="Take one snapshot and print as JSON")
    p_snap.add_argument("--out-dir", type=Path, default=None,
                        help="If set, append to metrics.{csv,jsonl} in this dir")
    p_fin = sub.add_parser("finalize", help="Compute verdict + write summary")
    p_fin.add_argument("out_dir", type=Path)
    args = p.parse_args()

    if args.cmd == "snapshot":
        snap = snapshot()
        if args.out_dir:
            MetricsRecorder(args.out_dir).record(snap)
        print(json.dumps(snap, indent=2))
        return 0
    if args.cmd == "finalize":
        return finalize(args.out_dir)
    return 2


if __name__ == "__main__":
    sys.exit(main())
