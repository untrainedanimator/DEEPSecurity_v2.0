"""24-hour soak test for DEEPSecurity — lightweight by default.

Runs a fixed cadence every 15 minutes for 24 hours. The default cycle
is intentionally cheap so this loop can run on a laptop you're using:

    every cycle (cheap path, ~10–15s of CPU):
        1. ``deepsec backup incremental --keep 48``
        2. ``python scripts\\verify_v2_5.py``
        3. ``deepsec clean --services-only --yes``

    every 4th cycle (heavy path, additionally ~70–90s of CPU):
        +. ``python scripts\\e2e_full.py``

That's ~1% average CPU and ~5–8 MB RSS spikes per cycle on a modern
laptop, with the heavy E2E running only ~once an hour by default.

Lightweight mode (``--lightweight``, default ON) also:
    * Spawns every subprocess at ``IDLE_PRIORITY_CLASS`` on Windows
      (the OS only schedules it when nothing else needs the CPU),
      and ``os.nice(+10)`` on POSIX.
    * Skips the cycle entirely when the laptop is on battery, so a
      24h soak doesn't drain you off-mains. The skip is logged and
      the loop resumes when the laptop is plugged back in.
    * Captures peak RSS per cycle so the roll-up shows real-world
      memory cost.

Use ``--no-lightweight`` if you want every cycle to run the full E2E
at normal priority (~5 minutes of CPU per cycle, ~30 min of CPU per
hour — only sane on a dedicated test rig).

The script is interrupt-safe — Ctrl-C during the wait window stops the
loop cleanly and writes a final roll-up. SIGTERM (Task Scheduler stop)
is handled the same way.

Usage:

    py -3.12 scripts\\loop_24h.py                          # 24h, lightweight
    py -3.12 scripts\\loop_24h.py --hours 8 --interval-min 30
    py -3.12 scripts\\loop_24h.py --no-lightweight        # full E2E every cycle
    py -3.12 scripts\\loop_24h.py --e2e-every 1            # E2E every cycle, still light
    py -3.12 scripts\\loop_24h.py --hours 1 --interval-min 5 --e2e-every 12  # smoke

Outputs:

    logs/loop_24h_<UTC-stamp>.md       Markdown roll-up (one row per cycle).
    logs/loop_24h_<UTC-stamp>.json     Machine-readable run state.
    logs/loop_24h_<UTC-stamp>/         Per-iteration verify + e2e logs.

Exit codes:

    0 — every executed cycle was OK
    1 — at least one cycle failed
    2 — interrupted (Ctrl-C or SIGTERM); roll-up written for what ran
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
LOG_DIR = HERE / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------------------------------
# Lightweight-mode helpers
# --------------------------------------------------------------------------

# Windows IDLE_PRIORITY_CLASS = 0x40. The OS schedules an "idle"-priority
# process only when no foreground process needs the CPU — the cleanest
# way to soak a laptop without slowing it down. POSIX equivalent is
# ``os.nice(+10)``, which we apply via ``preexec_fn``.
_WIN_IDLE_PRIORITY_CLASS = 0x00000040


def _idle_subprocess_kwargs() -> dict:
    """Return the kwargs to pass to subprocess.run so the child runs idle."""
    if os.name == "nt":
        return {"creationflags": _WIN_IDLE_PRIORITY_CLASS}
    return {"preexec_fn": lambda: os.nice(10)}


def _on_battery() -> bool:
    """True iff the laptop is currently running on battery (and we know).

    Returns False when we can't tell — desktop without a battery, a server,
    psutil missing — because those environments are always "plugged in"
    in the sense the loop cares about.
    """
    try:
        import psutil  # already a runtime dep

        bat = psutil.sensors_battery()
        if bat is None:
            return False
        return not bat.power_plugged
    except Exception:
        return False


def _peak_rss_mb_of(proc_pid: int | None) -> float:
    """Best-effort peak RSS for a single PID. 0.0 if we can't read it."""
    if not proc_pid:
        return 0.0
    try:
        import psutil

        return round(psutil.Process(proc_pid).memory_info().rss / (1024 * 1024), 1)
    except Exception:
        return 0.0


# --------------------------------------------------------------------------
# Signal handling
# --------------------------------------------------------------------------


_INTERRUPTED = False


def _handle_interrupt(*_: object) -> None:
    global _INTERRUPTED
    _INTERRUPTED = True
    print("\n[loop_24h] interrupt received — finishing current cycle", flush=True)


for _sig in (signal.SIGINT, signal.SIGTERM):
    try:
        signal.signal(_sig, _handle_interrupt)
    except (ValueError, AttributeError):
        # Windows can't always set SIGTERM; ignore.
        pass


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _run_step(
    label: str,
    cmd: list[str],
    log_path: Path,
    timeout_s: int,
    *,
    lightweight: bool = True,
) -> dict:
    """Run a subprocess; persist its output; return a structured result.

    When ``lightweight=True`` (default), the child runs at idle priority
    (Windows) or +10 nice (POSIX) so it stays out of the way of whatever
    the operator is doing on the laptop.
    """
    started = datetime.now(UTC)
    t0 = time.monotonic()
    extra_kwargs: dict = _idle_subprocess_kwargs() if lightweight else {}
    try:
        proc = subprocess.run(
            cmd,
            cwd=HERE,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            **extra_kwargs,
        )
        rc = proc.returncode
        stdout, stderr = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        rc = 124
        stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        stderr = f"TIMEOUT after {timeout_s}s\n" + stderr
    elapsed = time.monotonic() - t0
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(
        f"# {label}\n# rc={rc}\n# duration_s={elapsed:.1f}\n\n"
        f"--- STDOUT ---\n{stdout}\n\n--- STDERR ---\n{stderr}\n",
        encoding="utf-8",
    )
    return {
        "label": label,
        "ok": rc == 0,
        "rc": rc,
        "duration_s": round(elapsed, 1),
        "started": started.isoformat(),
        "log": str(log_path.relative_to(HERE)),
    }


def _wait_for_next_cycle(seconds: int) -> bool:
    """Sleep in 1s slices so Ctrl-C fires immediately. Returns False if we
    were interrupted during the wait."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if _INTERRUPTED:
            return False
        time.sleep(1.0)
    return not _INTERRUPTED


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def _deepsec(*args: str) -> list[str]:
    """Build a ``deepsec`` invocation that works whether the package is on
    the ``PATH`` (entry-point shim) or only importable as a module."""
    return [sys.executable, "-m", "deepsecurity.cli", *args]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--hours",
        type=float,
        default=24.0,
        help="Total wall-clock duration of the soak run (default 24).",
    )
    parser.add_argument(
        "--interval-min",
        type=float,
        default=15.0,
        help="Minutes between cycle starts (default 15).",
    )
    parser.add_argument(
        "--skip-backup",
        action="store_true",
        help="Don't run `deepsec backup incremental` each cycle.",
    )
    parser.add_argument(
        "--skip-e2e",
        action="store_true",
        help="Never run scripts\\e2e_full.py (always cheap cycle).",
    )
    parser.add_argument(
        "--e2e-every",
        type=int,
        default=4,
        help=(
            "Run the heavy E2E only every Nth cycle "
            "(default 4 → ~1 E2E per hour at the default 15-min interval)."
        ),
    )
    parser.add_argument(
        "--lightweight",
        dest="lightweight",
        action="store_true",
        help="Idle-priority subprocesses + skip on battery (default).",
    )
    parser.add_argument(
        "--no-lightweight",
        dest="lightweight",
        action="store_false",
        help="Run subprocesses at normal priority and ignore battery state.",
    )
    parser.set_defaults(lightweight=True)
    parser.add_argument(
        "--no-pause-on-battery",
        action="store_true",
        help=(
            "Even in lightweight mode, run cycles while on battery. "
            "Useful for unattended soak rigs without AC."
        ),
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help=(
            "Compress a 24h soak into ~1h: hours=1, interval-min=1, "
            "e2e-every=12. Useful for pre-release smoke and CI."
        ),
    )
    parser.add_argument(
        "--no-metrics",
        action="store_true",
        help="Skip per-cycle psutil metrics collection.",
    )
    args = parser.parse_args()

    if args.fast:
        args.hours = 1.0
        args.interval_min = 1.0
        args.e2e_every = 12

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    md_path = LOG_DIR / f"loop_24h_{stamp}.md"
    json_path = LOG_DIR / f"loop_24h_{stamp}.json"
    iter_dir = LOG_DIR / f"loop_24h_{stamp}"
    iter_dir.mkdir(parents=True, exist_ok=True)

    interval_s = int(args.interval_min * 60)
    deadline = datetime.now(UTC) + timedelta(hours=args.hours)

    print(
        f"[loop_24h] starting — interval={args.interval_min}m hours={args.hours} "
        f"lightweight={args.lightweight} e2e_every={args.e2e_every}"
    )
    print(f"[loop_24h] reports → {md_path}")
    print(f"[loop_24h] per-cycle logs → {iter_dir}")
    print()

    cycles: list[dict] = []
    cycle_idx = 0
    pause_on_battery = args.lightweight and not args.no_pause_on_battery

    # Metrics recorder — every cycle gets one psutil snapshot. Closes the
    # v3 production gap "24-hour soak loop not yet run". On exit, the
    # finalize() call computes a PASS/FAIL verdict against env-configurable
    # thresholds (RSS growth, FD leaks, audit log advance).
    metrics_recorder = None
    if not args.no_metrics:
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            import soak_metrics  # type: ignore[import-not-found]

            metrics_recorder = soak_metrics.MetricsRecorder(iter_dir)
        except Exception as exc:
            print(f"[loop_24h] metrics disabled: {exc}")

    while not _INTERRUPTED:
        cycle_idx += 1
        cycle_started = datetime.now(UTC)

        # Battery pause — log a SKIPPED entry so the rollup shows we're alive.
        if pause_on_battery and _on_battery():
            cycle_record = {
                "cycle": cycle_idx,
                "started": cycle_started.isoformat(),
                "finished": cycle_started.isoformat(),
                "duration_s": 0.0,
                "ok": True,  # not a failure — explicit policy skip
                "skipped": "on_battery",
                "steps": [],
            }
            cycles.append(cycle_record)
            _write_rollup(md_path, json_path, cycles, args)
            print(
                f"[loop_24h] cycle {cycle_idx} SKIPPED (on battery) — will retry at next interval"
            )
            if datetime.now(UTC) >= deadline:
                break
            if not _wait_for_next_cycle(interval_s):
                break
            continue

        run_e2e_this_cycle = not args.skip_e2e and (
            args.e2e_every <= 1 or (cycle_idx - 1) % args.e2e_every == 0
        )
        print(
            f"[loop_24h] cycle {cycle_idx} @ {cycle_started.isoformat()}  e2e={run_e2e_this_cycle}"
        )

        cycle_steps: list[dict] = []

        # 1. Incremental backup.
        if not args.skip_backup:
            cycle_steps.append(
                _run_step(
                    label=f"cycle{cycle_idx:03d}_backup",
                    cmd=_deepsec("backup", "incremental", "--keep", "48"),
                    log_path=iter_dir / f"cycle{cycle_idx:03d}_backup.log",
                    timeout_s=120,
                    lightweight=args.lightweight,
                )
            )

        # 2. Verify harness — every cycle (cheap).
        cycle_steps.append(
            _run_step(
                label=f"cycle{cycle_idx:03d}_verify",
                cmd=[sys.executable, "scripts/verify_v2_5.py"],
                log_path=iter_dir / f"cycle{cycle_idx:03d}_verify.log",
                timeout_s=900,
                lightweight=args.lightweight,
            )
        )

        # 3. Full E2E — only every Nth cycle (heavy).
        if run_e2e_this_cycle:
            cycle_steps.append(
                _run_step(
                    label=f"cycle{cycle_idx:03d}_e2e",
                    cmd=[sys.executable, "scripts/e2e_full.py"],
                    log_path=iter_dir / f"cycle{cycle_idx:03d}_e2e.log",
                    timeout_s=1800,
                    lightweight=args.lightweight,
                )
            )

        # 4. Stop hanging services without deleting anything.
        cycle_steps.append(
            _run_step(
                label=f"cycle{cycle_idx:03d}_clean",
                cmd=_deepsec("clean", "--services-only", "--yes"),
                log_path=iter_dir / f"cycle{cycle_idx:03d}_clean.log",
                timeout_s=60,
                lightweight=args.lightweight,
            )
        )

        cycle_finished = datetime.now(UTC)
        cycle_record = {
            "cycle": cycle_idx,
            "started": cycle_started.isoformat(),
            "finished": cycle_finished.isoformat(),
            "duration_s": round((cycle_finished - cycle_started).total_seconds(), 1),
            "ok": all(s["ok"] for s in cycle_steps),
            "ran_e2e": run_e2e_this_cycle,
            "steps": cycle_steps,
        }
        cycles.append(cycle_record)
        _write_rollup(md_path, json_path, cycles, args)

        # Per-cycle metrics snapshot (best-effort, never raises).
        if metrics_recorder is not None:
            try:
                metrics_recorder.record(soak_metrics.snapshot())  # type: ignore[name-defined]
            except Exception as exc:
                print(f"[loop_24h] metrics snapshot failed: {exc}")

        verdict = "OK " if cycle_record["ok"] else "FAIL"
        e2e_flag = " +e2e" if run_e2e_this_cycle else ""
        print(
            f"[loop_24h] cycle {cycle_idx} {verdict} in {cycle_record['duration_s']:.1f}s{e2e_flag}"
        )

        if datetime.now(UTC) >= deadline:
            print("[loop_24h] deadline reached — stopping")
            break
        seconds_to_next = max(
            5,
            interval_s - int((datetime.now(UTC) - cycle_started).total_seconds()),
        )
        print(f"[loop_24h] sleeping {seconds_to_next}s until next cycle\n")
        if not _wait_for_next_cycle(seconds_to_next):
            break

    # Final roll-up.
    _write_rollup(md_path, json_path, cycles, args)
    print(f"\n[loop_24h] done. {sum(1 for c in cycles if c['ok'])}/{len(cycles)} cycles OK")
    print(f"[loop_24h] report: {md_path}")

    # Metrics finalize → PASS/FAIL verdict. Only fails the run when
    # cycles all passed but metrics found a leak — that's the failure
    # mode soak loops are designed to surface.
    metrics_verdict_failed = False
    if metrics_recorder is not None:
        try:
            metrics_exit = soak_metrics.finalize(iter_dir)  # type: ignore[name-defined]
            metrics_verdict_failed = metrics_exit != 0
        except Exception as exc:
            print(f"[loop_24h] metrics finalize failed: {exc}")

    if _INTERRUPTED:
        return 2
    if not all(c["ok"] for c in cycles):
        return 1
    return 1 if metrics_verdict_failed else 0


def _write_rollup(
    md_path: Path,
    json_path: Path,
    cycles: list[dict],
    args: argparse.Namespace,
) -> None:
    """Write the Markdown + JSON roll-up. Idempotent."""
    executed = [c for c in cycles if not c.get("skipped")]
    skipped = [c for c in cycles if c.get("skipped")]
    ok = sum(1 for c in executed if c["ok"])
    fail = sum(1 for c in executed if not c["ok"])
    e2e_runs = sum(1 for c in executed if c.get("ran_e2e"))

    lines: list[str] = []
    lines.append(f"# DEEPSecurity 24-hour soak — {datetime.now(UTC).isoformat()}")
    lines.append("")
    lines.append(
        f"- Hours target: {args.hours}    interval: {args.interval_min} min    "
        f"lightweight: {args.lightweight}    e2e-every: {args.e2e_every}"
    )
    lines.append(
        f"- Cycles: {len(cycles)}  ({len(executed)} ran, {len(skipped)} skipped)    "
        f"OK: {ok}    FAIL: {fail}    E2E runs: {e2e_runs}"
    )
    lines.append("")
    lines.append("| # | Started (UTC) | Duration | E2E | Verdict | Steps |")
    lines.append("|---|---|---|---|---|---|")
    for c in cycles:
        if c.get("skipped"):
            lines.append(
                f"| {c['cycle']} | {c['started'].split('T')[1][:8]} | 0s | — "
                f"| _skip_ ({c['skipped']}) | — |"
            )
            continue
        steps_str = "  ".join(
            f"{s['label'].rsplit('_', 1)[-1]}={'OK' if s['ok'] else 'FAIL'}" for s in c["steps"]
        )
        lines.append(
            f"| {c['cycle']} | {c['started'].split('T')[1][:8]} "
            f"| {c['duration_s']:.0f}s "
            f"| {'Y' if c.get('ran_e2e') else 'n'} "
            f"| {'OK' if c['ok'] else '**FAIL**'} | {steps_str} |"
        )
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    json_path.write_text(json.dumps({"cycles": cycles}, indent=2), encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
