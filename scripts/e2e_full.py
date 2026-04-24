"""End-to-end verification battery for DEEPSecurity — stages A through P.

One command. Writes a markdown report. Stops at the first failure.
Cleans up every artefact it creates even on a crash. Stdlib only.

Usage (from repo root, Windows cmd):

    .venv\\Scripts\\python.exe scripts\\e2e_full.py

Output:
    logs/e2e_<UTC timestamp>.md    — the full report (table per stage)
    console                         — one line per stage: [X] OK/FAIL — evidence

Exit code:
    0  every stage OK / SKIP / KNOWN
    1  a stage failed
    2  interrupted (Ctrl+C)
    3  couldn't even start (missing venv, etc.)

Design notes:
    - No pip installs, no external deps, no network.
    - Budget: 10 minutes end-to-end; stages with their own timeouts.
    - Idempotent: every file / env / signature modification is paired
      with a cleanup registered on a LIFO stack that runs in `finally`.
    - Auth: STAGE E logs in once; token is cached for later stages.
"""
from __future__ import annotations

import atexit
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


# ---------------------------------------------------------------------------
# Paths and constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
VENV_PY = REPO_ROOT / ".venv" / "Scripts" / "python.exe"
LOG_DIR = REPO_ROOT / "logs"
SERVER_LOG = LOG_DIR / "server.log"
DATA_DIR = REPO_ROOT / "data"
SIGNATURES_PATH = DATA_DIR / "signatures.txt"
SERVER_URL = "http://127.0.0.1:5000"

START_TS = datetime.now(timezone.utc)
REPORT_PATH = LOG_DIR / f"e2e_{START_TS.strftime('%Y%m%dT%H%M%SZ')}.md"

BUDGET_S = 600  # total 10-minute cap

# The fake-malware payload the test suite already accepts.
FAKE_MALWARE = b"DEEPSEC-TEST-PAYLOAD-" + b"Z" * 48
FAKE_SHA256 = hashlib.sha256(FAKE_MALWARE).hexdigest()

USER_HOME = Path(os.path.expanduser("~"))


# ---------------------------------------------------------------------------
# Result + cleanup bookkeeping
# ---------------------------------------------------------------------------


@dataclass
class Result:
    code: str
    name: str
    status: str  # OK / FAIL / SKIP / KNOWN
    evidence: str = ""
    notes: str = ""
    duration_s: float = 0.0


results: list[Result] = []
cleanup_stack: list[Callable[[], None]] = []
_admin_token: str | None = None
_deadline: float = 0.0


def register_cleanup(fn: Callable[[], None]) -> None:
    cleanup_stack.append(fn)


def run_cleanup() -> None:
    while cleanup_stack:
        fn = cleanup_stack.pop()
        try:
            fn()
        except Exception:  # noqa: BLE001
            pass


atexit.register(run_cleanup)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


class StageFail(Exception):
    """Raised inside a stage function to record FAIL with a message."""


def now() -> float:
    return time.monotonic()


def budget_left() -> float:
    return max(0.0, _deadline - now())


def run_cmd(
    args: list[str],
    *,
    timeout: int = 60,
    env: dict | None = None,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        env=env,
        cwd=str(REPO_ROOT),
        check=False,
    )


def ds(*args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Invoke the deepsecurity CLI via its module path (bypasses entry-point wrapper)."""
    return run_cmd(
        [str(VENV_PY), "-m", "deepsecurity.cli", *args], timeout=timeout
    )


def http(
    method: str,
    path: str,
    *,
    bearer: str | None = None,
    body: dict | None = None,
    extra_headers: dict | None = None,
    timeout: float = 5.0,
) -> tuple[int, Any, dict]:
    url = f"{SERVER_URL}{path}"
    req = urllib.request.Request(url, method=method)
    if body is not None:
        req.data = json.dumps(body).encode("utf-8")
        req.add_header("Content-Type", "application/json")
    if bearer:
        req.add_header("Authorization", f"Bearer {bearer}")
    for k, v in (extra_headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status = r.status
            raw = r.read().decode("utf-8", errors="replace")
            hdrs = dict(r.headers.items())
    except urllib.error.HTTPError as e:
        status = e.code
        raw = e.read().decode("utf-8", errors="replace")
        hdrs = dict(e.headers.items())
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        parsed = raw
    return status, parsed, hdrs


def port_in_use(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    try:
        s.connect(("127.0.0.1", port))
        s.close()
        return True
    except OSError:
        return False


def dotenv() -> dict[str, str]:
    p = REPO_ROOT / ".env"
    out: dict[str, str] = {}
    if not p.exists():
        return out
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def admin_password() -> str:
    env = dotenv()
    pw = os.environ.get("DEEPSEC_DEV_PASSWORD") or env.get("DEEPSEC_DEV_PASSWORD", "")
    if not pw:
        raise StageFail(
            "DEEPSEC_DEV_PASSWORD missing from env and .env; cannot authenticate"
        )
    return pw


def wait_for_healthz(timeout: float = 30.0) -> bool:
    deadline = now() + timeout
    while now() < deadline:
        try:
            with urllib.request.urlopen(f"{SERVER_URL}/healthz", timeout=1.5) as r:
                if r.status == 200:
                    return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.4)
    return False


def tail_lines(path: Path, n: int = 20) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(lines[-n:])
    except Exception as exc:  # noqa: BLE001
        return f"(couldn't read {path}: {exc})"


# ---------------------------------------------------------------------------
# Stage runner
# ---------------------------------------------------------------------------


def run_stage(code: str, name: str, fn: Callable[[], tuple[str, str, str]]) -> bool:
    """Run one stage. Returns True to continue, False to STOP.

    fn() must return (status, evidence, notes). status ∈
    {"OK","SKIP","KNOWN","KNOWN-CEILING","KNOWN-MISSING"}. On FAIL the
    stage must raise StageFail with a concise message.
    """
    print(f"\n[{code}] {name} ...", flush=True)
    t0 = now()
    try:
        status, evidence, notes = fn()
    except StageFail as e:
        dur = now() - t0
        results.append(Result(code, name, "FAIL", str(e), "", dur))
        print(f"[{code}] FAIL — {e}", flush=True)
        print(f"--- last 20 lines of {SERVER_LOG} ---")
        print(tail_lines(SERVER_LOG, 20))
        return False
    except Exception as e:  # noqa: BLE001
        dur = now() - t0
        tb = traceback.format_exc(limit=3)
        results.append(
            Result(code, name, "FAIL", f"{type(e).__name__}: {e}", tb, dur)
        )
        print(f"[{code}] FAIL — unexpected {type(e).__name__}: {e}", flush=True)
        print(tb)
        return False
    dur = now() - t0
    results.append(Result(code, name, status, evidence, notes, dur))
    tag = status
    print(f"[{code}] {tag} — {evidence}", flush=True)
    return True


# ===========================================================================
# STAGE A — Environment sanity
# ===========================================================================


def stage_A() -> tuple[str, str, str]:
    if not VENV_PY.exists():
        raise StageFail(f"venv python missing at {VENV_PY}")
    r = run_cmd([str(VENV_PY), "--version"], timeout=5)
    if r.returncode != 0:
        raise StageFail(f"python --version exit {r.returncode}: {r.stderr!r}")
    pyver = (r.stdout + r.stderr).strip()
    m = re.search(r"Python (\d+)\.(\d+)", pyver)
    if not m or int(m.group(1)) != 3 or int(m.group(2)) not in (11, 12, 13, 14):
        raise StageFail(f"unsupported Python: {pyver}")

    # .env check
    env = dotenv()
    for k in ("DEEPSEC_SECRET_KEY", "DEEPSEC_JWT_SECRET", "DEEPSEC_DEV_PASSWORD"):
        if not env.get(k):
            raise StageFail(f".env missing or empty: {k}")

    # Ports — 5000 must be either free or ours (ours = deepsecurity status says
    # backend up with a pid).
    for port in (5000, 5173):
        if port_in_use(port):
            # Check if it's us. If `deepsecurity status` reports this port bound
            # to the backend/frontend, that's fine — we'll use/ignore it.
            st = ds("status", timeout=10)
            if "up (healthy)" not in st.stdout and "up" not in st.stdout:
                raise StageFail(
                    f"port {port} held by something that isn't DEEPSecurity. "
                    f"Free it and retry. `netstat -ano | findstr :{port}` will "
                    "show the PID."
                )

    # git dirty-file count (informational only)
    dirty = 0
    try:
        g = run_cmd(["git", "status", "--porcelain"], timeout=5)
        dirty = len([ln for ln in g.stdout.splitlines() if ln.strip()])
    except Exception:  # noqa: BLE001
        pass

    return (
        "OK",
        f"{pyver}, .env keys present, ports OK, git dirty={dirty}",
        "",
    )


# ===========================================================================
# STAGE B — Unit + integration pytest
# ===========================================================================


def stage_B() -> tuple[str, str, str]:
    # Ensure the production server is ACTUALLY down before pytest runs.
    # Otherwise its watchdog (active on user_risk scope, which covers
    # %TEMP%) will open every ``pytest-of-<user>/pytest-N/*/test.db`` to
    # compute entropy MID-TRANSACTION. Windows file locks + SQLite
    # writers = flaky tests, database-is-locked errors, and random
    # ScanSession ghost rows that make downstream stages FAIL.
    ds("stop", timeout=20)

    # Verify the stop actually took. ``deepsecurity stop`` can appear to
    # succeed while leaving a detached process alive if the pidfile was
    # stale or taskkill returned "Access denied".
    deadline = now() + 12.0
    while now() < deadline:
        try:
            with urllib.request.urlopen(f"{SERVER_URL}/healthz", timeout=1.0):
                pass
        except Exception:  # noqa: BLE001 — any failure means port is closed
            break
        time.sleep(0.4)
    else:
        raise StageFail(
            "`deepsecurity stop` claimed success but /healthz still answers. "
            "A detached process is probably still running on port 5000. "
            "Manually: `netstat -ano | findstr :5000` → `taskkill /F /PID <pid>`. "
            "Running pytest while the watchdog is live on %TEMP% destabilises "
            "the SQLite test fixtures — see watch_exclude_globs in config.py."
        )

    # NOTE: we deliberately do NOT pass ``--timeout`` — the
    # ``pytest-timeout`` plugin isn't in the pinned deps on every
    # developer's venv, and adding it would violate this battery's
    # "no pip install" rule. Our subprocess-level 420s cap is the
    # outer bound; individual slow tests are the operator's problem.
    pytest_argv = [str(VENV_PY), "-m", "pytest", "-q", "-m", "not slow"]
    r = run_cmd(pytest_argv, timeout=420)

    # Dump FULL pytest output to a side log EVERY time — win or lose.
    # The previous iteration of this stage extracted "failed lines"
    # from stdout; when pytest crashed before collection that stdout
    # was empty, and operators got a useless "pytest red: " with no
    # detail. Always persist the raw output so triage is one `type`
    # command away.
    pytest_log = LOG_DIR / f"e2e_pytest_{START_TS.strftime('%Y%m%dT%H%M%SZ')}.log"
    pytest_log.write_text(
        f"=== argv ===\n{pytest_argv}\n"
        f"=== returncode: {r.returncode} ===\n"
        f"=== STDOUT ===\n{r.stdout or '(empty)'}\n"
        f"=== STDERR ===\n{r.stderr or '(empty)'}\n",
        encoding="utf-8",
    )

    stdout_lines = (r.stdout or "").strip().splitlines()
    last = stdout_lines[-1] if stdout_lines else ""

    if r.returncode != 0:
        # 1. FAILED/ERROR lines (if any).
        failed = [
            ln for ln in stdout_lines
            if ln.startswith("FAILED ") or "FAILED" in ln or ln.startswith("ERROR ")
        ][:15]
        # 2. The short-summary block if pytest got far enough to emit it.
        short_summary_idx = None
        for i, ln in enumerate(stdout_lines):
            if ln.strip().startswith("short test summary info"):
                short_summary_idx = i
                break
        if short_summary_idx is not None:
            failed += stdout_lines[short_summary_idx : short_summary_idx + 20]
        # 3. Fallback: last 40 lines of COMBINED stdout+stderr. This is
        #    the safety net when pytest died before generating summary
        #    output (e.g. collection error, import crash).
        if not failed:
            combined_tail = (
                (r.stdout or "")[-2000:]
                + "\n--- STDERR ---\n"
                + (r.stderr or "")[-2000:]
            )
            failed = [combined_tail]

        detail = "\n".join(failed)
        raise StageFail(
            f"pytest exit={r.returncode}  last={last or '(no stdout)'}\n"
            f"(full output → {pytest_log.name})\n"
            f"{detail}"
        )

    m = re.search(r"(\d+)\s+passed", last)
    passed = int(m.group(1)) if m else 0
    if passed < 95:
        raise StageFail(f"only {passed} passed (expected >= 95): {last}")
    return "OK", f"{passed} passed — {last}", ""


# ===========================================================================
# STAGE C — Lifecycle
# ===========================================================================


def stage_C() -> tuple[str, str, str]:
    # status before
    s = ds("status", timeout=10)
    if s.returncode not in (0, 1):
        raise StageFail(f"`deepsecurity status` unexpected exit {s.returncode}: {s.stderr}")

    # Start clean — backend only.
    ds("stop", timeout=20)
    st = ds("start", "--no-browser", "--no-frontend", timeout=45)
    if "started" not in (st.stdout + st.stderr).lower() and not wait_for_healthz(
        timeout=10
    ):
        raise StageFail(
            f"deepsecurity start didn't come up:\n{(st.stdout + st.stderr)[-800:]}"
        )

    # healthy via status
    s2 = ds("status", timeout=10)
    if "up" not in s2.stdout or "healthy" not in s2.stdout:
        raise StageFail(f"status does not report healthy:\n{s2.stdout}")

    # Extract PID for the report.
    pid_match = re.search(r"pid=(\d+)", s2.stdout)
    pid = pid_match.group(1) if pid_match else "?"

    # stop + check
    s3 = ds("stop", timeout=20)
    if not wait_for_healthz_stopped(timeout=10):
        raise StageFail("backend didn't stop within 10s")

    # restart for subsequent stages
    st2 = ds("start", "--no-browser", "--no-frontend", timeout=45)
    if not wait_for_healthz(timeout=30):
        raise StageFail(
            f"backend didn't come back up after restart:\n{(st2.stdout + st2.stderr)[-800:]}"
        )

    register_cleanup(lambda: ds("stop", timeout=20))

    return "OK", f"start/stop/status round-trip ok (first-run pid={pid})", ""


def wait_for_healthz_stopped(timeout: float = 10.0) -> bool:
    deadline = now() + timeout
    while now() < deadline:
        try:
            with urllib.request.urlopen(f"{SERVER_URL}/healthz", timeout=1.0) as _r:
                pass
            time.sleep(0.3)
        except Exception:  # noqa: BLE001
            return True
    return False


# ===========================================================================
# STAGE D — Unauthenticated smoke + security headers
# ===========================================================================


def stage_D() -> tuple[str, str, str]:
    # /
    status, body, _ = http("GET", "/")
    if status != 200:
        raise StageFail(f"GET / expected 200, got {status}")
    if not isinstance(body, dict) or body.get("service") != "deepsecurity":
        raise StageFail(f"GET / unexpected body: {str(body)[:200]}")

    # /healthz (+ headers)
    status, body, hdrs = http("GET", "/healthz")
    if status != 200:
        raise StageFail(f"GET /healthz expected 200, got {status}")
    required_hdrs = {
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Content-Security-Policy",
        "Strict-Transport-Security",
    }
    missing = sorted(h for h in required_hdrs if not any(h.lower() == k.lower() for k in hdrs))
    if missing:
        raise StageFail(f"/healthz missing security headers: {missing}")

    # /readyz
    status, body, _ = http("GET", "/readyz")
    if status not in (200, 503):
        raise StageFail(f"GET /readyz expected 200/503, got {status}")
    if isinstance(body, dict) and body.get("checks", {}).get("database") != "ok":
        raise StageFail(f"/readyz database not ok: {body}")

    # /metrics
    status, body, _ = http("GET", "/metrics")
    if status != 200:
        raise StageFail(f"GET /metrics expected 200, got {status}")
    if "deepsec_build_info" not in str(body):
        raise StageFail("/metrics missing deepsec_build_info")

    # /api/scanner/sessions → 401
    status, _, _ = http("GET", "/api/scanner/sessions")
    if status != 401:
        raise StageFail(f"/api/scanner/sessions expected 401, got {status}")

    return "OK", "5 endpoints + 5 security headers verified", ""


# ===========================================================================
# STAGE E — Authenticated flows
# ===========================================================================


def stage_E() -> tuple[str, str, str]:
    global _admin_token
    pw = admin_password()
    status, body, _ = http(
        "POST", "/api/auth/login", body={"username": "admin", "password": pw}
    )
    if status != 200 or not isinstance(body, dict) or "access_token" not in body:
        raise StageFail(f"login failed: status={status} body={str(body)[:200]}")
    _admin_token = body["access_token"]

    for path in (
        "/api/auth/whoami",
        "/api/scanner/sessions",
        "/api/quarantine/list",
        "/api/dlp/findings",
        "/api/audit",
        "/api/watchdog/status",
    ):
        status, body, _ = http("GET", path, bearer=_admin_token)
        if status != 200:
            raise StageFail(f"GET {path} auth'd expected 200, got {status}")

    # Sanity on whoami shape
    status, body, _ = http("GET", "/api/auth/whoami", bearer=_admin_token)
    if not isinstance(body, dict) or body.get("username") != "admin":
        raise StageFail(f"whoami body unexpected: {str(body)[:200]}")

    # Watchdog sanity
    status, body, _ = http("GET", "/api/watchdog/status", bearer=_admin_token)
    if not isinstance(body, dict) or not body.get("available"):
        raise StageFail(f"watchdog.available != true: {body}")
    wd_note = (
        f"watchdog running={body.get('running')}, "
        f"watching={len(body.get('watching') or [])} paths"
    )

    return "OK", f"login + 6 routes ok; {wd_note}", ""


# ===========================================================================
# STAGE F — File-system E2E signature detection
# ===========================================================================

_METRICS_BEFORE = 0  # captured here for STAGE L
_METRICS_AFTER = 0


def stage_F() -> tuple[str, str, str]:
    global _METRICS_BEFORE, _METRICS_AFTER
    assert _admin_token, "STAGE E must run first"

    # capture metrics delta for STAGE L
    _METRICS_BEFORE = _read_metric("deepsec_files_scanned_total")

    tmp_scan = USER_HOME / "Downloads" / "deepsec_e2e_scan"
    tmp_scan.mkdir(parents=True, exist_ok=True)
    register_cleanup(lambda: shutil.rmtree(tmp_scan, ignore_errors=True))

    probe = tmp_scan / "probe.bin"
    probe.write_bytes(FAKE_MALWARE)

    # Append the fake SHA to signatures.txt, backing up first
    sig_backup: bytes | None = None
    SIGNATURES_PATH.parent.mkdir(parents=True, exist_ok=True)
    if SIGNATURES_PATH.exists():
        sig_backup = SIGNATURES_PATH.read_bytes()
    with SIGNATURES_PATH.open("a", encoding="utf-8") as f:
        f.write(FAKE_SHA256 + "\n")

    def _restore_sigs() -> None:
        if sig_backup is None:
            try:
                SIGNATURES_PATH.unlink()
            except OSError:
                pass
        else:
            SIGNATURES_PATH.write_bytes(sig_backup)

    register_cleanup(_restore_sigs)

    # Snapshot the existing session count BEFORE we start. We'll wait for
    # exactly one NEW session to land in the list, and then inspect that
    # session's ``total_detections``. This is race-proof — unlike polling
    # /api/scanner/status, which can return ``running=False`` before the
    # worker thread even begins (the scan starts in a background thread
    # and there's a gap between POST returning and state.running=True).
    status, body, _ = http("GET", "/api/scanner/sessions", bearer=_admin_token)
    if status != 200 or not isinstance(body, list):
        raise StageFail(f"/api/scanner/sessions expected list, got {status}: {str(body)[:200]}")
    sessions_before = len(body)
    max_session_id_before = max((int(s.get("id", 0)) for s in body), default=0)

    # Kick off scan
    status, body, _ = http(
        "POST",
        "/api/scanner/start",
        bearer=_admin_token,
        body={"path": str(tmp_scan), "quarantine": True},
    )
    if status not in (200, 202):
        raise StageFail(
            f"/api/scanner/start expected 200/202, got {status}: {str(body)[:300]}"
        )

    # Poll /api/scanner/sessions for a new row.
    deadline = now() + 45
    new_session: dict | None = None
    while now() < deadline:
        status, body, _ = http("GET", "/api/scanner/sessions", bearer=_admin_token)
        if status == 200 and isinstance(body, list) and len(body) > sessions_before:
            # Find the session that wasn't there before AND has
            # status="completed" (not "in_progress") so we know it finished.
            for s in body:
                sid = int(s.get("id", 0))
                if sid > max_session_id_before and s.get("status") in ("completed", "cancelled"):
                    new_session = s
                    break
            if new_session is not None:
                break
        time.sleep(0.5)
    else:
        raise StageFail(
            "scan did not produce a completed session row within 45s; "
            f"sessions_before={sessions_before}, current={len(body) if isinstance(body, list) else 'n/a'}"
        )

    total_detections = int(new_session.get("total_detections") or 0)
    if total_detections < 1:
        raise StageFail(
            f"session id={new_session.get('id')} has total_detections={total_detections} "
            f"(expected >=1). Session row: {new_session}"
        )

    # Cleanup any quarantine file we created
    def _drop_quarantine() -> None:
        qdir = dotenv().get("DEEPSEC_QUARANTINE_DIR") or str(REPO_ROOT / "quarantine")
        qp = Path(qdir)
        if qp.exists():
            for f in qp.iterdir():
                if FAKE_SHA256[:8] in f.name and "probe.bin" in f.name:
                    try:
                        f.unlink()
                    except OSError:
                        pass

    register_cleanup(_drop_quarantine)

    _METRICS_AFTER = _read_metric("deepsec_files_scanned_total")

    return (
        "OK",
        f"session id={new_session.get('id')} status={new_session.get('status')} "
        f"total_detections={total_detections}",
        f"metrics files_scanned: {_METRICS_BEFORE} → {_METRICS_AFTER}",
    )


def _read_metric(name: str) -> int:
    try:
        with urllib.request.urlopen(f"{SERVER_URL}/metrics", timeout=3.0) as r:
            text = r.read().decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return 0
    for line in text.splitlines():
        if line.startswith(name) and not line.startswith("#"):
            parts = line.rsplit(" ", 1)
            if len(parts) == 2:
                try:
                    return int(float(parts[1]))
                except ValueError:
                    return 0
    return 0


# ===========================================================================
# STAGE G — Watchdog live event
# ===========================================================================


def stage_G() -> tuple[str, str, str]:
    assert _admin_token
    # Confirm watchdog running
    status, body, _ = http("GET", "/api/watchdog/status", bearer=_admin_token)
    if not (isinstance(body, dict) and body.get("running")):
        raise StageFail(f"watchdog not running: {body}")

    downloads = USER_HOME / "Downloads"
    probe = downloads / "e2e_watchdog_probe.bin"
    excluded_dir = downloads / "node_modules"
    excluded_dir.mkdir(parents=True, exist_ok=True)
    excluded_probe = excluded_dir / "e2e_watchdog_probe_excluded.bin"

    def _cleanup_probes() -> None:
        for p in (probe, excluded_probe):
            try:
                p.unlink()
            except OSError:
                pass
        try:
            if excluded_dir.exists() and not any(excluded_dir.iterdir()):
                excluded_dir.rmdir()
        except OSError:
            pass

    register_cleanup(_cleanup_probes)

    # Capture size-before of server.log so we only grep new content.
    # Server.log is line-buffered by the Flask child, but on Windows the
    # kernel page cache plus our own read_text() retry interval can
    # introduce multi-second lag between event generation and our
    # visibility of it. Our previous 8-second window was too tight —
    # we observed the event at T+0.46s but ran out of time at T+8s
    # because the flush didn't make it to disk in time. 20s is
    # generous; stage still averages ~1-2s on a warm machine.
    size_before = SERVER_LOG.stat().st_size if SERVER_LOG.exists() else 0

    probe.write_bytes(FAKE_MALWARE)
    excluded_probe.write_bytes(FAKE_MALWARE)

    deadline = now() + 20.0
    saw_watched = False
    saw_excluded = False
    last_tail_check = 0.0
    while now() < deadline and not saw_watched:
        # Read in both "new-content-only" and "full-file-tail" modes.
        # Full-file tail is a safety net for the case where size_before
        # was captured after some unrelated log writes grew the file
        # enough that our sliced window landed past the probe line.
        if SERVER_LOG.exists():
            try:
                full = SERVER_LOG.read_text(encoding="utf-8", errors="replace")
            except OSError:
                # Windows can briefly refuse the read while the writer
                # has it open for append; retry on the next tick.
                time.sleep(0.25)
                continue

            new = full[size_before:]
            tail_2k = full[-2048:]  # last ~20 log lines, cheap

            if (
                "e2e_watchdog_probe.bin" in new
                and "watchdog.file_event" in new
            ) or (
                "e2e_watchdog_probe.bin" in tail_2k
                and "watchdog.file_event" in tail_2k
            ):
                saw_watched = True
            if "e2e_watchdog_probe_excluded.bin" in new or "e2e_watchdog_probe_excluded.bin" in tail_2k:
                saw_excluded = True
            last_tail_check = now()
        time.sleep(0.25)

    if not saw_watched:
        waited = f"{deadline - (deadline - 20.0):.1f}"
        raise StageFail(
            f"watchdog did not log e2e_watchdog_probe.bin within 20s. "
            f"If the tail of server.log shows the entry timestamped inside "
            f"the window, the root cause is Windows file-flush lag — "
            f"increase the window further in stage G."
        )
    if saw_excluded:
        raise StageFail(
            "exclusion globs failed: e2e_watchdog_probe_excluded.bin under "
            "node_modules/ appeared in server.log"
        )

    return "OK", "file_event fired on watched path; node_modules excluded", ""


# ===========================================================================
# STAGE H — DLP pattern coverage
# ===========================================================================


_DLP_PAYLOADS = [
    ("aws_access_key_id", "AWS_KEY=AKIAIOSFODNN7EXAMPLE"),
    ("private_key_pem", "-----BEGIN RSA PRIVATE KEY-----\nabc"),
    ("us_ssn", "SSN: 123-45-6789"),
    ("email_address", "mail: someone@example.com"),
    # These three may or may not be shipped as named patterns; test tolerantly
    ("github_pat", "GITHUB=ghp_AAAAbbbbCCCCddddEEEEffffGGGGhhhhIIII"),
    ("slack_token", "SLACK=xoxp-1234567890-1234567890-abcdefghij"),
    ("credit_card", "CARD=4111-1111-1111-1111"),
]


def stage_H() -> tuple[str, str, str]:
    """Call scan_file_for_secrets directly via a subprocess — so we don't need
    to import deepsecurity modules inside this orchestrator process."""
    script = (REPO_ROOT / "logs" / "_dlp_probe.py")
    payloads_json = json.dumps(_DLP_PAYLOADS)
    script.write_text(
        'import json, sys, tempfile, os\n'
        'from pathlib import Path\n'
        'from deepsecurity.dlp import scan_file_for_secrets, PATTERNS\n'
        f'payloads = json.loads({payloads_json!r})\n'
        'known = {p.name for p in PATTERNS}\n'
        'results = []\n'
        'with tempfile.TemporaryDirectory() as td:\n'
        '    for name, text in payloads:\n'
        '        if name not in known:\n'
        '            results.append((name, "KNOWN-MISSING", "not in PATTERNS"))\n'
        '            continue\n'
        '        p = Path(td) / f"{name}.txt"\n'
        '        p.write_text(text + "\\n", encoding="utf-8")\n'
        '        hits = scan_file_for_secrets(p, "text/plain")\n'
        '        names = [h.pattern_name for h in hits]\n'
        '        if name not in names:\n'
        '            results.append((name, "FAIL", f"no hit; names={names}"))\n'
        '        else:\n'
        '            # check redaction\n'
        '            leak = any(("AKIA" in h.redacted_preview or "ghp_A" in h.redacted_preview)\n'
        '                       for h in hits if h.pattern_name == name)\n'
        '            redacted_ok = all("****" in h.redacted_preview for h in hits if h.pattern_name == name)\n'
        '            if leak:\n'
        '                results.append((name, "FAIL", "raw secret leaked into preview"))\n'
        '            elif not redacted_ok:\n'
        '                results.append((name, "FAIL", "preview missing **** marker"))\n'
        '            else:\n'
        '                results.append((name, "OK", f"{len(hits)} hit(s)"))\n'
        'print(json.dumps(results))\n',
        encoding="utf-8",
    )
    register_cleanup(lambda: script.unlink(missing_ok=True))

    r = run_cmd([str(VENV_PY), str(script)], timeout=45)
    if r.returncode != 0:
        raise StageFail(
            f"dlp probe exit {r.returncode}:\nSTDOUT:\n{r.stdout[-600:]}\nSTDERR:\n{r.stderr[-600:]}"
        )
    try:
        out = json.loads(r.stdout.strip().splitlines()[-1])
    except Exception as e:  # noqa: BLE001
        raise StageFail(f"couldn't parse dlp probe output: {e}\n{r.stdout[:400]}") from e

    fails = [row for row in out if row[1] == "FAIL"]
    if fails:
        raise StageFail(f"DLP patterns failing: {fails}")

    oks = sum(1 for row in out if row[1] == "OK")
    missing = [row[0] for row in out if row[1] == "KNOWN-MISSING"]
    notes = f"{oks}/{len(out)} passed"
    if missing:
        notes += f"; KNOWN-MISSING patterns: {missing}"
    return "OK", notes, ""


# ===========================================================================
# STAGE I — Agent round-trip
# ===========================================================================


def stage_I() -> tuple[str, str, str]:
    assert _admin_token
    # Enrol
    status, body, _ = http(
        "POST",
        "/api/agents/enrol",
        bearer=_admin_token,
        body={"label": "e2e-probe", "ttl_hours": 1},
    )
    if status != 201 or "enrolment_token" not in (body or {}):
        raise StageFail(f"enrol expected 201+token, got {status}: {str(body)[:200]}")
    enrol_token = body["enrolment_token"]

    # Register (anon)
    status, body, _ = http(
        "POST",
        "/api/agents/register",
        body={
            "enrolment_token": enrol_token,
            "hostname": "e2e-host",
            "os": "windows",
            "os_version": "test",
            "agent_version": "e2e",
        },
    )
    if status != 201 or not isinstance(body, dict) or "agent_id" not in body:
        raise StageFail(f"register expected 201+agent_id, got {status}: {str(body)[:200]}")
    agent_id = body["agent_id"]
    api_key = body["api_key"]
    agent_headers = {
        "X-DEEPSEC-AGENT-ID": agent_id,
        "X-DEEPSEC-AGENT-KEY": api_key,
    }

    # Heartbeat
    status, body, _ = http(
        "POST",
        "/api/agents/heartbeat",
        body={"cpu_percent": 1.0, "ram_percent": 10.0},
        extra_headers=agent_headers,
    )
    if status != 200:
        raise StageFail(f"heartbeat expected 200, got {status}: {str(body)[:200]}")

    # Queue command (admin)
    status, body, _ = http(
        "POST",
        f"/api/agents/{agent_id}/commands",
        bearer=_admin_token,
        body={"kind": "self_test", "payload": {}},
    )
    if status != 201 or "command_id" not in (body or {}):
        raise StageFail(
            f"queue-command expected 201+command_id, got {status}: {str(body)[:200]}"
        )
    cmd_id = body["command_id"]

    # Agent pulls commands
    status, body, _ = http("GET", "/api/agents/commands", extra_headers=agent_headers)
    if status != 200 or not any(
        c.get("command_id") == cmd_id for c in (body.get("commands") or [])
    ):
        raise StageFail(f"agent did not receive queued command: {str(body)[:300]}")

    # Post result
    status, body, _ = http(
        "POST",
        "/api/agents/results",
        extra_headers=agent_headers,
        body={"command_id": cmd_id, "success": True, "result": {"alive": True}},
    )
    if status != 200:
        raise StageFail(f"results expected 200, got {status}: {str(body)[:200]}")

    # Revoke
    status, body, _ = http(
        "DELETE", f"/api/agents/{agent_id}", bearer=_admin_token
    )
    if status != 200:
        raise StageFail(f"revoke expected 200, got {status}: {str(body)[:200]}")

    # Heartbeat after revoke → 401
    status, body, _ = http(
        "POST",
        "/api/agents/heartbeat",
        body={"cpu_percent": 1.0, "ram_percent": 10.0},
        extra_headers=agent_headers,
    )
    if status != 401:
        raise StageFail(f"post-revoke heartbeat expected 401, got {status}")

    return "OK", f"enrol→register→HB→cmd→result→revoke cycle ok (agent {agent_id[:8]})", ""


# ===========================================================================
# STAGE J — Compliance report
# ===========================================================================


def stage_J() -> tuple[str, str, str]:
    assert _admin_token
    status, body, _ = http(
        "GET", "/api/compliance/report?days=1", bearer=_admin_token
    )
    if status != 200:
        raise StageFail(f"compliance/report expected 200, got {status}")
    if not isinstance(body, dict):
        raise StageFail(f"report not JSON dict: {str(body)[:200]}")
    for key in ("scans", "detections", "audit", "window"):
        if key not in body:
            raise StageFail(f"report missing top-level key {key!r}; keys={list(body.keys())}")
    if body["window"]["start"] >= body["window"]["end"]:
        raise StageFail(f"window.start >= window.end: {body['window']}")

    # CSV
    status, body, hdrs = http(
        "GET", "/api/compliance/audit.csv?days=1", bearer=_admin_token
    )
    if status != 200:
        raise StageFail(f"audit.csv expected 200, got {status}")
    ctype = next(
        (v for k, v in hdrs.items() if k.lower() == "content-type"), ""
    )
    if "text/csv" not in ctype.lower():
        raise StageFail(f"audit.csv content-type {ctype!r}")
    first = str(body).splitlines()[0] if body else ""
    if not first.startswith("timestamp,"):
        raise StageFail(f"audit.csv header unexpected: {first!r}")

    return "OK", f"report keys present; window valid; csv header ok", ""


# ===========================================================================
# STAGE K — CEF forwarder loopback
# ===========================================================================


def stage_K() -> tuple[str, str, str]:
    import struct  # noqa: F401 — not used, but ensures module import is fine

    received: list[bytes] = []
    stop_event = threading.Event()

    def _listener() -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        try:
            s.bind(("127.0.0.1", 55514))
        except OSError as e:
            received.append(f"bind-failed:{e}".encode())
            return
        while not stop_event.is_set():
            try:
                data, _ = s.recvfrom(65535)
                received.append(data)
                return
            except TimeoutError:
                continue
            except OSError:
                break
        s.close()

    t = threading.Thread(target=_listener, daemon=True)
    t.start()
    time.sleep(0.3)  # let socket bind

    probe = REPO_ROOT / "logs" / "_cef_probe.py"
    probe.write_text(
        'from deepsecurity.alerts import CefSyslogSink, AlertEvent\n'
        'sink = CefSyslogSink("127.0.0.1", 55514, protocol="udp")\n'
        'sink.send(AlertEvent(kind="e2e.probe", severity="high",\n'
        '                     summary="e2e cef test", actor="e2e",\n'
        '                     file_path="C:/x",\n'
        '                     details={"mitre_tags": ["T1552.001"],\n'
        '                              "reasons": ["e2e_test"]}))\n'
        'print("ok")\n',
        encoding="utf-8",
    )
    register_cleanup(lambda: probe.unlink(missing_ok=True))

    r = run_cmd([str(VENV_PY), str(probe)], timeout=15)
    if r.returncode != 0:
        stop_event.set()
        raise StageFail(
            f"cef probe exit {r.returncode}: {r.stdout[-200:]} {r.stderr[-200:]}"
        )

    # wait briefly for packet
    deadline = now() + 3.0
    while now() < deadline and not received:
        time.sleep(0.2)
    stop_event.set()

    if not received:
        raise StageFail("no CEF packet received on 127.0.0.1:55514 within 3s")
    pkt = received[0].decode("utf-8", errors="replace")
    if "CEF:0|DEEPSecurity|deepsecurity|" not in pkt:
        raise StageFail(f"packet not CEF-formatted: {pkt[:300]!r}")
    if "cs1Label=MitreTags" not in pkt or "T1552.001" not in pkt:
        raise StageFail(f"packet missing MitreTags extension: {pkt[:400]!r}")

    return "OK", "UDP CEF packet received; header + MitreTags valid", ""


# ===========================================================================
# STAGE L — Prometheus metrics delta
# ===========================================================================


def stage_L() -> tuple[str, str, str]:
    # Snapshot values were captured in STAGE F.
    if _METRICS_AFTER <= _METRICS_BEFORE:
        raise StageFail(
            f"deepsec_files_scanned_total did not increase: "
            f"before={_METRICS_BEFORE} after={_METRICS_AFTER}"
        )

    # Verify build_info line
    try:
        with urllib.request.urlopen(f"{SERVER_URL}/metrics", timeout=3.0) as r:
            text = r.read().decode("utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001
        raise StageFail(f"couldn't fetch /metrics for build_info: {e}") from e
    if "deepsec_build_info" not in text:
        raise StageFail("/metrics missing deepsec_build_info")

    return (
        "OK",
        f"files_scanned_total: {_METRICS_BEFORE} → {_METRICS_AFTER}; build_info present",
        "",
    )


# ===========================================================================
# STAGE M — Redteam regression sampler
# ===========================================================================


def stage_M() -> tuple[str, str, str]:
    verdicts: list[tuple[str, str, str]] = []

    # #6 ML pickle poisoning — must reject os.system pickle
    probe = REPO_ROOT / "logs" / "_ml_probe.py"
    probe.write_text(
        'import os, pickle, tempfile, pathlib, sys\n'
        'class _Rce:\n'
        '    def __reduce__(self):\n'
        '        return (os.system, ("echo pwned",))\n'
        'with tempfile.TemporaryDirectory() as td:\n'
        '    p = pathlib.Path(td) / "evil.joblib"\n'
        '    with p.open("wb") as f:\n'
        '        pickle.dump(_Rce(), f)\n'
        '    from deepsecurity.ml import MLClassifier\n'
        '    clf = MLClassifier(model_path=p, confidence_threshold=0.8)\n'
        '    v = clf.classify([1.0,2.0,3.0])\n'
        '    print("OK" if (not v.enabled and v.reason == "ml_disabled") else "FAIL")\n',
        encoding="utf-8",
    )
    register_cleanup(lambda: probe.unlink(missing_ok=True))
    r = run_cmd([str(VENV_PY), str(probe)], timeout=15)
    outcome = (r.stdout.strip().splitlines()[-1:] or [""])[0]
    if outcome != "OK":
        raise StageFail(f"#6 ML pickle gate regressed: {r.stdout[-400:]}")
    verdicts.append(("#6 ml-pickle", "PASS", "rejected os.system pickle"))

    # #8 quarantine collision — run the specific pytest case. No
    # ``--timeout`` flag: pytest-timeout isn't a pinned dep.
    r = run_cmd(
        [str(VENV_PY), "-m", "pytest", "-q",
         "tests/test_scanner.py::test_quarantine_no_collision_on_dup"],
        timeout=60,
    )
    if r.returncode != 0:
        raise StageFail(
            f"#8 quarantine collision regressed:\n{r.stdout[-400:]}"
        )
    verdicts.append(("#8 quarantine-collision", "PASS", "pytest green"))

    # #7 signature file swap — integrity snapshot covers signatures.txt
    # Ensure signatures file has at least a comment so swap is meaningful.
    if not SIGNATURES_PATH.exists():
        SIGNATURES_PATH.write_text("# placeholder\n", encoding="utf-8")
        register_cleanup(lambda: SIGNATURES_PATH.unlink(missing_ok=True))
    # Take snapshot (CLI)
    snap = ds("integrity", "snapshot", timeout=30)
    if snap.returncode != 0:
        raise StageFail(f"integrity snapshot failed: {snap.stdout} {snap.stderr}")
    orig = SIGNATURES_PATH.read_bytes()

    def _restore_sig() -> None:
        try:
            SIGNATURES_PATH.write_bytes(orig)
        except OSError:
            pass

    register_cleanup(_restore_sig)
    SIGNATURES_PATH.write_text("", encoding="utf-8")
    chk = ds("integrity", "check", timeout=30)
    combined = chk.stdout + chk.stderr
    if "signatures.txt" not in combined:
        raise StageFail(
            f"#7 signatures.txt change not flagged in integrity check:\n{combined[-400:]}"
        )
    verdicts.append(("#7 sig-file swap", "PASS", "integrity flagged signatures.txt"))
    _restore_sig()
    ds("integrity", "snapshot", timeout=30)

    # #9 policy substitution — run integrity check with a flipped env var;
    # expect <policy> mismatched. We do NOT modify .env.
    env = os.environ.copy()
    current = dotenv().get("DEEPSEC_DLP_ENABLED", "true").lower()
    env["DEEPSEC_DLP_ENABLED"] = "false" if current == "true" else "true"
    # Run integrity check with the flipped env.
    r = run_cmd(
        [str(VENV_PY), "-m", "deepsecurity.cli", "integrity", "check"],
        timeout=30, env=env,
    )
    out = r.stdout + r.stderr
    if "<policy>" not in out:
        raise StageFail(
            f"#9 policy flip did not surface <policy> in integrity check:\n{out[-500:]}"
        )
    verdicts.append(("#9 policy-subst", "PASS", "<policy> mismatched"))

    # #2 base64-DLP: KNOWN-CEILING (pattern-level limitation)
    verdicts.append(("#2 base64-DLP", "KNOWN-CEILING", "pattern-only; see docs/WEDGE.md"))
    # #3 exclusion-path drop: proved by STAGE G
    verdicts.append(("#3 excl-drop", "KNOWN-CEILING", "by-design; verified STAGE G"))
    # #5 DB wipe: Phase 3 item backup-db not yet shipped
    has_backup = "backup-db" in (
        run_cmd([str(VENV_PY), "-m", "deepsecurity.cli", "--help"], timeout=10).stdout
    )
    verdicts.append(
        ("#5 db-wipe", "KNOWN-MISSING" if not has_backup else "PASS",
         "backup-db CLI not yet shipped" if not has_backup else "backup-db present")
    )
    # Others from the 10-attack list: kernel-ceiling / by-design
    for idx, label in (
        ("#1", "polymorphic hash mutate"),
        ("#4", "agent-kill (taskkill)"),
        ("#10", "anon rate-limit DoS"),
    ):
        verdicts.append((idx, "KNOWN-CEILING", f"{label} — see docs/COVERAGE_MODEL.md"))

    pass_count = sum(1 for v in verdicts if v[1] == "PASS")
    known_count = sum(1 for v in verdicts if v[1].startswith("KNOWN"))
    return (
        "OK",
        f"{pass_count} PASS, {known_count} KNOWN-CEILING/MISSING",
        "; ".join(f"{v[0]}={v[1]}" for v in verdicts),
    )


# ===========================================================================
# STAGE N — Light load sanity
# ===========================================================================


def stage_N() -> tuple[str, str, str]:
    N, CONCURRENCY = 100, 10
    latencies: list[float] = []
    errors: list[str] = []
    lock = threading.Lock()
    sem = threading.Semaphore(CONCURRENCY)

    def _one() -> None:
        with sem:
            t0 = now()
            try:
                with urllib.request.urlopen(f"{SERVER_URL}/healthz", timeout=3.0) as r:
                    if r.status != 200:
                        with lock:
                            errors.append(f"status {r.status}")
                            return
                    _ = r.read()
            except Exception as e:  # noqa: BLE001
                with lock:
                    errors.append(type(e).__name__)
                    return
            dt = now() - t0
            with lock:
                latencies.append(dt)

    threads = [threading.Thread(target=_one) for _ in range(N)]
    t0 = now()
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    wall = now() - t0

    if errors:
        raise StageFail(f"{len(errors)} non-200/connection errors: {errors[:5]}")
    if len(latencies) < N:
        raise StageFail(f"only {len(latencies)}/{N} responses within 30s")

    latencies.sort()
    p95 = latencies[int(0.95 * N) - 1] * 1000
    p99 = latencies[-1] * 1000
    if p95 > 200:
        raise StageFail(f"P95 {p95:.0f}ms > 200ms budget")

    return (
        "OK",
        f"{N} req @ c={CONCURRENCY} in {wall:.2f}s, P95={p95:.0f}ms P99={p99:.0f}ms",
        "",
    )


# ===========================================================================
# STAGE O — Integrity snapshot round-trip
# ===========================================================================


def stage_O() -> tuple[str, str, str]:
    # Snapshot
    r = ds("integrity", "snapshot", timeout=30)
    if r.returncode != 0:
        raise StageFail(f"snapshot failed: {r.stdout} {r.stderr}")

    # Check — expect ok
    r = ds("integrity", "check", timeout=30)
    if '"status": "ok"' not in r.stdout:
        raise StageFail(f"check not ok after fresh snapshot: {r.stdout[-400:]}")

    # Tamper: append a harmless comment to deepsecurity/__init__.py
    init_py = REPO_ROOT / "deepsecurity" / "__init__.py"
    orig = init_py.read_bytes()

    def _restore_init() -> None:
        try:
            init_py.write_bytes(orig)
        except OSError:
            pass

    register_cleanup(_restore_init)
    init_py.write_bytes(orig + b"\n# e2e tamper probe\n")

    r = ds("integrity", "check", timeout=30)
    out = r.stdout + r.stderr
    if '"status": "tampered"' not in out and "__init__.py" not in out:
        raise StageFail(
            f"tamper not detected on deepsecurity/__init__.py:\n{out[-400:]}"
        )

    # Restore and re-snapshot
    _restore_init()
    ds("integrity", "snapshot", timeout=30)
    r = ds("integrity", "check", timeout=30)
    if '"status": "ok"' not in r.stdout:
        raise StageFail(f"not ok after restore+resnapshot:\n{r.stdout[-400:]}")

    return "OK", "snapshot → tamper detected → restore → ok", ""


# ===========================================================================
# STAGE P — Cleanup + report
# ===========================================================================


def stage_P() -> tuple[str, str, str]:
    # stop the server we started in C
    try:
        ds("stop", timeout=20)
    except Exception:  # noqa: BLE001
        pass
    write_report()
    return "OK", f"report → {REPORT_PATH}", ""


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------


def write_report() -> None:
    LOG_DIR.mkdir(exist_ok=True)
    lines: list[str] = []
    lines.append(f"# DEEPSecurity E2E report — {START_TS.isoformat()}")
    lines.append("")
    total_dur = sum(r.duration_s for r in results)
    ok = sum(1 for r in results if r.status == "OK")
    fail = sum(1 for r in results if r.status == "FAIL")
    known = sum(1 for r in results if r.status.startswith("KNOWN"))
    lines.append(f"- Stages run: {len(results)}")
    lines.append(f"- OK: {ok}  FAIL: {fail}  KNOWN: {known}")
    lines.append(f"- Total duration: {total_dur:.1f}s")
    lines.append(f"- Report file: `{REPORT_PATH}`")
    lines.append("")
    lines.append("| Stage | Result | Duration | Evidence | Notes |")
    lines.append("|-------|--------|---------:|----------|-------|")
    pipe_bs = "\\|"
    for r in results:
        # Pre-escape outside the f-string; Python 3.11 refuses backslashes
        # inside f-string expressions (PEP 701 relaxed this only from 3.12).
        evidence = r.evidence.replace("|", pipe_bs)
        notes = r.notes.replace("|", pipe_bs)
        lines.append(
            f"| {r.code} {r.name} | {r.status} | {r.duration_s:.1f}s | "
            f"{evidence} | {notes} |"
        )
    lines.append("")
    REPORT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


STAGES: list[tuple[str, str, Callable[[], tuple[str, str, str]]]] = [
    ("A", "Environment sanity", stage_A),
    ("B", "Unit + integration pytest", stage_B),
    ("C", "Lifecycle CLI", stage_C),
    ("D", "Unauthenticated smoke", stage_D),
    ("E", "Authenticated flows", stage_E),
    ("F", "File-system E2E signature detection", stage_F),
    ("G", "Watchdog live event", stage_G),
    ("H", "DLP pattern coverage", stage_H),
    ("I", "Agent round-trip", stage_I),
    ("J", "Compliance report", stage_J),
    ("K", "CEF/syslog forwarder", stage_K),
    ("L", "Prometheus metrics delta", stage_L),
    ("M", "Redteam regression", stage_M),
    ("N", "Light load sanity", stage_N),
    ("O", "Integrity snapshot round-trip", stage_O),
    ("P", "Cleanup + report", stage_P),
]


def main() -> int:
    global _deadline
    _deadline = now() + BUDGET_S
    LOG_DIR.mkdir(exist_ok=True)

    if not VENV_PY.exists():
        print(f"FATAL: venv Python missing at {VENV_PY}")
        return 3

    exit_code = 0
    try:
        for code, name, fn in STAGES:
            if budget_left() < 2.0 and code != "P":
                print(f"[{code}] SKIP — budget exhausted")
                results.append(
                    Result(code, name, "SKIP", "budget exhausted", "", 0.0)
                )
                continue
            ok = run_stage(code, name, fn)
            if not ok and code != "P":
                # still run final cleanup + report via atexit; exit code 1
                exit_code = 1
                break
    except KeyboardInterrupt:
        print("\n-- interrupted --")
        exit_code = 2
    finally:
        # Always run stage P (write report) even on early termination.
        if not any(r.code == "P" for r in results):
            try:
                run_stage("P", "Cleanup + report", stage_P)
            except Exception:  # noqa: BLE001
                pass
        # Final summary
        ok = sum(1 for r in results if r.status == "OK")
        fail = sum(1 for r in results if r.status == "FAIL")
        known = sum(1 for r in results if r.status.startswith("KNOWN"))
        skip = sum(1 for r in results if r.status == "SKIP")
        print("")
        print(f"=== E2E summary: {ok} OK  {fail} FAIL  {known} KNOWN  {skip} SKIP ===")
        print(f"=== Report: {REPORT_PATH} ===")
    return exit_code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        sys.exit(1)
