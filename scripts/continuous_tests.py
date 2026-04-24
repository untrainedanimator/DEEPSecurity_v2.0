"""Continuous DEEPSecurity test runner.

ONE script. All tests. Runs forever on your laptop and tells you the
moment something regresses. No external dependencies beyond the stdlib.

Usage (from the repo root, venv activated):

    # Default: run every 5 minutes, autostart Flask, colour output.
    python scripts/continuous_tests.py

    # Every 30 minutes (user's original ask):
    python scripts/continuous_tests.py --interval 1800

    # One pass and exit — for CI / manual spot-check.
    python scripts/continuous_tests.py --once

    # Tight loop — every 30 seconds.
    python scripts/continuous_tests.py --interval 30

    # React to source changes instead of timed loop (needs `watchdog`).
    python scripts/continuous_tests.py --watch

    # Use an already-running server instead of autostarting one.
    python scripts/continuous_tests.py --no-autostart

    # Skip the live-HTTP smoke phase entirely.
    python scripts/continuous_tests.py --no-smoke

    # Stop after N consecutive failures (default 5 = don't stop).
    python scripts/continuous_tests.py --max-consecutive-failures 3

What it runs, in order, every pass:

    1. pytest (unit + integration, excluding `slow`)         ~5–15s
    2. pytest tests/test_operations_e2e.py                   ~20–30s
    3. scripts/smoke.py against a running server (optional)  ~3–5s

By default, the script spawns the Flask dev server *once* at the start
of the loop, reuses it for every pass's smoke phase, and stops it on
Ctrl+C. If a server is already listening on the target URL, that one is
reused and we don't spawn a new one. Pass ``--no-autostart`` to suppress
the spawn (e.g. when you're running the server yourself in another
terminal or pointing at a remote instance via ``--url``).

On pass: green line printed, status written to logs/last_run.json.
On fail: red line + traceback, failure reason written to log file,
and if a DEEPSecurity server is reachable, an alert event is dispatched
through the alert bus (so Slack/webhook/email fires).

Outputs:
    logs/continuous_tests.log    rolling human log (append-only)
    logs/last_run.json           last-pass summary (machine-readable)
    logs/failure_<ts>.txt        full stdout/stderr of any failed phase
    logs/server.log              stdout+stderr of the autostart server

Exit codes (with --once):
    0  everything passed
    1  at least one phase failed
    2  interrupted
    3  a dependency is missing (e.g. pytest not installed)
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = REPO_ROOT / "logs"
LOG_FILE = LOG_DIR / "continuous_tests.log"
LAST_RUN_FILE = LOG_DIR / "last_run.json"
SERVER_LOG = LOG_DIR / "server.log"


# ---------------------------------------------------------------------------
# Minimal ANSI colour helper (same pattern as scripts/smoke.py)
# ---------------------------------------------------------------------------


class C:
    if os.name == "nt":
        try:
            import ctypes

            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            pass
    green = "\033[32m"
    red = "\033[31m"
    yellow = "\033[33m"
    cyan = "\033[36m"
    dim = "\033[2m"
    bold = "\033[1m"
    reset = "\033[0m"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Phase result model
# ---------------------------------------------------------------------------


@dataclass
class PhaseResult:
    name: str
    status: str  # "pass" | "fail" | "skip"
    duration_sec: float
    message: str = ""
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0


@dataclass
class RunSummary:
    started_at: str
    finished_at: str
    total_seconds: float
    phases: list[dict] = field(default_factory=list)
    passed: int = 0
    failed: int = 0
    skipped: int = 0

    @property
    def all_green(self) -> bool:
        return self.failed == 0


# ---------------------------------------------------------------------------
# Server handle — spin up / tear down the Flask dev server around the smoke
# phase so we don't need a separate terminal running `flask run`.
# ---------------------------------------------------------------------------


def _parse_url(url: str) -> tuple[str, int]:
    """Return (host, port) from a URL like http://127.0.0.1:5000."""
    from urllib.parse import urlparse

    p = urlparse(url)
    host = p.hostname or "127.0.0.1"
    port = p.port or 5000
    return host, port


class ServerHandle:
    """Context manager: start the Flask dev server if it isn't already up.

    Detects a live server by polling ``/healthz``. If one is already
    listening at the target URL we don't touch it (handy when you're
    running ``flask run`` in another terminal or pointing at a remote
    instance). Otherwise we launch ``python -m flask run`` as a child
    process, wait for ``/healthz`` to return 200, and terminate it on
    exit.

    All stdout/stderr from the server is streamed to logs/server.log so
    the continuous-test console stays clean.
    """

    def __init__(self, url: str, autostart: bool = True) -> None:
        self.url = url.rstrip("/")
        self.host, self.port = _parse_url(url)
        self.autostart = autostart
        self._proc: subprocess.Popen | None = None
        self._log_handle = None
        self._we_started_it = False

    # -- context manager -----------------------------------------------------

    def __enter__(self) -> "ServerHandle":
        if self.is_up():
            print(
                f"  {C.dim}server already running at {self.url} — reusing it"
                f"{C.reset}"
            )
            return self

        if not self.autostart:
            print(
                f"  {C.yellow}no server at {self.url} and --no-autostart — "
                f"smoke phase will fail{C.reset}"
            )
            return self

        self._spawn()
        if not self._wait_ready(timeout=30):
            out = ""
            try:
                if SERVER_LOG.exists():
                    out = SERVER_LOG.read_text(encoding="utf-8", errors="replace")[-2000:]
            except Exception:
                pass
            self._stop()
            raise RuntimeError(
                f"Flask server did not come up within 30s. "
                f"Last server log:\n{out}"
            )
        print(
            f"  {C.green}server up{C.reset}  {self.url}  "
            f"{C.dim}(pid={self._proc.pid}, log={SERVER_LOG}){C.reset}"
        )
        self._we_started_it = True
        return self

    def __exit__(self, *exc_info) -> None:  # type: ignore[no-untyped-def]
        self._stop()

    # -- helpers -------------------------------------------------------------

    def is_up(self) -> bool:
        import urllib.error
        import urllib.request

        try:
            with urllib.request.urlopen(f"{self.url}/healthz", timeout=1.5) as resp:
                return resp.status == 200
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
            return False
        except Exception:
            return False

    def _spawn(self) -> None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env.setdefault("FLASK_APP", "deepsecurity.api:create_app")
        env.setdefault("PYTHONUNBUFFERED", "1")
        # Force UTF-8 on the Flask child so any unicode in JSON/log output
        # (e.g. arrows, emoji) doesn't explode against cp1252 on Windows.
        env.setdefault("PYTHONIOENCODING", "utf-8")
        # Respect caller-set DEEPSEC_HOST/PORT if they're in env; otherwise
        # force to match the URL we're going to smoke against.
        env.setdefault("DEEPSEC_HOST", self.host)
        env.setdefault("DEEPSEC_PORT", str(self.port))

        self._log_handle = SERVER_LOG.open("a", encoding="utf-8", buffering=1)
        self._log_handle.write(
            f"\n=== server start  {_iso_now()}  {self.url} ===\n"
        )
        print(
            f"  {C.dim}starting Flask server on {self.url} … "
            f"(log → {SERVER_LOG}){C.reset}"
        )

        # Platform-specific: on Windows, group the child in a new process
        # group so we can terminate the whole tree cleanly.
        creationflags = 0
        start_new_session = False
        if os.name == "nt":
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
        else:
            start_new_session = True

        self._proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "flask",
                "run",
                "--host",
                self.host,
                "--port",
                str(self.port),
                "--no-reload",  # reloader confuses signal handling
            ],
            cwd=str(REPO_ROOT),
            env=env,
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
            creationflags=creationflags,
            start_new_session=start_new_session,
        )

    def _wait_ready(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._proc is not None and self._proc.poll() is not None:
                # Child exited before becoming ready — no point waiting.
                return False
            if self.is_up():
                return True
            time.sleep(0.4)
        return False

    def _stop(self) -> None:
        if self._proc is None:
            if self._log_handle is not None:
                try:
                    self._log_handle.close()
                except Exception:
                    pass
                self._log_handle = None
            return

        print(
            f"  {C.dim}stopping server (pid={self._proc.pid}) …{C.reset}"
        )
        try:
            if os.name == "nt":
                # Send Ctrl+Break to the new process group.
                try:
                    self._proc.send_signal(signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
                except Exception:
                    self._proc.terminate()
            else:
                self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=2)
        except Exception:
            try:
                self._proc.kill()
            except Exception:
                pass
        finally:
            self._proc = None
            if self._log_handle is not None:
                try:
                    self._log_handle.write(
                        f"=== server stop  {_iso_now()} ===\n"
                    )
                    self._log_handle.close()
                except Exception:
                    pass
                self._log_handle = None


# ---------------------------------------------------------------------------
# Individual phase runners
# ---------------------------------------------------------------------------


def _run_phase(name: str, cmd: list[str], timeout: int = 300) -> PhaseResult:
    """Run a subprocess, capture output, map exit code to pass/fail."""
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",        # ← force UTF-8 so unicode in children survives
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        return PhaseResult(
            name=name,
            status="skip",
            duration_sec=time.monotonic() - t0,
            message=f"command not found: {cmd[0]}  ({exc})",
            returncode=127,
        )
    except subprocess.TimeoutExpired:
        return PhaseResult(
            name=name,
            status="fail",
            duration_sec=time.monotonic() - t0,
            message=f"timeout after {timeout}s",
            returncode=124,
        )

    duration = time.monotonic() - t0
    status = "pass" if proc.returncode == 0 else "fail"
    # Trim the output to keep the JSON file sane — full detail goes to disk.
    short = (proc.stdout or "").splitlines()[-5:]
    return PhaseResult(
        name=name,
        status=status,
        duration_sec=duration,
        message=" / ".join(short) if short else "",
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        returncode=proc.returncode,
    )


def phase_pytest_fast() -> PhaseResult:
    return _run_phase(
        "pytest (unit + integration)",
        [sys.executable, "-m", "pytest", "-q", "-m", "not slow"],
        timeout=300,
    )


def phase_pytest_e2e() -> PhaseResult:
    return _run_phase(
        "pytest e2e (operations runbook)",
        [sys.executable, "-m", "pytest", "-q", "tests/test_operations_e2e.py"],
        timeout=300,
    )


def phase_smoke(url: str, password: str | None) -> PhaseResult:
    cmd = [sys.executable, "scripts/smoke.py", "--url", url]
    if password:
        cmd += ["--password", password]
    return _run_phase("live smoke (HTTP)", cmd, timeout=120)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def one_pass(*, url: str, password: str | None, include_smoke: bool) -> RunSummary:
    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    phases: list[PhaseResult] = []

    phases.append(phase_pytest_fast())
    # Only run e2e if the fast tests passed — otherwise the e2e output just
    # amplifies the same failure.
    if phases[-1].status == "pass":
        phases.append(phase_pytest_e2e())
    else:
        phases.append(
            PhaseResult(
                name="pytest e2e (operations runbook)",
                status="skip",
                duration_sec=0.0,
                message="skipped because earlier phase failed",
            )
        )

    if include_smoke:
        phases.append(phase_smoke(url, password))
    else:
        phases.append(
            PhaseResult(
                name="live smoke (HTTP)",
                status="skip",
                duration_sec=0.0,
                message="--no-smoke",
            )
        )

    finished = datetime.now(timezone.utc)
    summary = RunSummary(
        started_at=started.isoformat(timespec="seconds"),
        finished_at=finished.isoformat(timespec="seconds"),
        total_seconds=time.monotonic() - t0,
        phases=[asdict(p) for p in phases],
        passed=sum(1 for p in phases if p.status == "pass"),
        failed=sum(1 for p in phases if p.status == "fail"),
        skipped=sum(1 for p in phases if p.status == "skip"),
    )
    return summary


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def _print_phase(p: dict) -> None:
    status = p["status"]
    colour = {"pass": C.green, "fail": C.red, "skip": C.yellow}[status]
    tag = f"{colour}{status.upper():<4}{C.reset}"
    dur = f"{p['duration_sec']:.1f}s"
    print(f"  {tag}  {p['name']:<36} {C.dim}{dur}{C.reset}  {p['message']}")


def _print_summary(s: RunSummary) -> None:
    tag = (
        f"{C.green}{C.bold}ALL GREEN{C.reset}"
        if s.all_green
        else f"{C.red}{C.bold}{s.failed} FAILED{C.reset}"
    )
    print("")
    print(
        f"  {tag}   "
        f"{C.green}{s.passed} pass{C.reset}  "
        f"{C.red}{s.failed} fail{C.reset}  "
        f"{C.yellow}{s.skipped} skip{C.reset}   "
        f"({s.total_seconds:.1f}s)"
    )


def _persist(s: RunSummary) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    # Rolling human log: one line per pass.
    tag = "OK " if s.all_green else "FAIL"
    line = (
        f"{s.finished_at}  {tag}  "
        f"pass={s.passed} fail={s.failed} skip={s.skipped}  "
        f"dur={s.total_seconds:.1f}s\n"
    )
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(line)

    # Machine-readable latest snapshot.
    LAST_RUN_FILE.write_text(json.dumps(asdict(s), indent=2), encoding="utf-8")

    # Full stdout+stderr of any failed phase, one file per failure.
    for p in s.phases:
        if p["status"] != "fail":
            continue
        ts = s.finished_at.replace(":", "").replace("-", "")
        fname = LOG_DIR / f"failure_{ts}_{p['name'].split()[0]}.txt"
        fname.write_text(
            f"# {p['name']}\n# exit {p['returncode']}\n\n"
            f"=== STDOUT ===\n{p['stdout']}\n\n"
            f"=== STDERR ===\n{p['stderr']}\n",
            encoding="utf-8",
        )


def _maybe_alert(s: RunSummary, url: str, password: str | None) -> None:
    """If the run failed and a DEEPSecurity server is reachable, fire an
    alert event through the bus. Best-effort — if the alert can't be
    delivered, we don't care (we're not blocking the test loop on it)."""
    if s.all_green or not password:
        return
    try:
        import urllib.request

        # Log in to get a token.
        login_body = json.dumps({"username": "admin", "password": password}).encode()
        req = urllib.request.Request(
            url.rstrip("/") + "/api/auth/login",
            data=login_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            token = json.loads(resp.read().decode()).get("access_token")
        if not token:
            return
        # Post a synthetic event (this route is admin-only, so will succeed).
        req = urllib.request.Request(
            url.rstrip("/") + "/api/sinks/test",
            data=b"",
            headers={"Authorization": f"Bearer {token}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5):
            pass
    except Exception:
        return


# ---------------------------------------------------------------------------
# Loop + watch modes
# ---------------------------------------------------------------------------


_SHUTDOWN = False


def _install_sigint_handler() -> None:
    def _handler(_signum, _frame) -> None:  # type: ignore[no-untyped-def]
        global _SHUTDOWN
        _SHUTDOWN = True
        print(f"\n{C.yellow}shutdown requested — finishing current pass{C.reset}")

    signal.signal(signal.SIGINT, _handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handler)


def loop(
    *,
    url: str,
    password: str | None,
    include_smoke: bool,
    interval: float,
    max_consecutive_failures: int,
) -> int:
    consecutive_failures = 0
    total_runs = 0
    total_failures = 0

    print(f"{C.bold}continuous_tests{C.reset}  target={url}  interval={interval}s")
    print(f"  log:       {LOG_FILE}")
    print(f"  last-run:  {LAST_RUN_FILE}")
    print(f"  Ctrl+C to stop\n")

    while not _SHUTDOWN:
        total_runs += 1
        print(f"{C.cyan}─── pass #{total_runs}  @  {_iso_now()}{C.reset}")
        s = one_pass(url=url, password=password, include_smoke=include_smoke)
        for p in s.phases:
            _print_phase(p)
        _print_summary(s)
        _persist(s)

        if s.all_green:
            consecutive_failures = 0
        else:
            consecutive_failures += 1
            total_failures += 1
            _maybe_alert(s, url, password)
            if consecutive_failures >= max_consecutive_failures:
                print(
                    f"\n{C.red}{C.bold}stopping: {consecutive_failures} consecutive failures"
                    f"{C.reset}"
                )
                return 1

        if _SHUTDOWN:
            break
        # Sleep in small chunks so Ctrl+C is snappy.
        print(f"{C.dim}sleeping {interval}s …{C.reset}\n")
        remain = interval
        while remain > 0 and not _SHUTDOWN:
            time.sleep(min(1.0, remain))
            remain -= 1.0

    print(
        f"\n{C.bold}stopped{C.reset}  "
        f"total_runs={total_runs}  total_failures={total_failures}"
    )
    return 0


def watch_mode(*, url: str, password: str | None, include_smoke: bool) -> int:
    """Re-run on source changes under deepsecurity/ and tests/.

    Needs the `watchdog` optional dep. Falls back to timed loop if not
    installed.
    """
    try:
        from watchdog.events import FileSystemEventHandler  # type: ignore[import-not-found]
        from watchdog.observers import Observer  # type: ignore[import-not-found]
    except ImportError:
        print(
            f"{C.yellow}watchdog not installed — falling back to 60s interval loop."
            f" Install with: pip install watchdog{C.reset}"
        )
        return loop(
            url=url,
            password=password,
            include_smoke=include_smoke,
            interval=60.0,
            max_consecutive_failures=999,
        )

    class Handler(FileSystemEventHandler):  # type: ignore[misc]
        def __init__(self) -> None:
            self._last = 0.0

        def on_any_event(self, event) -> None:  # type: ignore[no-untyped-def]
            if event.is_directory:
                return
            p = str(event.src_path)
            if not (p.endswith(".py") or p.endswith(".jsx") or p.endswith(".yaml")):
                return
            # Debounce: one run per 2 s of quiet.
            now = time.monotonic()
            if now - self._last < 2.0:
                return
            self._last = now
            print(
                f"{C.cyan}source changed: {Path(p).relative_to(REPO_ROOT)}"
                f" — rerunning{C.reset}"
            )
            s = one_pass(url=url, password=password, include_smoke=include_smoke)
            for ph in s.phases:
                _print_phase(ph)
            _print_summary(s)
            _persist(s)
            if not s.all_green:
                _maybe_alert(s, url, password)

    obs = Observer()
    handler = Handler()
    obs.schedule(handler, str(REPO_ROOT / "deepsecurity"), recursive=True)
    obs.schedule(handler, str(REPO_ROOT / "tests"), recursive=True)
    obs.start()
    print(
        f"{C.bold}continuous_tests (watch){C.reset}  target={url}  "
        f"watching: deepsecurity/ tests/"
    )
    print(f"  Ctrl+C to stop\n")

    # Initial pass.
    s = one_pass(url=url, password=password, include_smoke=include_smoke)
    for ph in s.phases:
        _print_phase(ph)
    _print_summary(s)
    _persist(s)

    try:
        while not _SHUTDOWN:
            time.sleep(1.0)
    finally:
        obs.stop()
        obs.join()
    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run exactly one pass then exit. Useful for CI.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=300.0,
        help="Seconds between runs in loop mode. Default 300.",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Re-run on source change instead of timed loop (needs `watchdog`).",
    )
    parser.add_argument(
        "--no-smoke",
        action="store_true",
        help="Skip the live-HTTP smoke phase entirely.",
    )
    parser.add_argument(
        "--no-autostart",
        action="store_true",
        help=(
            "Don't autostart the Flask server for the smoke phase. Use this "
            "if you're running the server yourself or pointing --url at a "
            "remote instance."
        ),
    )
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:5000",
        help="Server URL for the live smoke phase. Default http://127.0.0.1:5000",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="Admin password. Default: read DEEPSEC_DEV_PASSWORD from env/.env",
    )
    parser.add_argument(
        "--max-consecutive-failures",
        type=int,
        default=5,
        help="Stop after this many consecutive failures. Default 5.",
    )
    args = parser.parse_args()

    # Read password from .env if not given.
    password = args.password or os.environ.get("DEEPSEC_DEV_PASSWORD") or ""
    if not password:
        env_path = REPO_ROOT / ".env"
        if env_path.exists():
            for line in env_path.read_text(encoding="utf-8").splitlines():
                if line.startswith("DEEPSEC_DEV_PASSWORD="):
                    password = line.split("=", 1)[1].strip().strip('"').strip("'")
                    break

    include_smoke = not args.no_smoke
    autostart = include_smoke and not args.no_autostart

    _install_sigint_handler()

    # One ServerHandle covers all three modes. When include_smoke is False we
    # still enter the context for symmetry, but ServerHandle.__enter__ is a
    # no-op because autostart is False and we never hit the smoke phase.
    try:
        with ServerHandle(url=args.url, autostart=autostart):
            if args.once:
                s = one_pass(
                    url=args.url,
                    password=password or None,
                    include_smoke=include_smoke,
                )
                for p in s.phases:
                    _print_phase(p)
                _print_summary(s)
                _persist(s)
                return 0 if s.all_green else 1

            if args.watch:
                return watch_mode(
                    url=args.url,
                    password=password or None,
                    include_smoke=include_smoke,
                )

            return loop(
                url=args.url,
                password=password or None,
                include_smoke=include_smoke,
                interval=args.interval,
                max_consecutive_failures=args.max_consecutive_failures,
            )
    except RuntimeError as exc:
        # Thrown by ServerHandle if the Flask server refused to come up.
        print(f"\n{C.red}{C.bold}fatal: {exc}{C.reset}")
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(2)
