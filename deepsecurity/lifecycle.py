"""Server lifecycle helpers — start / stop / status / clean.

Manages BOTH the Flask backend and the Vite frontend. The DB is created
by the backend on startup (``get_engine()`` auto-mkdirs the SQLite
parent), so "start the DB" is not a separate step — booting the backend
does it.

Pidfile shape (``.deepsec.pid``, JSON):

    {
      "backend":  {"pid": 12345, "url": "http://127.0.0.1:5000"},
      "frontend": {"pid": 12346, "url": "http://127.0.0.1:5173"}
    }

Design notes:
    - The CLI (``deepsecurity start``) orchestrates: spawn backend, wait
      for ``/healthz``, spawn frontend (vite), wait for vite's HTTP 200,
      then open the browser at the frontend URL.
    - We only detach background processes on Windows via DETACHED_PROCESS
      + CREATE_NEW_PROCESS_GROUP; on POSIX we ``start_new_session=True``
      which is functionally equivalent.
    - ``stop`` is graceful → force-kill after timeout. Kills both.
    - ``clean`` builds a plan first so the confirmation prompt shows
      exactly what's about to disappear.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = REPO_ROOT / "frontend"
PID_FILE = REPO_ROOT / ".deepsec.pid"
LOG_DIR = REPO_ROOT / "logs"
SERVER_LOG = LOG_DIR / "server.log"
FRONTEND_LOG = LOG_DIR / "frontend.log"

DEFAULT_FRONTEND_PORT = 5173


# ---------------------------------------------------------------------------
# Pidfile helpers
# ---------------------------------------------------------------------------


def _read_pidfile() -> dict:
    if not PID_FILE.exists():
        return {}
    try:
        raw = PID_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return {}
    if not raw:
        return {}

    # Preferred: a JSON object ``{"backend": {...}, "frontend": {...}}``.
    # Legacy: a bare integer (the old single-backend-PID pidfile). Note that
    # ``json.loads("12345")`` happily returns the int 12345 without raising —
    # so we can't rely on JSONDecodeError to distinguish the two formats; we
    # have to check the TYPE after parsing.
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = None

    if isinstance(parsed, dict):
        return parsed
    if isinstance(parsed, int):
        return {"backend": {"pid": parsed, "url": _default_backend_url()}}
    # Last-ditch: try to coerce the raw text to an int (pre-JSON pidfile).
    try:
        return {"backend": {"pid": int(raw), "url": _default_backend_url()}}
    except ValueError:
        return {}


def _write_pidfile(data: dict) -> None:
    PID_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _clear_pidfile_entry(key: str) -> None:
    """Remove one entry from the pidfile (backend or frontend). Delete the
    file entirely if nothing is left."""
    data = _read_pidfile()
    data.pop(key, None)
    if data:
        _write_pidfile(data)
    else:
        try:
            PID_FILE.unlink()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Process liveness / health probes
# ---------------------------------------------------------------------------


def _pid_alive(pid: int | None) -> bool:
    """Best-effort check that ``pid`` is still a live OS process."""
    if not pid or pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid
            )
            if not handle:
                return False
            code = ctypes.c_ulong(0)
            ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
            ctypes.windll.kernel32.CloseHandle(handle)
            return code.value == 259  # STILL_ACTIVE
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def _http_ok(url: str, path: str = "/", timeout: float = 1.5) -> bool:
    """Does ``url + path`` answer with any 2xx/3xx response?"""
    try:
        full = url.rstrip("/") + path
        with urllib.request.urlopen(full, timeout=timeout) as r:
            return 200 <= r.status < 400
    except urllib.error.HTTPError:
        # 4xx/5xx means the server is up but the route disagrees — still "up".
        return True
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
        return False
    except Exception:
        return False


def _backend_healthy(url: str) -> bool:
    return _http_ok(url, path="/healthz", timeout=1.5)


def _frontend_up(url: str) -> bool:
    # Vite dev server responds with 200 HTML on /.
    return _http_ok(url, path="/", timeout=1.5)


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------


def _default_backend_url() -> str:
    try:
        from deepsecurity.config import settings

        return f"http://{settings.host}:{settings.port}"
    except Exception:
        return "http://127.0.0.1:5000"


def _default_frontend_url(port: int = DEFAULT_FRONTEND_PORT) -> str:
    return f"http://127.0.0.1:{port}"


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


@dataclass
class ComponentStatus:
    name: str
    pid: int | None
    url: str
    pid_alive: bool
    http_up: bool

    @property
    def running(self) -> bool:
        return self.pid_alive or self.http_up


@dataclass
class ServerStatus:
    backend: ComponentStatus
    frontend: ComponentStatus
    pidfile: Path
    server_log: Path
    frontend_log: Path

    @property
    def running(self) -> bool:
        """True if EITHER component is running (used by callers that just
        want to know "is there anything to stop")."""
        return self.backend.running or self.frontend.running

    @property
    def healthy(self) -> bool:
        """Backend healthy = ``/healthz`` OK. The only component that has a
        meaningful health probe."""
        return self.backend.http_up

    # Back-compat shims for older callers that expected a single pid/url.
    @property
    def pid(self) -> int | None:
        return self.backend.pid if self.backend.pid_alive else None

    @property
    def url(self) -> str:
        return self.frontend.url if self.frontend.running else self.backend.url

    @property
    def extra(self) -> dict:
        return {
            "pidfile_present": PID_FILE.exists(),
            "backend_pid_from_file": self.backend.pid,
            "backend_pid_alive": self.backend.pid_alive,
            "frontend_pid_from_file": self.frontend.pid,
            "frontend_pid_alive": self.frontend.pid_alive,
        }


def status() -> ServerStatus:
    pf = _read_pidfile()

    be = pf.get("backend") or {}
    be_pid = be.get("pid")
    be_url = be.get("url") or _default_backend_url()
    backend = ComponentStatus(
        name="backend",
        pid=be_pid if isinstance(be_pid, int) else None,
        url=be_url,
        pid_alive=_pid_alive(be_pid if isinstance(be_pid, int) else None),
        http_up=_backend_healthy(be_url),
    )

    fe = pf.get("frontend") or {}
    fe_pid = fe.get("pid")
    fe_url = fe.get("url") or _default_frontend_url()
    frontend = ComponentStatus(
        name="frontend",
        pid=fe_pid if isinstance(fe_pid, int) else None,
        url=fe_url,
        pid_alive=_pid_alive(fe_pid if isinstance(fe_pid, int) else None),
        http_up=_frontend_up(fe_url),
    )

    return ServerStatus(
        backend=backend,
        frontend=frontend,
        pidfile=PID_FILE,
        server_log=SERVER_LOG,
        frontend_log=FRONTEND_LOG,
    )


# ---------------------------------------------------------------------------
# Start helpers
# ---------------------------------------------------------------------------


def _detach_flags() -> tuple[int, bool]:
    """Return (creationflags, start_new_session) so spawned children survive
    the parent shell exiting."""
    if os.name == "nt":
        # DETACHED_PROCESS (0x08) + CREATE_NEW_PROCESS_GROUP (0x200)
        return 0x00000008 | 0x00000200, False
    return 0, True


def _wait_for(predicate, timeout: float, probe_proc: subprocess.Popen | None = None) -> bool:
    """Poll ``predicate()`` every 400ms until True or deadline passes.
    If ``probe_proc`` is given and it exits, bail early."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if probe_proc is not None and probe_proc.poll() is not None:
            return False
        if predicate():
            return True
        time.sleep(0.4)
    return False


def _spawn_backend(host: str, port: int) -> tuple[int, str]:
    """Start the Flask backend in the background. Returns (pid, url)."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    url = f"http://{host}:{port}"

    env = os.environ.copy()
    env.setdefault("FLASK_APP", "deepsecurity.api:create_app")
    env.setdefault("PYTHONUNBUFFERED", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env["DEEPSEC_HOST"] = host
    env["DEEPSEC_PORT"] = str(port)

    log_handle = SERVER_LOG.open("a", encoding="utf-8", buffering=1)
    log_handle.write(f"\n=== backend start  host={host} port={port} ===\n")

    creationflags, start_new_session = _detach_flags()

    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "flask",
            "run",
            "--host",
            host,
            "--port",
            str(port),
            "--no-reload",
        ],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        creationflags=creationflags,
        start_new_session=start_new_session,
        close_fds=True,
    )

    log_handle.write(f"=== backend pid={proc.pid} ===\n")

    ready = _wait_for(lambda: _backend_healthy(url), timeout=30.0, probe_proc=proc)
    if not ready:
        # Child may have died or taken too long; surface a clean error.
        if proc.poll() is not None:
            raise RuntimeError(
                f"backend exited with code {proc.returncode} during startup; "
                f"see {SERVER_LOG}"
            )
        raise RuntimeError(
            f"backend did not answer /healthz within 30s; still pid {proc.pid} — "
            f"see {SERVER_LOG}"
        )

    return proc.pid, url


def _frontend_available() -> tuple[bool, str]:
    """(available, reason). False + reason if we can't or shouldn't start."""
    if not FRONTEND_DIR.exists():
        return False, f"no frontend directory at {FRONTEND_DIR}"
    if not (FRONTEND_DIR / "package.json").exists():
        return False, f"no package.json in {FRONTEND_DIR}"
    if shutil.which("npm") is None:
        return False, "npm not found on PATH (install Node.js to use the frontend)"
    if not (FRONTEND_DIR / "node_modules").exists():
        return False, (
            f"{FRONTEND_DIR / 'node_modules'} is missing — run "
            f"``cd frontend && npm install`` first"
        )
    return True, ""


def _spawn_frontend(port: int = DEFAULT_FRONTEND_PORT) -> tuple[int, str]:
    """Start Vite in the background. Returns (pid, url)."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    url = f"http://127.0.0.1:{port}"

    # Resolve ``npm`` (Windows gives us npm.cmd).
    npm = shutil.which("npm")
    if npm is None:
        raise RuntimeError("npm not found on PATH")

    log_handle = FRONTEND_LOG.open("a", encoding="utf-8", buffering=1)
    log_handle.write(f"\n=== frontend start  port={port} ===\n")

    env = os.environ.copy()
    env.setdefault("FORCE_COLOR", "0")  # keep the log readable

    creationflags, start_new_session = _detach_flags()

    # ``npm run dev -- --port N --strictPort`` pins the port so we know
    # exactly where to open the browser.
    proc = subprocess.Popen(
        [npm, "run", "dev", "--", "--port", str(port), "--strictPort"],
        cwd=str(FRONTEND_DIR),
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        creationflags=creationflags,
        start_new_session=start_new_session,
        close_fds=True,
        shell=False,
    )

    log_handle.write(f"=== frontend pid={proc.pid} ===\n")

    # Vite typically comes up in 1-3s on Windows, but cold starts can take
    # longer the first time it rebuilds the dep cache.
    ready = _wait_for(lambda: _frontend_up(url), timeout=60.0, probe_proc=proc)
    if not ready:
        if proc.poll() is not None:
            raise RuntimeError(
                f"frontend exited with code {proc.returncode} during startup; "
                f"see {FRONTEND_LOG}"
            )
        raise RuntimeError(
            f"frontend did not answer on {url} within 60s; still pid {proc.pid} — "
            f"see {FRONTEND_LOG}"
        )

    return proc.pid, url


# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------


def start(
    *,
    host: str | None = None,
    port: int | None = None,
    foreground: bool = False,
    ready_timeout: float = 30.0,  # kept for back-compat; per-component timeouts live inside
    backend: bool = True,
    frontend: bool = True,
    frontend_port: int = DEFAULT_FRONTEND_PORT,
    open_browser: bool = True,
) -> ServerStatus:
    """Launch backend + frontend (both by default).

    - ``foreground`` runs the backend inline, no frontend. Good for ``flask run``
      style debugging. Does not write a pidfile or open a browser.
    - Default mode: detaches both, writes PIDs to ``.deepsec.pid``, polls until
      each is healthy, then (if ``open_browser``) opens the frontend URL.
    """
    from deepsecurity.config import settings as cfg

    bind_host = host or cfg.host
    bind_port = port or cfg.port

    if foreground:
        # Foreground means "run the backend here in this terminal". No
        # frontend, no browser, no pidfile. Same shape as ``flask run``.
        from deepsecurity.api import create_app
        from deepsecurity.db import init_db

        init_db()
        app = create_app()
        app.run(host=bind_host, port=bind_port, debug=cfg.debug)
        return status()

    pf = _read_pidfile()
    cur = status()

    # Backend --------------------------------------------------------------
    if backend and not cur.backend.running:
        be_pid, be_url = _spawn_backend(bind_host, bind_port)
        pf["backend"] = {"pid": be_pid, "url": be_url}
        _write_pidfile(pf)

    # Frontend -------------------------------------------------------------
    if frontend:
        ok, reason = _frontend_available()
        if not ok:
            # Don't fail the whole start — just log and carry on.
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            FRONTEND_LOG.open("a", encoding="utf-8").write(
                f"=== frontend skipped  reason={reason} ===\n"
            )
            print(f"  frontend skipped — {reason}")
        else:
            cur = status()  # re-check; backend just came up
            if not cur.frontend.running:
                fe_pid, fe_url = _spawn_frontend(port=frontend_port)
                pf["frontend"] = {"pid": fe_pid, "url": fe_url}
                _write_pidfile(pf)

    final = status()

    # Browser --------------------------------------------------------------
    if open_browser:
        target = (
            final.frontend.url
            if final.frontend.http_up
            else final.backend.url
            if final.backend.http_up
            else None
        )
        if target:
            try:
                webbrowser.open_new_tab(target)
            except Exception:
                # If we can't open, no big deal — the URL is printed anyway.
                pass

    return final


# ---------------------------------------------------------------------------
# Stop
# ---------------------------------------------------------------------------


def _kill(pid: int | None, timeout: float) -> bool:
    """Best-effort graceful stop → force-kill. Returns True if we actually
    killed something."""
    if not pid or not _pid_alive(pid):
        return False
    try:
        if os.name == "nt":
            try:
                os.kill(pid, signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
            except (OSError, AttributeError):
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T"], check=False
                )
        else:
            os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return False

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.3)

    # Still alive — force.
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"], check=False
            )
        else:
            os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    # Final check.
    return not _pid_alive(pid)


def stop(*, timeout: float = 10.0) -> dict:
    """Stop both components. Returns per-component results."""
    pf = _read_pidfile()
    out = {"backend": False, "frontend": False}

    for key in ("frontend", "backend"):  # stop frontend first — it depends on backend
        entry = pf.get(key) or {}
        pid = entry.get("pid") if isinstance(entry.get("pid"), int) else None
        if pid is None:
            continue
        if _kill(pid, timeout=timeout):
            out[key] = True
        _clear_pidfile_entry(key)

    return out


# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------


@dataclass
class CleanPlan:
    """What ``clean`` is going to remove. Built up, then executed."""

    stop_server: bool = False
    paths: list[Path] = field(default_factory=list)

    def add(self, path: Path) -> None:
        if path.exists():
            self.paths.append(path)

    @property
    def anything_to_do(self) -> bool:
        return self.stop_server or bool(self.paths)


def build_clean_plan(
    *,
    logs: bool = True,
    database: bool = True,
    quarantine: bool = True,
    safelist: bool = False,
    deleted: bool = True,
    caches: bool = True,
    pidfile: bool = True,
) -> CleanPlan:
    """Figure out what ``clean`` would do, without doing it.

    Defaults remove throwaway state (logs, caches, DB, quarantine, deleted
    files, stale pidfile) but PRESERVE the operator-curated safelist — you
    rarely want that nuked. Pass ``safelist=True`` to include it.
    """
    plan = CleanPlan()
    st = status()
    if st.running:
        plan.stop_server = True

    try:
        from deepsecurity.config import settings

        if database:
            url = settings.database_url
            if url.startswith("sqlite:") and ":memory:" not in url:
                _, _, tail = url.partition(":///")
                if tail:
                    plan.add(Path(tail))
        if quarantine:
            plan.add(settings.quarantine_dir)
        if safelist:
            plan.add(settings.safelist_dir)
        if deleted:
            plan.add(settings.deleted_dir)
    except Exception:
        if database:
            plan.add(REPO_ROOT / "data" / "deepscan.db")
        if quarantine:
            plan.add(REPO_ROOT / "quarantine")
        if deleted:
            plan.add(REPO_ROOT / "deleted")

    if logs:
        plan.add(LOG_DIR)

    if caches:
        for cache_dir in (".pytest_cache", ".mypy_cache", ".ruff_cache", "htmlcov"):
            plan.add(REPO_ROOT / cache_dir)
        plan.add(REPO_ROOT / ".coverage")

    if pidfile:
        plan.add(PID_FILE)

    return plan


def execute_clean_plan(plan: CleanPlan) -> dict[str, int]:
    """Run the plan. Returns counters for the CLI to report."""
    counts = {"stopped": 0, "removed": 0, "failed": 0}
    if plan.stop_server:
        result = stop()
        counts["stopped"] = sum(1 for v in result.values() if v)

    for path in plan.paths:
        try:
            if path.is_file():
                path.unlink()
            elif path.is_dir():
                shutil.rmtree(path)
            else:
                continue
            counts["removed"] += 1
        except OSError:
            counts["failed"] += 1
    return counts
