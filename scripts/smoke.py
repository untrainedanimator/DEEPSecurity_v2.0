"""End-to-end smoke test for a running DEEPSecurity server.

Usage:
    python scripts/smoke.py                       # uses defaults from .env
    python scripts/smoke.py --url http://host:5000
    python scripts/smoke.py --password "my pwd"
    python scripts/smoke.py --verbose             # show full response bodies

Exits 0 if every step passes, non-zero otherwise. Uses only the stdlib, so
it runs even if the venv isn't activated — `python scripts/smoke.py` from
the repo root is enough.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import ssl
import sys
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable


# Force UTF-8 on stdout/stderr so unicode arrows etc. render on Windows
# (cp1252 consoles otherwise raise UnicodeEncodeError and fail the script).
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
except Exception:
    # Older Python or wrapped streams — wrap manually.
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True
    )
    sys.stderr = io.TextIOWrapper(
        sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True
    )


# ---------------------------------------------------------------------------
# Tiny colour helper — ANSI, degrades to plain on Windows without ANSI.
# ---------------------------------------------------------------------------


class C:
    if os.name == "nt":
        # Enable VT sequences on modern Windows 10+ terminals.
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


# ---------------------------------------------------------------------------
# HTTP helpers (stdlib)
# ---------------------------------------------------------------------------


def _request(
    method: str,
    url: str,
    *,
    token: str | None = None,
    body: Any = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, str], bytes]:
    headers: dict[str, str] = {"Accept": "application/json, text/plain"}
    data: bytes | None = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    ctx = ssl.create_default_context() if url.startswith("https://") else None
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read()


def _json(payload: bytes) -> Any:
    try:
        return json.loads(payload.decode("utf-8"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Config — read the admin password from .env if not supplied.
# ---------------------------------------------------------------------------


def _password_from_env(env_path: Path) -> str:
    if not env_path.exists():
        return ""
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("DEEPSEC_DEV_PASSWORD="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return ""


def _scan_root_from_env(env_path: Path) -> Path | None:
    if not env_path.exists():
        return None
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("DEEPSEC_SCAN_ROOT="):
            return Path(line.split("=", 1)[1].strip().strip('"').strip("'"))
    return None


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class Runner:
    def __init__(self, url: str, verbose: bool) -> None:
        self.url = url.rstrip("/")
        self.verbose = verbose
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.token: str | None = None

    def _out(self, status: str, colour: str, label: str, detail: str = "") -> None:
        tag = f"{colour}{status:<6}{C.reset}"
        print(f"  {tag}  {label}", end="")
        if detail:
            print(f"  {C.dim}{detail}{C.reset}")
        else:
            print("")

    def check(
        self,
        label: str,
        fn: Callable[[], tuple[bool, str]],
        *,
        skip_reason: str | None = None,
    ) -> None:
        if skip_reason:
            self.skipped += 1
            self._out("SKIP", C.yellow, label, skip_reason)
            return
        try:
            ok, detail = fn()
            if ok:
                self.passed += 1
                self._out("PASS", C.green, label, detail)
            else:
                self.failed += 1
                self._out("FAIL", C.red, label, detail)
        except Exception as e:
            self.failed += 1
            self._out("FAIL", C.red, label, f"{type(e).__name__}: {e}")
            if self.verbose:
                traceback.print_exc()

    def summary(self) -> int:
        total = self.passed + self.failed + self.skipped
        tag = (
            f"{C.green}{C.bold}ALL GREEN{C.reset}"
            if self.failed == 0
            else f"{C.red}{C.bold}{self.failed} FAILED{C.reset}"
        )
        print("")
        print(
            f"  {tag}   "
            f"{C.green}{self.passed} passed{C.reset}  "
            f"{C.red}{self.failed} failed{C.reset}  "
            f"{C.yellow}{self.skipped} skipped{C.reset}  "
            f"(total {total})"
        )
        return 0 if self.failed == 0 else 1


# ---------------------------------------------------------------------------
# Individual checks — each returns (ok, detail_for_output).
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:5000")
    parser.add_argument(
        "--password",
        default=None,
        help="Admin password. Defaults to DEEPSEC_DEV_PASSWORD from .env.",
    )
    parser.add_argument("--env-file", default=".env")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument(
        "--full-scan",
        action="store_true",
        help="Actually kick off a scan. Writes files into scan_root.",
    )
    args = parser.parse_args()

    env_path = Path(args.env_file)
    password = args.password or os.environ.get("DEEPSEC_DEV_PASSWORD") or _password_from_env(
        env_path
    )

    r = Runner(args.url, args.verbose)

    print(f"{C.bold}DEEPSecurity smoke test{C.reset}")
    print(f"  target: {C.cyan}{args.url}{C.reset}")
    print(f"  env:    {C.cyan}{env_path}{C.reset}")
    print("")

    # -------------------- Unauthenticated --------------------
    print(f"{C.bold}Unauthenticated{C.reset}")

    def _root() -> tuple[bool, str]:
        code, _, body = _request("GET", f"{r.url}/")
        j = _json(body) or {}
        ok = code == 200 and j.get("service") == "deepsecurity"
        return ok, f"HTTP {code}  service={j.get('service')}  version={j.get('version')}"

    r.check("GET /", _root)

    def _healthz() -> tuple[bool, str]:
        code, _, body = _request("GET", f"{r.url}/healthz")
        return code == 200 and _json(body) == {"status": "ok"}, f"HTTP {code}"

    r.check("GET /healthz", _healthz)

    def _readyz() -> tuple[bool, str]:
        code, _, body = _request("GET", f"{r.url}/readyz")
        j = _json(body) or {}
        detail = f"HTTP {code}  status={j.get('status')}  db={j.get('checks',{}).get('database')}"
        return code == 200 and j.get("status") == "ok", detail

    r.check("GET /readyz", _readyz)

    def _metrics() -> tuple[bool, str]:
        code, headers, body = _request("GET", f"{r.url}/metrics")
        text = body.decode("utf-8", errors="replace")
        ok = (
            code == 200
            and headers.get("Content-Type", "").startswith("text/plain")
            and "deepsec_build_info" in text
            and "deepsec_scans_started_total" in text
        )
        return ok, f"HTTP {code}  {len(text.splitlines())} lines"

    r.check("GET /metrics", _metrics)

    def _headers() -> tuple[bool, str]:
        code, headers, _ = _request("GET", f"{r.url}/healthz")
        missing = [
            h
            for h in (
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
                "Content-Security-Policy",
                "Strict-Transport-Security",
            )
            if h not in headers
        ]
        return len(missing) == 0, "all 5 security headers present" if not missing else f"missing: {missing}"

    r.check("security headers", _headers)

    def _favicon() -> tuple[bool, str]:
        code, _, _ = _request("GET", f"{r.url}/favicon.ico")
        return code == 204, f"HTTP {code}"

    r.check("GET /favicon.ico → 204", _favicon)

    def _unauthed_protected() -> tuple[bool, str]:
        code, _, body = _request("GET", f"{r.url}/api/scanner/sessions")
        j = _json(body) or {}
        ok = code == 401 and j.get("error") == "unauthenticated"
        return ok, f"HTTP {code}  error={j.get('error')}"

    r.check("unauth → 401 (no fallback identity)", _unauthed_protected)

    def _bad_login() -> tuple[bool, str]:
        code, _, _ = _request(
            "POST",
            f"{r.url}/api/auth/login",
            body={"username": "admin", "password": "definitely-wrong"},
        )
        return code == 401, f"HTTP {code}"

    r.check("login wrong password → 401", _bad_login)

    # -------------------- Authenticated --------------------
    print("")
    print(f"{C.bold}Authenticated{C.reset}")

    if not password:
        r.check(
            "login",
            lambda: (False, "no password found"),
            skip_reason="--password not given and DEEPSEC_DEV_PASSWORD not in .env/environment",
        )
        return r.summary()

    def _login() -> tuple[bool, str]:
        code, _, body = _request(
            "POST",
            f"{r.url}/api/auth/login",
            body={"username": "admin", "password": password},
        )
        j = _json(body) or {}
        if code == 200 and j.get("access_token"):
            r.token = j["access_token"]
            return True, f"role={j.get('role')}  token={r.token[:20]}..."
        # On failure surface the full server-side error — in dev mode the
        # handler includes the exception class too.
        detail = f"HTTP {code}  error={j.get('error')}"
        if j.get("exception"):
            detail += f"  ({j['exception']})"
        if j.get("detail"):
            detail += f"  {j['detail']}"
        return False, detail

    r.check("POST /api/auth/login", _login)

    def _whoami() -> tuple[bool, str]:
        code, _, body = _request("GET", f"{r.url}/api/auth/whoami", token=r.token)
        j = _json(body) or {}
        return code == 200 and j.get("role") == "admin", f"HTTP {code}  {j}"

    r.check("GET /api/auth/whoami", _whoami)

    def _scanner_status() -> tuple[bool, str]:
        code, _, body = _request("GET", f"{r.url}/api/scanner/status")
        j = _json(body) or {}
        ok = code == 200 and "running" in j and "progress_percent" in j
        return ok, f"HTTP {code}  running={j.get('running')}  cpu={j.get('cpu')}"

    r.check("GET /api/scanner/status", _scanner_status)

    def _err_detail(code: int, body: bytes, extra: str = "") -> str:
        """Uniform failure detail: HTTP code + error body."""
        j = _json(body)
        if isinstance(j, dict) and "error" in j:
            msg = f"HTTP {code}  {j.get('error')}"
            if "exception" in j:
                msg += f"  ({j['exception']})"
            return msg
        if extra:
            return f"HTTP {code}  {extra}"
        return f"HTTP {code}  body={body[:120]!r}"

    def _sessions() -> tuple[bool, str]:
        code, _, body = _request("GET", f"{r.url}/api/scanner/sessions", token=r.token)
        j = _json(body)
        if code == 200 and isinstance(j, list):
            return True, f"HTTP {code}  {len(j)} sessions"
        return False, _err_detail(code, body)

    r.check("GET /api/scanner/sessions", _sessions)

    def _quarantine() -> tuple[bool, str]:
        code, _, body = _request("GET", f"{r.url}/api/quarantine/list", token=r.token)
        j = _json(body) or {}
        if code == 200 and "entries" in j:
            return True, f"HTTP {code}  {len(j.get('entries', []))} entries"
        return False, _err_detail(code, body)

    r.check("GET /api/quarantine/list", _quarantine)

    def _audit() -> tuple[bool, str]:
        code, _, body = _request("GET", f"{r.url}/api/audit?limit=10", token=r.token)
        j = _json(body)
        if code == 200 and isinstance(j, list):
            return True, f"HTTP {code}  {len(j)} rows"
        return False, _err_detail(code, body)

    r.check("GET /api/audit", _audit)

    def _dlp() -> tuple[bool, str]:
        code, _, body = _request("GET", f"{r.url}/api/dlp/findings?limit=5", token=r.token)
        j = _json(body)
        if code == 200 and isinstance(j, list):
            return True, f"HTTP {code}  {len(j)} findings"
        return False, _err_detail(code, body)

    r.check("GET /api/dlp/findings", _dlp)

    def _watchdog() -> tuple[bool, str]:
        code, _, body = _request("GET", f"{r.url}/api/watchdog/status", token=r.token)
        j = _json(body) or {}
        if code == 200 and "available" in j:
            return True, f"HTTP {code}  available={j.get('available')}"
        return False, _err_detail(code, body)

    r.check("GET /api/watchdog/status", _watchdog)

    def _report() -> tuple[bool, str]:
        code, _, body = _request("GET", f"{r.url}/api/compliance/report?days=7", token=r.token)
        j = _json(body) or {}
        if code == 200 and "scans" in j and "detections" in j and "audit" in j:
            return True, f"HTTP {code}  scans={j.get('scans',{}).get('total')}"
        return False, _err_detail(code, body)

    r.check("GET /api/compliance/report", _report)

    def _relative_path_rejected() -> tuple[bool, str]:
        """Relative paths must always be refused — they're ambiguous regardless of mode."""
        code, _, body = _request(
            "POST",
            f"{r.url}/api/scanner/start",
            token=r.token,
            body={"path": "../etc/passwd"},
        )
        j = _json(body) or {}
        ok = code == 400 and j.get("error") == "path_outside_scan_root"
        return ok, f"HTTP {code}  error={j.get('error')}"

    r.check("reject relative path", _relative_path_rejected)

    def _restricted_mode_rejects_outsider() -> tuple[bool, str]:
        """In restricted mode, paths outside every allowed root must be refused.
        Skipped when the server is in permissive mode (no allow-list)."""
        ready_code, _, ready_body = _request("GET", f"{r.url}/readyz")
        ready = _json(ready_body) or {}
        scan_root_check = ready.get("checks", {}).get("scan_root", "")
        if "permissive" in scan_root_check:
            return True, "skipped — server in permissive mode"
        # Restricted — try an obviously outside path.
        outsider = "C:\\definitely\\not\\allowed" if os.name == "nt" else "/definitely/not/allowed"
        code, _, body = _request(
            "POST",
            f"{r.url}/api/scanner/start",
            token=r.token,
            body={"path": outsider},
        )
        j = _json(body) or {}
        return code == 400 and j.get("error") == "path_outside_scan_root", (
            f"HTTP {code}  error={j.get('error')}"
        )

    r.check("restricted-mode path guard", _restricted_mode_rejects_outsider)

    # -------------------- Optional live scan --------------------
    if args.full_scan:
        print("")
        print(f"{C.bold}Live scan{C.reset}")

        scan_root = _scan_root_from_env(env_path)
        if scan_root is None:
            r.check(
                "live scan",
                lambda: (False, ""),
                skip_reason="DEEPSEC_SCAN_ROOT not found in .env",
            )
            return r.summary()

        scan_root.mkdir(parents=True, exist_ok=True)
        test_file = scan_root / "smoke_test.txt"
        test_file.write_text("hello from the smoke test\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

        def _start_scan() -> tuple[bool, str]:
            code, _, body = _request(
                "POST",
                f"{r.url}/api/scanner/start",
                token=r.token,
                body={"path": str(scan_root), "quarantine": True},
            )
            j = _json(body) or {}
            ok = code in (202, 200) and j.get("status") == "started"
            return ok, f"HTTP {code}  path={j.get('path')}"

        r.check("POST /api/scanner/start", _start_scan)

        # Poll until done, up to 30 s.
        def _wait_for_completion() -> tuple[bool, str]:
            deadline = time.time() + 30
            while time.time() < deadline:
                code, _, body = _request("GET", f"{r.url}/api/scanner/status")
                j = _json(body) or {}
                if not j.get("running"):
                    return True, (
                        f"scanned={j.get('scanned_count')}  "
                        f"detections={j.get('total_detections')}"
                    )
                time.sleep(0.5)
            return False, "timed out after 30s"

        r.check("scan completes within 30s", _wait_for_completion)

        def _session_has_results() -> tuple[bool, str]:
            code, _, body = _request(
                "GET", f"{r.url}/api/scanner/sessions?limit=1", token=r.token
            )
            sessions = _json(body) or []
            if not sessions:
                return False, "no sessions"
            sid = sessions[0]["id"]
            code2, _, body2 = _request(
                "GET", f"{r.url}/api/scanner/results?session_id={sid}", token=r.token
            )
            results = _json(body2) or []
            return code2 == 200 and len(results) >= 1, (
                f"session {sid}  {len(results)} results"
            )

        r.check("session → results", _session_has_results)

        def _dlp_caught_the_key() -> tuple[bool, str]:
            code, _, body = _request(
                "GET", f"{r.url}/api/dlp/findings?limit=50", token=r.token
            )
            findings = _json(body) or []
            aws = [f for f in findings if f.get("pattern") == "aws_access_key_id"]
            return len(aws) >= 1, (
                f"{len(aws)} aws_access_key_id finding(s) out of {len(findings)} total"
            )

        r.check("DLP caught the planted AWS key", _dlp_caught_the_key)

    print("")
    return r.summary()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except urllib.error.URLError as e:
        print(f"\n{C.red}{C.bold}could not reach the server:{C.reset} {e}")
        print(f"  is it running? Start it with: {C.cyan}deepsec serve{C.reset}")
        sys.exit(2)
