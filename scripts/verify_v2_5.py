r"""End-to-end verification harness for the v2.5.0 release.

Run on the developer's Windows machine after the v2.5 changes land:

    py -3.12 .\.venv\Scripts\activate.bat
    pip install -r requirements-dev.txt
    pip install "deepsecurity[oidc]" "deepsecurity[redis]"
    python scripts\verify_v2_5.py

The script doesn't replace e2e_full.py — it just confirms the v2.5
changes are wired correctly before the user invokes the existing E2E.
Output is a Markdown report at logs/v2_5_verify_<timestamp>.md so the
green/red status is unambiguous.
"""

from __future__ import annotations

import importlib
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent.parent
LOG_DIR = HERE / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
STAMP = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
REPORT = LOG_DIR / f"v2_5_verify_{STAMP}.md"

# All stages append to this list; the final write builds the Markdown.
results: list[dict[str, Any]] = []


def _record(name: str, ok: bool, detail: str = "", **extra: Any) -> None:
    results.append({"name": name, "ok": ok, "detail": detail, **extra})


def _which(cmd: str) -> str | None:
    return shutil.which(cmd)


# --------------------------------------------------------------------------
# Stage A — environment sanity
# --------------------------------------------------------------------------


def stage_environment() -> None:
    # Accept everything from 3.11 (lowest pyproject `requires-python`) up
    # to 3.14 (which the README documents as working for core deps).
    py_ok = sys.version_info[:2] in {(3, 11), (3, 12), (3, 13), (3, 14)}
    _record(
        "A1 Python version supported",
        py_ok,
        detail=f"Python {sys.version.split()[0]}",
    )
    env_path = HERE / ".env"
    _record("A2 .env present", env_path.exists(), detail=str(env_path))


# --------------------------------------------------------------------------
# Stage B — module imports cleanly with the v2.5 wiring
# --------------------------------------------------------------------------


def stage_imports() -> None:
    # We need at least DEEPSEC_SECRET_KEY / JWT_SECRET to satisfy pydantic
    # validators. The harness reads from the user's .env via the standard
    # config.py path.
    sys.path.insert(0, str(HERE))
    os.environ.setdefault("DEEPSEC_ENV", "development")
    os.environ.setdefault("DEEPSEC_SECRET_KEY", "0123456789abcdef0123456789abcdef")
    os.environ.setdefault("DEEPSEC_JWT_SECRET", "fedcba9876543210fedcba9876543210")
    os.environ.setdefault("DEEPSEC_DEV_PASSWORD", "verify-only-dev-password")
    os.environ.setdefault("DEEPSEC_DATABASE_URL", "sqlite:///./data/verify_v2_5.db")
    os.environ.setdefault("DEEPSEC_WATCHDOG_AUTOSTART", "")
    os.environ.setdefault("DEEPSEC_STATE_BACKEND", "memory")

    for mod in [
        "deepsecurity.config",
        "deepsecurity.state_backend",
        "deepsecurity.scan_state",
        "deepsecurity.rate_limit",
        "deepsecurity.api",
        "deepsecurity.api.oidc",
        "deepsecurity.dlp",
    ]:
        try:
            importlib.import_module(mod)
            _record(f"B {mod}", True)
        except Exception as exc:
            _record(f"B {mod}", False, detail=f"{type(exc).__name__}: {exc}")


# --------------------------------------------------------------------------
# Stage C — state backend round-trip (memory + fakeredis)
# --------------------------------------------------------------------------


def stage_state_backend() -> None:
    from deepsecurity.state_backend import (
        InMemoryBackend,
        get_backend,
        reset_backend,
    )

    # In-memory smoke test
    b = InMemoryBackend()
    ok, _ = b.rate_allow("k", 3, 60.0)
    assert ok
    for _ in range(3):
        b.rate_allow("k", 3, 60.0)
    blocked, _ = b.rate_allow("k", 3, 60.0)
    assert not blocked
    assert b.scan_acquire(1) is True
    assert b.scan_acquire(2) is False
    b.scan_release()
    assert b.scan_acquire(2) is True
    _record("C1 InMemoryBackend round-trip", True)

    # Optional fakeredis path
    try:
        import fakeredis  # noqa: F401

        os.environ["DEEPSEC_STATE_BACKEND"] = "fake"
        from deepsecurity.config import get_settings

        get_settings.cache_clear()
        reset_backend()
        rb = get_backend()
        rb.scan_release()
        assert rb.scan_acquire(99, ttl_seconds=5) is True
        assert rb.scan_acquire(100, ttl_seconds=5) is False
        _record("C2 fakeredis-backed RedisBackend round-trip", True)
    except ImportError:
        _record(
            "C2 fakeredis-backed RedisBackend round-trip",
            True,
            detail="fakeredis not installed — install requirements-dev.txt; SKIPPING",
        )
    finally:
        os.environ["DEEPSEC_STATE_BACKEND"] = "memory"
        from deepsecurity.config import get_settings

        get_settings.cache_clear()
        from deepsecurity.state_backend import reset_backend

        reset_backend()


# --------------------------------------------------------------------------
# Stage D — OIDC blueprint mounts and returns 503 when disabled
# --------------------------------------------------------------------------


def stage_oidc_disabled_503() -> None:
    os.environ["DEEPSEC_OIDC_ENABLED"] = "false"
    from deepsecurity.config import get_settings

    get_settings.cache_clear()
    from deepsecurity.api import create_app

    app = create_app()
    c = app.test_client()
    r = c.get("/api/auth/oidc/login")
    _record(
        "D1 /api/auth/oidc/login returns 503 when OIDC disabled",
        r.status_code == 503,
        detail=f"got {r.status_code}",
    )


# --------------------------------------------------------------------------
# Stage E — production refuses dev-password login
# --------------------------------------------------------------------------


def stage_prod_refuses_dev_login() -> None:
    os.environ["DEEPSEC_ENV"] = "production"
    os.environ["DEEPSEC_DEV_PASSWORD"] = "must-be-set-but-must-not-be-tried"
    from deepsecurity.config import get_settings

    get_settings.cache_clear()
    from deepsecurity.api import create_app

    app = create_app()
    c = app.test_client()
    r = c.post("/api/auth/login", json={"username": "admin", "password": "x"})
    _record(
        "E1 /api/auth/login refused in production",
        r.status_code == 403,
        detail=f"got {r.status_code} {r.get_json()}",
    )
    os.environ["DEEPSEC_ENV"] = "development"
    get_settings.cache_clear()


# --------------------------------------------------------------------------
# Stage F — DLP credit_card pattern (Luhn-validated)
# --------------------------------------------------------------------------


def stage_dlp_credit_card() -> None:
    from deepsecurity.dlp import _luhn_valid, scan_text

    findings = scan_text("card: 4242 4242 4242 4242", "/x")
    has_cc = any(f.pattern_name == "credit_card" for f in findings)
    _record("F1 credit_card matches Luhn-valid Visa", has_cc)
    _record("F2 _luhn_valid('4242...') is True", _luhn_valid("4242424242424242"))
    findings = scan_text("rnd: 4111 1111 1111 1112", "/x")
    no_match = not any(f.pattern_name == "credit_card" for f in findings)
    _record("F3 credit_card REJECTS Luhn-invalid Visa shape", no_match)


# --------------------------------------------------------------------------
# Stage G — pytest unit + integration suite
# --------------------------------------------------------------------------


def stage_pytest() -> None:
    if _which("pytest") is None:
        _record(
            "G pytest -m 'not slow'",
            False,
            detail="pytest not on PATH — pip install -r requirements-dev.txt",
        )
        return
    log_path = LOG_DIR / f"v2_5_verify_{STAMP}_pytest.log"
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-m", "not slow", "--tb=short", "-rF"],
            cwd=HERE,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        _record("G pytest -m 'not slow'", False, detail="timeout after 10 min")
        return
    # Persist the FULL pytest output so failure modes are diagnosable
    # without re-running. The summary line goes into the harness report;
    # the per-test detail goes into the sibling log.
    log_path.write_text(
        f"# pytest output for verify run {STAMP}\n# rc={proc.returncode}\n\n"
        f"--- STDOUT ---\n{proc.stdout}\n\n--- STDERR ---\n{proc.stderr}\n",
        encoding="utf-8",
    )
    summary_line = ""
    if proc.stdout:
        for line in reversed(proc.stdout.splitlines()):
            if "passed" in line or "failed" in line or "error" in line:
                summary_line = line.strip()
                break
    # Extract the FAILED test names (one per line) for the report cell.
    failed = [
        ln.split(" ", 2)[1] if len(ln.split(" ", 2)) > 1 else ln
        for ln in proc.stdout.splitlines()
        if ln.startswith("FAILED ")
    ][:6]
    detail = summary_line
    if failed:
        detail += "  |  failures: " + "; ".join(failed)
    detail += f"  |  full log: {log_path.name}"
    _record(
        "G pytest -m 'not slow'",
        proc.returncode == 0,
        detail=detail,
        rc=proc.returncode,
    )


# --------------------------------------------------------------------------
# Stage H — alembic check
# --------------------------------------------------------------------------


def stage_alembic_check() -> None:
    if _which("alembic") is None:
        _record("H alembic check", False, detail="alembic not on PATH")
        return
    try:
        proc = subprocess.run(
            ["alembic", "history"],
            cwd=HERE,
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "DEEPSEC_DATABASE_URL": "sqlite:///./data/verify_v2_5.db"},
        )
    except subprocess.TimeoutExpired:
        _record("H alembic history", False, detail="timeout")
        return
    _record(
        "H alembic history",
        proc.returncode == 0,
        detail=proc.stdout.strip().splitlines()[-1] if proc.stdout else proc.stderr.strip()[:200],
    )


# --------------------------------------------------------------------------
# Stage I — ruff lint + format check
# --------------------------------------------------------------------------


def stage_ruff() -> None:
    if _which("ruff") is None:
        _record("I ruff check", False, detail="ruff not on PATH")
        return
    proc = subprocess.run(
        ["ruff", "check", "deepsecurity", "tests"],
        cwd=HERE,
        capture_output=True,
        text=True,
    )
    # Persist the full ruff output so the user can see WHICH rules fired
    # without re-running. ruff exits non-zero when there are any unfixed
    # findings — the summary line is the last line of stdout.
    log_path = LOG_DIR / f"v2_5_verify_{STAMP}_ruff.log"
    log_path.write_text(
        f"# ruff output for verify run {STAMP}\n# rc={proc.returncode}\n\n"
        f"--- STDOUT ---\n{proc.stdout}\n\n--- STDERR ---\n{proc.stderr}\n",
        encoding="utf-8",
    )
    summary = (proc.stdout.strip().splitlines() or ["clean"])[-1]
    _record(
        "I1 ruff check",
        proc.returncode == 0,
        detail=f"{summary}  |  full log: {log_path.name}",
    )


# --------------------------------------------------------------------------
# Report writer
# --------------------------------------------------------------------------


def write_report() -> None:
    ok = sum(1 for r in results if r["ok"])
    fail = len(results) - ok
    lines: list[str] = []
    lines.append(f"# v2.5.0 verification — {STAMP}")
    lines.append("")
    lines.append(f"- Total stages: {len(results)}")
    lines.append(f"- Pass: {ok}    Fail: {fail}")
    lines.append("")
    lines.append("| Stage | Result | Detail |")
    lines.append("|---|---|---|")
    for r in results:
        flag = "OK" if r["ok"] else "FAIL"
        detail = (r.get("detail") or "").replace("|", r"\|").replace("\n", " ")
        lines.append(f"| {r['name']} | {flag} | {detail[:200]} |")
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nReport written to: {REPORT}")
    print(f"Summary: {ok} pass / {fail} fail")


def main() -> int:
    print(f"DEEPSecurity v2.5.0 verification harness — {STAMP}")
    print(f"  HERE: {HERE}")
    print()

    stages = [
        ("Environment sanity", stage_environment),
        ("Module imports", stage_imports),
        ("State backend", stage_state_backend),
        ("OIDC disabled returns 503", stage_oidc_disabled_503),
        ("Production refuses dev login", stage_prod_refuses_dev_login),
        ("DLP credit_card", stage_dlp_credit_card),
        ("Alembic history", stage_alembic_check),
        ("ruff check", stage_ruff),
        ("pytest", stage_pytest),
    ]
    for label, fn in stages:
        print(f"  → {label} …", flush=True)
        try:
            fn()
        except Exception as exc:
            _record(f"{label} (crashed)", False, detail=f"{type(exc).__name__}: {exc}")

    write_report()
    fail = sum(1 for r in results if not r["ok"])
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
