"""Command-line interface.

Usage:
    deepsec init-env        # generate .env with real random secrets (run first!)
    deepsec init-db
    deepsec serve
    deepsec scan /path/to/dir
    deepsec signature-hash /path/to/file
    deepsec intel-update
    deepsec report --days 30
    deepsec purge --days 90
    deepsec watchdog start|stop|status

Config import is lazy: every command that needs settings imports them
inside the function body, so `deepsec init-env` and `--help` work even if
the current environment would fail validation.
"""
from __future__ import annotations

import secrets
import sys
from pathlib import Path

import click


@click.group()
@click.version_option("2.2.0", prog_name="deepsec")
def main() -> None:
    """DEEPSecurity — a safe, local malware scanner."""
    from deepsecurity.logging_config import configure_logging

    # Only configure logging once we're running — some commands bypass it.
    try:
        configure_logging()
    except Exception:
        # Don't let a bad env block `deepsec init-env`.
        pass


# ---------------------------------------------------------------------------
# init-env — bootstrap a working .env from .env.example
# ---------------------------------------------------------------------------


_PLACEHOLDERS = {
    "DEEPSEC_SECRET_KEY": "change-me-to-a-32-char-random-string",
    "DEEPSEC_JWT_SECRET": "change-me-to-another-32-char-random-string",
}


@main.command("init-env")
@click.option(
    "--output",
    default=".env",
    show_default=True,
    type=click.Path(dir_okay=False),
    help="Target .env path.",
)
@click.option(
    "--template",
    default=".env.example",
    show_default=True,
    type=click.Path(dir_okay=False),
    help="Source template.",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite an existing .env (otherwise refuses to clobber).",
)
@click.option(
    "--password",
    default=None,
    help="Dev-user password. Prompts if omitted.",
)
def init_env_cmd(output: str, template: str, force: bool, password: str | None) -> None:
    """Generate a working .env with real random secrets.

    Replaces the DEEPSEC_SECRET_KEY and DEEPSEC_JWT_SECRET placeholders with
    64-char hex strings generated from secrets.token_hex(32). Fills in
    DEEPSEC_DEV_PASSWORD too (prompts if not supplied).
    """
    tpl = Path(template)
    dst = Path(output)

    if not tpl.exists():
        click.echo(f"template not found: {tpl}", err=True)
        sys.exit(1)
    if dst.exists() and not force:
        click.echo(
            f"{dst} already exists. Re-run with --force to overwrite, or edit the file by hand.",
            err=True,
        )
        sys.exit(1)

    if password is None:
        password = click.prompt(
            "dev-user password (used to log in via /api/auth/login)",
            hide_input=True,
            confirmation_prompt=True,
        )

    replacements = {
        **_PLACEHOLDERS,
        "DEEPSEC_DEV_PASSWORD": "",
    }
    generated = {
        "DEEPSEC_SECRET_KEY": secrets.token_hex(32),
        "DEEPSEC_JWT_SECRET": secrets.token_hex(32),
        "DEEPSEC_DEV_PASSWORD": password,
    }

    lines_out: list[str] = []
    for raw in tpl.read_text(encoding="utf-8").splitlines():
        rewrote = False
        stripped = raw.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key, _, value = stripped.partition("=")
            key = key.strip()
            value = value.strip()
            if key in replacements and (value == replacements[key] or value == ""):
                lines_out.append(f"{key}={generated[key]}")
                rewrote = True
        if not rewrote:
            lines_out.append(raw)

    dst.write_text("\n".join(lines_out) + "\n", encoding="utf-8")
    click.echo(f"wrote {dst}")
    click.echo("  DEEPSEC_SECRET_KEY: generated (64 hex chars)")
    click.echo("  DEEPSEC_JWT_SECRET: generated (64 hex chars)")
    click.echo("  DEEPSEC_DEV_PASSWORD: set from prompt")
    click.echo("")
    click.echo("Next: edit DEEPSEC_SCAN_ROOT in .env, then run `deepsec init-db`.")


# ---------------------------------------------------------------------------
# init-db
# ---------------------------------------------------------------------------


@main.command("init-db")
def init_db_cmd() -> None:
    """Create database tables if absent.

    SAFE. Never drops or alters existing tables.
    If your DB is from a previous schema version, use `deepsec reset-db`.
    """
    from deepsecurity.config import settings
    from deepsecurity.db import init_db
    from deepsecurity.secret_masking import mask_database_url

    init_db()
    click.echo(f"database ready: {mask_database_url(settings.database_url)}")

    # Probe for schema drift and warn — cheap, catches the most common upgrade pitfall.
    try:
        from sqlalchemy import inspect

        from deepsecurity.db import get_engine
        from deepsecurity.models import Base

        insp = inspect(get_engine())
        drift: list[str] = []
        for table_name, table in Base.metadata.tables.items():
            if not insp.has_table(table_name):
                continue
            existing = {c["name"] for c in insp.get_columns(table_name)}
            expected = set(table.columns.keys())
            missing = expected - existing
            if missing:
                drift.append(f"  {table_name}: missing columns {sorted(missing)}")
        if drift:
            click.echo(
                click.style(
                    "\nSCHEMA DRIFT DETECTED — tables exist but are missing columns:",
                    fg="yellow",
                )
            )
            for d in drift:
                click.echo(click.style(d, fg="yellow"))
            click.echo(
                click.style(
                    "\nYour DB predates the current models. Run `deepsec reset-db` "
                    "to drop and recreate (destroys existing rows).",
                    fg="yellow",
                )
            )
    except Exception:
        # Inspection is a best-effort nicety — never fail init-db over it.
        pass


@main.command("reset-db")
@click.option(
    "--yes",
    is_flag=True,
    help="Skip the confirmation prompt.",
)
def reset_db_cmd(yes: bool) -> None:
    """DROP every table and recreate from current models. Destroys data.

    Use when `init-db` reports schema drift after an upgrade, or when you
    want to wipe scan history and start clean.
    """
    from deepsecurity.config import settings
    from deepsecurity.db import get_engine
    from deepsecurity.models import Base
    from deepsecurity.secret_masking import mask_database_url

    click.echo(f"target database: {mask_database_url(settings.database_url)}")
    if not yes:
        click.confirm(
            "This will DROP every deepsecurity table and recreate it. Continue?",
            abort=True,
        )
    engine = get_engine()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    click.echo("database reset: all tables dropped and recreated.")


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@main.command("scan")
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
@click.option("--actor", default="cli", show_default=True)
@click.option("--role", default="admin", show_default=True)
@click.option("--no-quarantine", is_flag=True, help="Skip copying detections to quarantine.")
def scan_cmd(directory: str, actor: str, role: str, no_quarantine: bool) -> None:
    """Scan DIRECTORY. Must be inside DEEPSEC_SCAN_ROOT."""
    from deepsecurity.db import init_db
    from deepsecurity.scanner import scan_directory

    init_db()
    summary = scan_directory(
        directory,
        actor=actor,
        user_role=role,
        quarantine_enabled=not no_quarantine,
    )
    click.echo(
        f"session={summary['session_id']}  "
        f"files={summary['total_files']}  "
        f"detections={summary['total_detections']}"
    )


# ---------------------------------------------------------------------------
# signature-hash — useful before any config exists
# ---------------------------------------------------------------------------


@main.command("signature-hash")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
def signature_hash_cmd(path: str) -> None:
    """Print SHA-256 for PATH (for pasting into a signature list)."""
    # Import lazily so it works before config is valid.
    from deepsecurity.scanner import compute_sha256

    click.echo(compute_sha256(Path(path)))


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------


@main.command("serve")
@click.option("--host", default=None, help="Override DEEPSEC_HOST")
@click.option("--port", type=int, default=None, help="Override DEEPSEC_PORT")
def serve_cmd(host: str | None, port: int | None) -> None:
    """Run the Flask dev server. For production, use gunicorn (see Makefile)."""
    from deepsecurity.api import create_app
    from deepsecurity.config import settings
    from deepsecurity.db import init_db
    from deepsecurity.logging_config import get_logger

    init_db()
    app = create_app()
    log = get_logger(__name__)
    bind_host = host or settings.host
    bind_port = port or settings.port
    log.info("serve.start", host=bind_host, port=bind_port)
    app.run(host=bind_host, port=bind_port, debug=settings.debug)


# ---------------------------------------------------------------------------
# intel-update
# ---------------------------------------------------------------------------


@main.command("intel-update")
def intel_update_cmd() -> None:
    """Pull every configured threat-intel feed into the signature file."""
    from deepsecurity.threat_intel import update_all_feeds

    for res in update_all_feeds():
        status = f"error: {res.error}" if res.error else f"added {res.added}"
        click.echo(f"{res.name}: fetched={res.fetched}  {status}")


# ---------------------------------------------------------------------------
# purge
# ---------------------------------------------------------------------------


@main.command("purge")
@click.option("--days", type=int, default=None, help="Override DEEPSEC_RETENTION_DAYS")
def purge_cmd(days: int | None) -> None:
    """Enforce the retention policy: delete audit / results older than --days."""
    from deepsecurity.compliance import purge_older_than
    from deepsecurity.config import settings

    effective = days if days is not None else settings.retention_days
    counts = purge_older_than(effective)
    click.echo(
        f"purged (> {effective} days): "
        f"audit={counts['audit_deleted']} "
        f"results={counts['results_deleted']} "
        f"sessions={counts['sessions_deleted']}"
    )


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


@main.command("report")
@click.option("--days", type=int, default=30, help="Window in days (default 30)")
def report_cmd(days: int) -> None:
    """Print a compliance report for the last N days as JSON."""
    import json

    from deepsecurity.compliance import DateWindow, generate_report

    rep = generate_report(DateWindow.last_days(days))
    if rep.get("retention", {}).get("oldest_event"):
        rep["retention"]["oldest_event"] = rep["retention"]["oldest_event"].isoformat()
    click.echo(json.dumps(rep, indent=2, default=str))


# ---------------------------------------------------------------------------
# watchdog
# ---------------------------------------------------------------------------


@main.command("self-test")
@click.option("--url", default=None, help="Target server URL (default: use DEEPSEC_HOST/PORT).")
@click.option("--password", default=None, help="Admin password (default: read .env).")
@click.option("--full-scan", is_flag=True, help="Also run a live scan against scan_root.")
@click.option("--verbose", "-v", is_flag=True, help="Show full response bodies on failure.")
def self_test_cmd(
    url: str | None, password: str | None, full_scan: bool, verbose: bool
) -> None:
    """Run the end-to-end smoke test against a running server."""
    import runpy

    from deepsecurity.config import settings

    target_url = url or f"http://{settings.host}:{settings.port}"
    argv = ["scripts/smoke.py", "--url", target_url]
    if password:
        argv += ["--password", password]
    if full_scan:
        argv.append("--full-scan")
    if verbose:
        argv.append("--verbose")

    sys.argv = argv
    script_path = Path(__file__).resolve().parent.parent / "scripts" / "smoke.py"
    try:
        runpy.run_path(str(script_path), run_name="__main__")
    except SystemExit as e:
        sys.exit(e.code)


@main.command("test-loop")
@click.option("--once", is_flag=True, help="Run one pass and exit (good for CI).")
@click.option("--watch", is_flag=True, help="Re-run on source changes (needs `watchdog`).")
@click.option("--interval", type=float, default=300.0, show_default=True,
              help="Seconds between timed loop runs.")
@click.option("--no-smoke", is_flag=True, help="Skip the live-HTTP smoke phase.")
@click.option("--url", default=None, help="Server URL for the smoke phase.")
@click.option("--password", default=None, help="Admin password for the smoke phase.")
def test_loop_cmd(
    once: bool,
    watch: bool,
    interval: float,
    no_smoke: bool,
    url: str | None,
    password: str | None,
) -> None:
    """Continuously run all tests (pytest + e2e + live smoke)."""
    import runpy

    from deepsecurity.config import settings

    target_url = url or f"http://{settings.host}:{settings.port}"
    argv = ["scripts/continuous_tests.py", "--url", target_url, "--interval", str(interval)]
    if once:
        argv.append("--once")
    if watch:
        argv.append("--watch")
    if no_smoke:
        argv.append("--no-smoke")
    if password:
        argv += ["--password", password]

    sys.argv = argv
    script_path = Path(__file__).resolve().parent.parent / "scripts" / "continuous_tests.py"
    try:
        runpy.run_path(str(script_path), run_name="__main__")
    except SystemExit as e:
        sys.exit(e.code)


@main.command("integrity")
@click.argument("action", type=click.Choice(["snapshot", "check"]))
def integrity_cmd(action: str) -> None:
    """Self-integrity — snapshot the package hash set, or check against it."""
    import json as _json

    from deepsecurity.integrity import check, report_as_dict, snapshot

    if action == "snapshot":
        r = snapshot()
    else:
        r = check()
    click.echo(_json.dumps(report_as_dict(r), indent=2))


@main.command("kill-pid")
@click.argument("pid", type=int)
@click.option("--reason", required=True, help="Recorded in the audit log.")
@click.option("--force", is_flag=True, help="SIGKILL / kill instead of terminate.")
def kill_pid_cmd(pid: int, reason: str, force: bool) -> None:
    """Terminate a process by PID. Audit-logged."""
    import json as _json

    from deepsecurity.audit import audit_log
    from deepsecurity.processes import kill_process

    result = kill_process(pid, force=force)
    audit_log(
        actor="cli",
        action="process.kill",
        status="ok" if result.get("killed") else "failed",
        details={"pid": pid, "reason": reason, "force": force, "result": result},
    )
    click.echo(_json.dumps(result, indent=2))


@main.command("watchdog")
@click.argument("action", type=click.Choice(["start", "stop", "status"]))
@click.option(
    "--path",
    "paths",
    multiple=True,
    help="Path(s) to watch (repeatable). Only applies to start.",
)
@click.option(
    "--scope",
    type=click.Choice(["user_risk", "system"]),
    default=None,
    help=(
        "Shortcut: 'user_risk' = Downloads + Desktop + Documents + Outlook "
        "cache + %TEMP% (recommended). 'system' = every drive / every common "
        "user path (broad but noisy)."
    ),
)
@click.option(
    "--password",
    default=None,
    help="Admin password. Defaults to DEEPSEC_DEV_PASSWORD from env/.env.",
)
@click.option(
    "--url",
    default=None,
    help="Backend URL (default: http://DEEPSEC_HOST:DEEPSEC_PORT).",
)
def watchdog_cmd(
    action: str,
    paths: tuple[str, ...],
    scope: str | None,
    password: str | None,
    url: str | None,
) -> None:
    """Start / stop / check the real-time file-system watchdog.

    Talks to the backend over HTTP so you see the same state the dashboard
    does — the watchdog runs in the backend's Python process; a separate
    CLI process would have its own (empty) controller. If the backend
    isn't running you'll get a clear connection error instead.
    """
    import json
    import os as _os
    import urllib.error
    import urllib.request
    from pathlib import Path as _Path

    from deepsecurity.config import settings

    base = (url or f"http://{settings.host}:{settings.port}").rstrip("/")

    # Resolve admin password — env, CLI flag, or .env fallback.
    pw = password or _os.environ.get("DEEPSEC_DEV_PASSWORD") or ""
    if not pw:
        env_path = _Path(__file__).resolve().parent.parent / ".env"
        if env_path.exists():
            for line in env_path.read_text(encoding="utf-8").splitlines():
                if line.startswith("DEEPSEC_DEV_PASSWORD="):
                    pw = line.split("=", 1)[1].strip().strip('"').strip("'")
                    break

    def _post(path: str, body: dict, auth: str | None) -> dict:
        req = urllib.request.Request(
            base + path,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        if auth:
            req.add_header("Authorization", f"Bearer {auth}")
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode("utf-8"))

    def _get(path: str, auth: str | None) -> dict:
        req = urllib.request.Request(base + path, method="GET")
        if auth:
            req.add_header("Authorization", f"Bearer {auth}")
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read().decode("utf-8"))

    # Login (every watchdog route is auth-gated).
    try:
        login = _post(
            "/api/auth/login",
            {"username": "admin", "password": pw},
            auth=None,
        )
    except urllib.error.URLError as exc:
        click.echo(
            f"cannot reach backend at {base}: {exc.reason}\n"
            f"  tip: is ``deepsecurity start`` running?",
            err=True,
        )
        sys.exit(1)
    token = login.get("access_token")
    if not token:
        click.echo(
            f"login rejected — bad password? set DEEPSEC_DEV_PASSWORD or pass --password",
            err=True,
        )
        sys.exit(1)

    try:
        if action == "status":
            out = _get("/api/watchdog/status", token)
        elif action == "stop":
            out = _post("/api/watchdog/stop", {}, token)
        else:  # start
            body: dict = {}
            if scope:
                body["scope"] = scope
            if paths:
                body["paths"] = list(paths)
            out = _post("/api/watchdog/start", body, token)
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8"))
        except Exception:
            payload = {"error": str(exc)}
        click.echo(json.dumps(payload, indent=2), err=True)
        sys.exit(1)

    click.echo(json.dumps(out, indent=2))


# ---------------------------------------------------------------------------
# Lifecycle — start / stop / status / clean / test
#
# These are the "day-to-day" commands. They wrap ``deepsecurity/lifecycle.py``
# so ``deepsecurity start`` etc. all work from a single top-level CLI.
# ---------------------------------------------------------------------------


@main.command("start")
@click.option("--host", default=None, help="Override DEEPSEC_HOST (backend bind host).")
@click.option("--port", type=int, default=None, help="Override DEEPSEC_PORT (backend).")
@click.option(
    "--frontend-port",
    type=int,
    default=5173,
    show_default=True,
    help="Port for the Vite frontend dev server.",
)
@click.option(
    "--foreground",
    "-f",
    is_flag=True,
    help="Run the backend inline in this terminal (no frontend, no browser).",
)
@click.option(
    "--no-frontend",
    is_flag=True,
    help="Start only the backend; skip Vite and the browser.",
)
@click.option(
    "--no-browser",
    is_flag=True,
    help="Don't auto-open the dashboard in the default browser.",
)
@click.option(
    "--timeout",
    type=float,
    default=30.0,
    show_default=True,
    help="Seconds to wait for the backend /healthz before giving up.",
)
def start_cmd(
    host: str | None,
    port: int | None,
    frontend_port: int,
    foreground: bool,
    no_frontend: bool,
    no_browser: bool,
    timeout: float,
) -> None:
    """Start DEEPSecurity: DB → backend → frontend → open browser.

    Default mode: brings the backend up (the DB is created on first boot),
    starts the Vite frontend, waits for both to report ready, then opens
    the dashboard in your default browser. Writes a PID file so
    ``deepsecurity stop`` / ``deepsecurity status`` know what's running.

    Flags:
        --foreground     backend only, inline, no frontend, no browser
        --no-frontend    backend only (detached), no frontend, no browser
        --no-browser     start both but don't auto-open
    """
    from deepsecurity import lifecycle

    pre = lifecycle.status()
    # If everything we wanted is already up, don't re-spawn — just report
    # and (optionally) re-open the browser.
    want_frontend = not foreground and not no_frontend
    want_browser = not foreground and not no_browser

    all_wanted_up = (
        pre.backend.running
        and (not want_frontend or pre.frontend.running)
    )
    if all_wanted_up and not foreground:
        click.echo("already running:")
        _print_component("backend ", pre.backend)
        _print_component("frontend", pre.frontend)
        if want_browser:
            import webbrowser

            target = (
                pre.frontend.url if pre.frontend.http_up else pre.backend.url
            )
            try:
                webbrowser.open_new_tab(target)
                click.echo(f"  opened:  {target}")
            except Exception:
                pass
        else:
            click.echo(
                f"  pidfile: {pre.pidfile}\n"
                f"  tip: ``deepsecurity stop`` to stop, ``deepsecurity status`` to recheck"
            )
        return

    try:
        st = lifecycle.start(
            host=host,
            port=port,
            foreground=foreground,
            ready_timeout=timeout,
            backend=True,
            frontend=want_frontend,
            frontend_port=frontend_port,
            open_browser=want_browser,
        )
    except RuntimeError as exc:
        click.echo(f"start failed: {exc}", err=True)
        sys.exit(1)

    if foreground:
        click.echo("server exited")
        return

    click.echo("started:")
    _print_component("backend ", st.backend)
    _print_component("frontend", st.frontend)
    click.echo(f"  pidfile: {st.pidfile}")
    if st.frontend.http_up and want_browser:
        click.echo(f"  opened:  {st.frontend.url}")


def _print_component(label: str, c) -> None:  # type: ignore[no-untyped-def]
    """Helper: one-line status of a ComponentStatus."""
    from deepsecurity import lifecycle  # noqa: F401 — type hint source

    if c.http_up and c.pid_alive:
        state = "up (healthy)"
    elif c.http_up:
        state = "up (not owned by us)"
    elif c.pid_alive:
        state = "starting / unhealthy"
    else:
        state = "down"
    click.echo(
        f"  {label}  {state:<22}  pid={c.pid if c.pid else '-':<8}  url={c.url}"
    )


@main.command("stop")
@click.option(
    "--timeout",
    type=float,
    default=10.0,
    show_default=True,
    help="Seconds to wait for graceful shutdown before force-kill.",
)
def stop_cmd(timeout: float) -> None:
    """Stop DEEPSecurity (backend + frontend)."""
    from deepsecurity import lifecycle

    pre = lifecycle.status()
    if not pre.running:
        click.echo("nothing to stop — server is not running")
        return

    result = lifecycle.stop(timeout=timeout)
    any_stopped = any(result.values())
    if any_stopped:
        click.echo("stopped:")
        for name, stopped in result.items():
            click.echo(f"  {name}: {'killed' if stopped else 'no-op'}")
    else:
        click.echo("stop completed — nothing was owned by our pidfile")


@main.command("status")
def status_cmd() -> None:
    """Show status of both backend and frontend."""
    from deepsecurity import lifecycle

    st = lifecycle.status()
    click.echo("DEEPSecurity status:")
    _print_component("backend ", st.backend)
    _print_component("frontend", st.frontend)
    click.echo(
        f"  pidfile:      {st.pidfile}\n"
        f"  backend log:  {st.server_log}\n"
        f"  frontend log: {st.frontend_log}"
    )
    if not st.running:
        click.echo("\n  → nothing running. ``deepsecurity start`` to launch.")


@main.command("clean")
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="Skip the confirmation prompt.",
)
@click.option(
    "--keep-logs",
    is_flag=True,
    help="Don't delete logs/.",
)
@click.option(
    "--keep-db",
    is_flag=True,
    help="Don't delete the SQLite DB file.",
)
@click.option(
    "--also-safelist",
    is_flag=True,
    help="ALSO delete the operator-curated safelist (off by default — keep it).",
)
def clean_cmd(yes: bool, keep_logs: bool, keep_db: bool, also_safelist: bool) -> None:
    """Stop the server and delete throwaway state (DB, quarantine, logs, caches).

    Preserves the safelist by default — pass ``--also-safelist`` to include
    it. Always stops the server first if it's running.
    """
    from deepsecurity import lifecycle

    plan = lifecycle.build_clean_plan(
        logs=not keep_logs,
        database=not keep_db,
        safelist=also_safelist,
    )

    if not plan.anything_to_do:
        click.echo("nothing to clean")
        return

    click.echo("clean plan:")
    if plan.stop_server:
        click.echo("  - stop running server")
    for p in plan.paths:
        click.echo(f"  - delete {p}")

    if not yes:
        if not click.confirm("\nproceed?", default=False):
            click.echo("aborted")
            sys.exit(1)

    counts = lifecycle.execute_clean_plan(plan)
    click.echo(
        f"done  stopped={counts['stopped']}  removed={counts['removed']}  "
        f"failed={counts['failed']}"
    )


@main.command("test")
@click.option(
    "--once/--loop",
    default=True,
    show_default=True,
    help="One pass and exit (default) or run the continuous 5-minute loop.",
)
@click.option(
    "--interval",
    type=float,
    default=300.0,
    show_default=True,
    help="Seconds between loops (only relevant with --loop).",
)
@click.option(
    "--no-smoke",
    is_flag=True,
    help="Skip the live-HTTP smoke phase (e.g. when running offline).",
)
@click.option(
    "--no-autostart",
    is_flag=True,
    help="Don't autostart the Flask server for the smoke phase.",
)
@click.option("--url", default=None, help="Server URL for the smoke phase.")
@click.option("--password", default=None, help="Admin password for the smoke phase.")
def test_cmd(
    once: bool,
    interval: float,
    no_smoke: bool,
    no_autostart: bool,
    url: str | None,
    password: str | None,
) -> None:
    """Run the full test suite (pytest + e2e + live smoke).

    Thin wrapper around ``scripts/continuous_tests.py`` so you don't have
    to remember the path. ``--once`` is the default — one pass, exit with
    the result code. ``--loop`` runs forever.
    """
    import runpy

    from deepsecurity.config import settings

    target_url = url or f"http://{settings.host}:{settings.port}"
    argv = [
        "scripts/continuous_tests.py",
        "--url",
        target_url,
        "--interval",
        str(interval),
    ]
    if once:
        argv.append("--once")
    if no_smoke:
        argv.append("--no-smoke")
    if no_autostart:
        argv.append("--no-autostart")
    if password:
        argv += ["--password", password]

    sys.argv = argv
    script_path = Path(__file__).resolve().parent.parent / "scripts" / "continuous_tests.py"
    try:
        runpy.run_path(str(script_path), run_name="__main__")
    except SystemExit as e:
        sys.exit(e.code)


if __name__ == "__main__":
    sys.exit(main())
