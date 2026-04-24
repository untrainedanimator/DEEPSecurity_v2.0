"""Central configuration — the single source of truth.

All settings come from environment variables (loaded from `.env` in development).
Nothing is hardcoded. Nothing is read from ad-hoc JSON files. No secrets in source.

Usage:
    from deepsecurity.config import settings
    settings.jwt_secret  # raises if unset

Validation happens at startup; the app refuses to boot with a bad config.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings loaded from env vars prefixed DEEPSEC_."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="DEEPSEC_",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Core -----------------------------------------------------------
    env: Literal["development", "staging", "production"] = "development"
    secret_key: str = Field(min_length=16)
    jwt_secret: str = Field(min_length=16)
    jwt_access_minutes: int = Field(default=60, ge=1, le=1440)

    host: str = "127.0.0.1"
    port: int = Field(default=5000, ge=1, le=65535)

    # --- Security -------------------------------------------------------
    # Comma-separated list in env; parsed to a tuple of explicit origins.
    # "*" is explicitly forbidden.
    cors_origins: str = "http://localhost:5173"

    # --- Database -------------------------------------------------------
    database_url: str = "sqlite:///data/deepscan.db"

    # --- Scanner paths --------------------------------------------------
    # DEEPSEC_SCAN_ROOT is OPTIONAL. Leave empty for the default permissive
    # mode — any absolute path can be scanned. Set it only if you want to
    # lock the scanner down to a specific drive / folder list (useful when
    # deploying as a shared service where the authenticated caller is not
    # automatically trusted to pick the target). Semicolon- or comma-
    # separated list.
    scan_root: str = ""
    quarantine_dir: Path = Path("./quarantine")
    safelist_dir: Path = Path("./safelist")
    deleted_dir: Path = Path("./deleted")
    signature_path: Path = Path("./data/signatures.txt")

    # --- ML -------------------------------------------------------------
    ml_model_path: Path | None = None
    ml_confidence_threshold: float = Field(default=0.85, ge=0.0, le=1.0)

    # --- Outlook --------------------------------------------------------
    outlook_enabled: bool = False
    # A hard-locked default. We refuse to auto-delete email attachments.
    outlook_delete_on_detect: bool = False

    # --- Logging --------------------------------------------------------
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_json: bool = True

    # --- YARA -----------------------------------------------------------
    yara_rules_dir: Path | None = None

    # --- Watchdog (realtime) customisation -----------------------------
    # Auto-start the watchdog when the server boots. This is the one knob
    # that turns DEEPSecurity from "configure every restart" into "it just
    # works." Default: user_risk (Downloads, Desktop, Documents, %TEMP%,
    # Outlook cache) — the scope recommended by docs/WEDGE.md. Set to
    # "system" for whole-drive coverage (noisier). Set to "" to disable
    # and force manual start.
    watchdog_autostart: Literal["user_risk", "system", ""] = "user_risk"
    # Override the built-in "user_risk" preset with your own list of
    # semicolon- or comma-separated paths. Empty = use defaults
    # (Downloads, Desktop, Documents, Outlook cache, %TEMP%). See
    # docs/WEDGE.md for the rationale behind the default list.
    user_risk_paths: str = ""
    # Glob patterns that must NEVER be scanned, regardless of scope.
    # Semicolon- or comma-separated. Applies on top of any scope — even
    # if you explicitly point the watcher at a path, files matching these
    # globs are skipped. Default covers the common noise sources on a
    # dev workstation (IDE caches, Python venvs, node_modules, browser
    # caches, tool caches, OS cruft). Expand or replace if a specific
    # noise source is burning CPU in your environment.
    watch_exclude_globs: str = (
        # Dev-language tooling
        "**/node_modules/**;**/.venv/**;**/venv/**;**/.tox/**;"
        "**/.git/**;**/__pycache__/**;**/.pytest_cache/**;"
        "**/.mypy_cache/**;**/.ruff_cache/**;**/htmlcov/**;"
        "**/target/**;**/build/**;**/dist/**;**/.gradle/**;"
        # Pytest on Windows drops its DB fixtures under %TEMP%\pytest-of-*;
        # leaving that in scope causes the watchdog to open every test.db
        # mid-transaction and flag it ``suspicious`` on entropy, which races
        # with SQLite writes and destabilises the test run. Excluded.
        "**/pytest-of-*/**;**/pytest-*/**;"
        # IDE / editor
        "**/.idea/**;**/.vscode/**;**/.vs/**;**/.history/**;"
        # Browsers — Chrome/Edge/Brave write ridiculous amounts of cache
        "**/Code Cache/**;**/GPUCache/**;**/Cache_Data/**;"
        "**/Media Cache/**;**/Service Worker/**;**/blob_storage/**;"
        "**/IndexedDB/**;**/Local Storage/**;**/Session Storage/**;"
        # Package managers + language toolchains
        "**/pip/**;**/pip-*/**;**/.npm/**;**/yarn/**;**/.cargo/**;"
        "**/.rustup/**;**/go-build/**;**/.m2/**;"
        # Windows Temp subfolder noise (Claude, Teams, Zoom, Slack, …)
        "**/Temp/claude/**;**/Temp/claude-*/**;**/Temp/Anthropic/**;"
        "**/Temp/ClickOnce*/**;**/Temp/MsEdgeCrashpad/**;"
        "**/AppData/Local/Microsoft/Edge/**;"
        "**/AppData/Local/Google/Chrome/User Data/**;"
        "**/AppData/Local/Mozilla/Firefox/**;"
        "**/AppData/Local/Slack/**;**/AppData/Local/Microsoft/Teams/**;"
        "**/AppData/Roaming/Slack/Cache/**;"
        # File types that are almost always noise
        "**/*.pyc;**/*.pyo;**/*.pyd;**/*.class;**/*.o;**/*.obj;"
        "**/Thumbs.db;**/.DS_Store;**/desktop.ini;**/ntuser.dat*"
    )

    # --- DLP ------------------------------------------------------------
    dlp_enabled: bool = True
    dlp_max_bytes: int = 2 * 1024 * 1024

    # --- Threat intel feeds --------------------------------------------
    intel_malwarebazaar_enabled: bool = False

    # --- Alerts ---------------------------------------------------------
    slack_webhook_url: str | None = None
    alert_webhook_url: str | None = None
    syslog_host: str | None = None
    syslog_port: int = 514
    # --- SIEM (CEF over syslog) ----------------------------------------
    # Set cef_host (and optionally cef_port / cef_protocol) to forward every
    # alert as ArcSight-CEF-formatted syslog. Splunk / Elastic / Sentinel /
    # ArcSight / QRadar all auto-parse CEF into typed fields, so the
    # operator gets extractable attributes out of the box.
    cef_host: str | None = None
    cef_port: int = Field(default=514, ge=1, le=65535)
    cef_protocol: Literal["udp", "tcp"] = "udp"
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_starttls: bool = True
    alert_email_from: str | None = None
    alert_email_to: str | None = None

    # --- Rate limiting --------------------------------------------------
    rate_limit_anon_per_minute: int = Field(default=30, ge=1, le=10000)
    rate_limit_auth_per_minute: int = Field(default=120, ge=1, le=100000)
    max_request_bytes: int = Field(default=10 * 1024 * 1024, ge=1024)

    # --- Retention ------------------------------------------------------
    retention_days: int = Field(default=90, ge=1, le=3650)

    # --- Enforcement (user-space, honest) ------------------------------
    # Terminate processes flagged "known_bad" during a process scan.
    # Requires admin to kill other users' processes on Windows; on Unix,
    # you need to own the PID or be root. Off by default — we prefer
    # audit + alert over autonomous kill unless the operator opts in.
    auto_kill_known_bad: bool = False

    # --- Ransomware rate detector --------------------------------------
    # If a single PID writes more than this many files per second for
    # `ransomware_rate_window_seconds`, fire a critical alert. Set to 0
    # to disable the detector entirely.
    ransomware_rate_threshold: int = Field(default=50, ge=0, le=100000)
    ransomware_rate_window_seconds: float = Field(default=2.0, gt=0.0, le=60.0)
    ransomware_auto_kill: bool = False

    # --- IP reputation --------------------------------------------------
    ip_reputation_enabled: bool = True
    ip_reputation_path: Path = Path("./data/ip_reputation.txt")

    # --- Self-integrity -------------------------------------------------
    integrity_check_on_boot: bool = True
    integrity_snapshot_path: Path = Path("./data/.integrity.json")

    # --- Dev bootstrap user --------------------------------------------
    # Replace with your real IdP before exposing beyond localhost.
    dev_user: str = "admin"
    dev_password: str = ""
    dev_role: str = "admin"

    # --- Validators -----------------------------------------------------
    @field_validator("cors_origins", mode="after")
    @classmethod
    def _reject_wildcard_cors(cls, v: str) -> str:
        """Refuse to start with `*` CORS. It's the most common way this tool would get abused."""
        if v.strip() == "*" or "*" in [o.strip() for o in v.split(",")]:
            raise ValueError(
                "cors_origins may not contain '*' — list explicit origins "
                "(e.g. 'http://localhost:5173,https://deepsec.example')"
            )
        return v

    @field_validator("secret_key", "jwt_secret", mode="after")
    @classmethod
    def _reject_default_secrets(cls, v: str) -> str:
        forbidden = {
            "change-me-to-a-32-char-random-string",
            "change-me-to-another-32-char-random-string",
            "changeme",
            "secret",
            "password",
            "admin",
        }
        if v.lower() in forbidden:
            raise ValueError("refusing to start with a placeholder secret — set a real value")
        return v

    @field_validator("quarantine_dir", "safelist_dir", "deleted_dir", mode="after")
    @classmethod
    def _resolve_paths(cls, v: Path) -> Path:
        return v.resolve()

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def scan_roots(self) -> list[Path]:
        """Parsed list of allowed scan roots.

        Empty list → permissive mode: any absolute path is accepted. This
        is the default for personal / local use where the operator trusts
        themselves.

        Non-empty list → restricted mode: scan targets must resolve inside
        at least one of these roots. Useful for networked / shared
        deployments. Accepts a comma- or semicolon-separated list so
        Windows paths survive.
        """
        raw = self.scan_root or ""
        for sep in (";", ","):
            if sep in raw:
                parts = raw.split(sep)
                break
        else:
            parts = [raw]
        return [Path(p.strip()).expanduser().resolve() for p in parts if p.strip()]

    @property
    def restricted_paths(self) -> bool:
        """True if an allow-list is configured."""
        return bool(self.scan_roots)

    @property
    def debug(self) -> bool:
        return self.env == "development"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton (cached)."""
    return Settings()  # type: ignore[call-arg]


class _SettingsProxy:
    """Lazy attribute proxy for the settings singleton.

    Modules across the codebase do ``from deepsecurity.config import settings``
    at import time. Without a proxy, each of those imports captures a *direct*
    reference to whatever ``get_settings()`` returned on first evaluation.
    Tests that monkeypatch env vars then call ``get_settings.cache_clear()``,
    but the 20 already-captured references still point at the stale Settings
    instance, silently re-using the developer's real ``.env`` database,
    quarantine dir, data dir, etc. That causes schema drift and "file not
    found" flakiness in the test suite.

    Routing every attribute access through ``get_settings()`` fixes that:
    the lru_cache is the single source of truth, and clearing it in a
    fixture is enough to switch every caller to the new values.
    """

    __slots__ = ()

    def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
        return getattr(get_settings(), name)

    def __setattr__(self, name: str, value) -> None:  # type: ignore[no-untyped-def]
        # Allow test monkeypatches — they target the live singleton, which is
        # what callers read through us anyway.
        setattr(get_settings(), name, value)

    def __repr__(self) -> str:
        return f"<SettingsProxy -> {get_settings()!r}>"


# Convenience export — import this in application code.
# The actual load happens on first access. Tests can override via
# ``get_settings.cache_clear()`` after setting env vars (see tests/conftest.py).
settings: Settings = _SettingsProxy()  # type: ignore[assignment]
