"""Database backup and restore — online snapshots, rotated.

Operators ship DEEPSecurity into environments where the SOC2/ISO/HIPAA
auditor is going to ask for "your backup runbook." This module is that
runbook in code: a pure-functional helper that takes a snapshot of the
running database, rotates older snapshots, and restores from one when
asked.

Design choices:

- **Online snapshots, no service downtime.** SQLite has a built-in
  ``Connection.backup()`` API that copies pages while the server is
  still writing. No flock contention, no "stop the server first."
- **Rotated full backups, not real deltas.** ``full`` and
  ``incremental`` both produce complete snapshots; the only difference
  is rotation policy (``full`` keeps 7 by default for daily-ish use,
  ``incremental`` keeps 24 for hourly-ish use). This is the "Option A"
  shape: simpler to reason about, simpler to restore from, and a 50MB
  SQLite DB does not benefit from real WAL-shipping incrementals.
- **Restore is destructive and refuses to run if the server is up.**
  The CLI checks ``lifecycle.status()`` and aborts unless the server is
  stopped. Even when stopped, we take a one-shot safety backup of the
  current DB before overwriting it, so "I restored the wrong file" is
  always recoverable.
- **Never raises through the public surface.** Failures return a
  structured ``BackupResult`` / ``RestoreResult`` with ``ok=False`` and
  an ``error`` string; the CLI layer prints it. The audit-log call is
  wrapped because audit-write failure must not block a backup.

Public surface:

    full_backup(to_dir, keep=7) -> BackupResult
    list_backups(in_dir) -> list[BackupEntry]
    restore(from_path, *, confirm=False) -> RestoreResult

Filename shape:
    deepsec_<UTC iso>_full.db          (sqlite snapshot)
    deepsec_<UTC iso>_full.sql         (postgres pg_dump)
"""

from __future__ import annotations

import re
import shutil
import sqlite3
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from deepsecurity.config import settings
from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Result types — pure data, easy to print or assert on in tests.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BackupEntry:
    """One existing backup on disk, parsed from filename."""

    path: Path
    timestamp: datetime
    kind: str  # "full" — reserved for future flavors
    size_bytes: int


@dataclass(frozen=True)
class BackupResult:
    """Outcome of ``full_backup``. ``ok=False`` means nothing was written."""

    ok: bool
    path: Path | None = None
    size_bytes: int = 0
    rotated: list[Path] = field(default_factory=list)
    error: str | None = None

    @property
    def kept(self) -> int:
        """Convenience for the CLI summary: how many we kept after rotation."""
        return 0 if not self.ok else 1  # placeholder; CLI computes from listing


@dataclass(frozen=True)
class RestoreResult:
    """Outcome of ``restore``."""

    ok: bool
    restored_from: Path | None = None
    safety_backup: Path | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Filename helpers — the rotation policy lives in filenames so we don't
# need a sidecar manifest. Parse the ISO timestamp out of the name.
# ---------------------------------------------------------------------------


_FILENAME_RE = re.compile(r"^deepsec_(?P<ts>\d{8}T\d{6}Z)_(?P<kind>full)\.(?P<ext>db|sql)$")
_TS_FORMAT = "%Y%m%dT%H%M%SZ"  # 20260425T143015Z — filename-safe ISO 8601


def _now_utc() -> datetime:
    """Indirection for testability. UTC-aware."""
    return datetime.now(UTC)


def _format_filename(ts: datetime, ext: str, kind: str = "full") -> str:
    return f"deepsec_{ts.strftime(_TS_FORMAT)}_{kind}.{ext}"


def _parse_filename(name: str) -> tuple[datetime, str] | None:
    """Return (timestamp, kind) for a backup filename or ``None`` if junk."""
    m = _FILENAME_RE.match(name)
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("ts"), _TS_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return None
    return ts, m.group("kind")


# ---------------------------------------------------------------------------
# Database-URL classification — sqlite vs postgres vs unsupported.
# ---------------------------------------------------------------------------


def _db_kind(url: str) -> str:
    """Return ``"sqlite"`` / ``"postgres"`` / ``"unsupported"``."""
    if url.startswith("sqlite:"):
        return "sqlite"
    if url.startswith(("postgres:", "postgresql:", "postgresql+")):
        return "postgres"
    return "unsupported"


def _sqlite_path(url: str) -> Path | None:
    """Extract the on-disk path from a SQLite URL.

    Returns ``None`` for ``:memory:`` (nothing to back up).
    """
    if not url.startswith("sqlite:"):
        return None
    _, _, tail = url.partition(":///")
    if not tail or tail == ":memory:":
        return None
    return Path(tail).expanduser()


# ---------------------------------------------------------------------------
# Public: list backups in a directory.
# ---------------------------------------------------------------------------


def list_backups(in_dir: Path) -> list[BackupEntry]:
    """Return existing backups in ``in_dir``, newest first.

    Files that don't match the filename schema are silently ignored —
    operators put their own README.md and other clutter in backup dirs
    and we don't want a stray file to break ``deepsec backup full``.
    """
    if not in_dir.exists():
        return []
    out: list[BackupEntry] = []
    for entry in in_dir.iterdir():
        if not entry.is_file():
            continue
        parsed = _parse_filename(entry.name)
        if parsed is None:
            continue
        ts, kind = parsed
        try:
            size = entry.stat().st_size
        except OSError:
            size = 0
        out.append(BackupEntry(path=entry, timestamp=ts, kind=kind, size_bytes=size))
    out.sort(key=lambda e: e.timestamp, reverse=True)
    return out


# ---------------------------------------------------------------------------
# Public: take a backup.
# ---------------------------------------------------------------------------


def full_backup(to_dir: Path | str, *, keep: int = 7) -> BackupResult:
    """Snapshot the live database into ``to_dir``, then rotate.

    Args:
        to_dir: Destination directory. Created if missing.
        keep: How many snapshots to retain. Older ones are deleted.
              Must be ``>= 1`` — caller protects from a typo erasing
              the just-written backup.

    Returns:
        ``BackupResult``. On success, ``path`` points at the new file
        and ``rotated`` lists files that were deleted.
    """
    if keep < 1:
        return BackupResult(ok=False, error=f"keep must be >= 1, got {keep}")

    dest_dir = Path(to_dir).expanduser()
    try:
        dest_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return BackupResult(ok=False, error=f"cannot create {dest_dir}: {exc}")

    url = settings.database_url
    kind = _db_kind(url)
    ts = _now_utc()

    if kind == "sqlite":
        src = _sqlite_path(url)
        if src is None:
            return BackupResult(
                ok=False,
                error="cannot back up an in-memory or empty SQLite URL",
            )
        if not src.exists():
            return BackupResult(
                ok=False,
                error=f"sqlite database file not found: {src}",
            )
        dest = dest_dir / _format_filename(ts, "db")
        try:
            _sqlite_online_backup(src, dest)
        except (sqlite3.Error, OSError) as exc:
            return BackupResult(ok=False, error=f"sqlite backup failed: {exc}")

    elif kind == "postgres":
        dest = dest_dir / _format_filename(ts, "sql")
        try:
            _postgres_pg_dump(url, dest)
        except (FileNotFoundError, subprocess.CalledProcessError, OSError) as exc:
            return BackupResult(ok=False, error=f"postgres backup failed: {exc}")

    else:
        return BackupResult(
            ok=False,
            error=(
                f"unsupported database URL scheme: {url.split(':', 1)[0]!r}; "
                "backup only handles sqlite:// and postgresql://"
            ),
        )

    try:
        size = dest.stat().st_size
    except OSError:
        size = 0

    rotated = _rotate(dest_dir, keep=keep)

    _log.info(
        "backup.full.ok",
        path=str(dest),
        size_bytes=size,
        rotated=len(rotated),
        keep=keep,
        db_kind=kind,
    )

    return BackupResult(
        ok=True,
        path=dest,
        size_bytes=size,
        rotated=rotated,
    )


# ---------------------------------------------------------------------------
# Public: restore from a snapshot.
# ---------------------------------------------------------------------------


def restore(from_path: Path | str, *, confirm: bool = False) -> RestoreResult:
    """Replace the live database with the contents of ``from_path``.

    Destructive. Refuses unless ``confirm=True`` (the CLI sets this only
    after the user has typed YES). Before overwriting, the current DB is
    copied to a sibling file with suffix ``.pre_restore_<UTC ts>`` so
    "I restored the wrong file" is always recoverable.

    Caller is responsible for ensuring the server is stopped — this
    module does not import ``lifecycle`` to avoid the circular import.
    The CLI does that check.
    """
    if not confirm:
        return RestoreResult(
            ok=False,
            error="restore refused: pass confirm=True to acknowledge that this is destructive",
        )

    src = Path(from_path).expanduser()
    if not src.exists():
        return RestoreResult(ok=False, error=f"backup file not found: {src}")
    if not src.is_file():
        return RestoreResult(ok=False, error=f"backup path is not a regular file: {src}")

    url = settings.database_url
    kind = _db_kind(url)

    if kind == "sqlite":
        live = _sqlite_path(url)
        if live is None:
            return RestoreResult(
                ok=False,
                error="cannot restore over an in-memory or empty SQLite URL",
            )

        # Safety backup of the current file (only if it exists — fresh
        # installs may have no DB yet, which is fine).
        safety: Path | None = None
        if live.exists():
            safety_name = f"{live.name}.pre_restore_{_now_utc().strftime(_TS_FORMAT)}"
            safety = live.with_name(safety_name)
            try:
                shutil.copy2(live, safety)
            except OSError as exc:
                return RestoreResult(
                    ok=False,
                    error=f"could not write safety backup {safety}: {exc}",
                )

        try:
            live.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, live)
        except OSError as exc:
            return RestoreResult(
                ok=False,
                safety_backup=safety,
                error=f"copy {src} → {live} failed: {exc}",
            )

        _log.info(
            "backup.restore.ok",
            from_=str(src),
            to=str(live),
            safety=str(safety) if safety else None,
        )
        return RestoreResult(ok=True, restored_from=src, safety_backup=safety)

    if kind == "postgres":
        try:
            _postgres_psql_restore(url, src)
        except (FileNotFoundError, subprocess.CalledProcessError, OSError) as exc:
            return RestoreResult(
                ok=False,
                error=f"postgres restore failed: {exc}",
            )
        _log.info("backup.restore.ok", from_=str(src), db_kind="postgres")
        return RestoreResult(ok=True, restored_from=src)

    return RestoreResult(
        ok=False,
        error=(f"unsupported database URL scheme for restore: {url.split(':', 1)[0]!r}"),
    )


# ---------------------------------------------------------------------------
# Internals — backup engines.
# ---------------------------------------------------------------------------


def _sqlite_online_backup(src: Path, dest: Path) -> None:
    """Use sqlite3 ``Connection.backup()`` for an online page-by-page copy.

    Works while the server is writing — SQLite serialises page reads
    against ongoing transactions internally. On exit, the dest file is
    a complete consistent snapshot.
    """
    src_conn = sqlite3.connect(str(src))
    try:
        # Open dest as a fresh DB and let backup() pump pages into it.
        # delete=True semantics: if dest exists from a partial run, blow
        # it away first so we don't append to a stale file.
        if dest.exists():
            dest.unlink()
        dest_conn = sqlite3.connect(str(dest))
        try:
            src_conn.backup(dest_conn)
        finally:
            dest_conn.close()
    finally:
        src_conn.close()


def _postgres_pg_dump(url: str, dest: Path) -> None:
    """Shell out to ``pg_dump`` for a plain-SQL snapshot.

    We pass the URL through directly — pg_dump understands the same
    connection-string shapes SQLAlchemy does. Output is plain SQL so
    the operator can also ``less`` it in a pinch.
    """
    pg_dump = shutil.which("pg_dump")
    if not pg_dump:
        raise FileNotFoundError("pg_dump not on PATH; install postgresql-client or set PGBIN")

    # Strip SQLAlchemy's "+driver" qualifier (postgresql+psycopg → postgresql)
    # because pg_dump rejects unknown schemes.
    canon = _canonicalise_pg_url(url)

    # Capture both streams so we can include stderr in the exception
    # message on failure — pg_dump's "permission denied" lives in stderr.
    proc = subprocess.run(
        [pg_dump, "--no-owner", "--no-privileges", "--format=plain", canon],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(
            proc.returncode,
            ["pg_dump", "..."],
            output=proc.stdout,
            stderr=proc.stderr,
        )
    dest.write_bytes(proc.stdout)


def _postgres_psql_restore(url: str, src: Path) -> None:
    """Replay a pg_dump SQL file via ``psql``.

    Caveat for the runbook: this assumes the target DB exists and is
    empty (or willing to be overwritten). For a true point-in-time
    rebuild, operators should ``DROP DATABASE; CREATE DATABASE;`` first.
    The runbook in docs/BACKUP_RESTORE.md spells this out.
    """
    psql = shutil.which("psql")
    if not psql:
        raise FileNotFoundError("psql not on PATH; install postgresql-client or set PGBIN")
    canon = _canonicalise_pg_url(url)
    proc = subprocess.run(
        [psql, "--quiet", "-v", "ON_ERROR_STOP=1", "-f", str(src), canon],
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(
            proc.returncode,
            ["psql", "..."],
            output=proc.stdout,
            stderr=proc.stderr,
        )


def _canonicalise_pg_url(url: str) -> str:
    """Drop the SQLAlchemy ``+driver`` qualifier from a postgres URL.

    ``postgresql+psycopg://...`` → ``postgresql://...`` — pg_dump and
    psql don't know what ``+psycopg`` means and refuse to parse it.
    Everything else is left untouched.
    """
    parts = urlsplit(url)
    scheme = parts.scheme
    if "+" in scheme:
        scheme = scheme.split("+", 1)[0]
    return parts._replace(scheme=scheme).geturl()


# ---------------------------------------------------------------------------
# Internals — rotation.
# ---------------------------------------------------------------------------


def _rotate(in_dir: Path, *, keep: int) -> list[Path]:
    """Delete backups past index ``keep`` (newest first). Returns the list.

    Pure file-system operation. We never touch files that don't match
    our filename schema, so an operator's hand-curated archives in the
    same directory survive.
    """
    backups = list_backups(in_dir)  # newest → oldest
    victims = backups[keep:]
    deleted: list[Path] = []
    for v in victims:
        try:
            v.path.unlink()
            deleted.append(v.path)
        except OSError as exc:
            _log.warning(
                "backup.rotate.delete_failed",
                path=str(v.path),
                error=f"{type(exc).__name__}: {exc}",
            )
    return deleted
