"""Backup / restore module tests.

Coverage:
    - online snapshot of a live SQLite DB succeeds while the DB is open
    - filename schema round-trips through list_backups()
    - rotation deletes the oldest, keeps the N newest
    - rotation never touches files that don't match our schema
    - restore is destructive but takes a safety copy first
    - restore refuses without confirm=True
    - restore from a missing file fails cleanly
    - unsupported scheme (e.g. mysql://) yields a clean error, not a stack trace
    - in-memory SQLite is rejected (we can't snapshot :memory:)
    - sqlite-online-backup actually copies user rows (round-trip integrity)
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Filename helpers — pure functions, exercise without any DB.
# ---------------------------------------------------------------------------


def test_filename_round_trip() -> None:
    from deepsecurity.backup import _format_filename, _parse_filename

    ts = datetime(2026, 4, 25, 14, 30, 15, tzinfo=UTC)
    name = _format_filename(ts, "db")
    assert name == "deepsec_20260425T143015Z_full.db"

    parsed = _parse_filename(name)
    assert parsed is not None
    out_ts, kind = parsed
    assert out_ts == ts
    assert kind == "full"


def test_parse_filename_rejects_junk() -> None:
    from deepsecurity.backup import _parse_filename

    assert _parse_filename("README.md") is None
    assert _parse_filename("deepsec_2026-04-25_full.db") is None  # wrong ts shape
    assert _parse_filename("deepsec_20260425T143015Z_diff.db") is None  # wrong kind
    assert _parse_filename("deepsec_20260425T143015Z_full.txt") is None  # wrong ext


# ---------------------------------------------------------------------------
# Live SQLite backup.
# ---------------------------------------------------------------------------


def test_full_backup_creates_a_file_with_real_db_contents(
    initialized_db: Path,
) -> None:
    """Take a live snapshot, then open it with sqlite3 and verify rows survived."""
    from deepsecurity import backup as backup_mod
    from deepsecurity.audit import audit_log

    # Write at least one row through the public API so the snapshot has
    # content we can verify after the round-trip.
    audit_log(
        actor="test",
        action="backup.test_seed",
        status="ok",
        details={"marker": "round-trip-seed"},
    )

    out_dir = initialized_db / "backups"
    res = backup_mod.full_backup(out_dir, keep=7)

    assert res.ok, res.error
    assert res.path is not None
    assert res.path.exists()
    assert res.size_bytes > 0

    # Open the snapshot directly and verify it has the seed row.
    conn = sqlite3.connect(str(res.path))
    try:
        cur = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = ?",
            ("backup.test_seed",),
        )
        count = cur.fetchone()[0]
    finally:
        conn.close()
    assert count >= 1, "snapshot didn't capture the seed row"


def test_full_backup_rejects_keep_zero(initialized_db: Path) -> None:
    """``keep=0`` would delete the just-written backup. Refuse the request."""
    from deepsecurity import backup as backup_mod

    res = backup_mod.full_backup(initialized_db / "backups", keep=0)
    assert not res.ok
    assert "keep" in (res.error or "")


def test_full_backup_in_memory_url_is_rejected(
    initialized_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``sqlite:///:memory:`` has no on-disk file to copy."""
    from deepsecurity import backup as backup_mod
    from deepsecurity import config as cfg_mod
    from deepsecurity import db as db_mod

    monkeypatch.setenv("DEEPSEC_DATABASE_URL", "sqlite:///:memory:")
    cfg_mod.get_settings.cache_clear()
    db_mod.get_engine.cache_clear()
    db_mod._session_factory.cache_clear()

    res = backup_mod.full_backup(initialized_db / "backups", keep=3)
    assert not res.ok
    assert "memory" in (res.error or "").lower()


def test_full_backup_unsupported_scheme(
    initialized_db: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Operators with mysql:// URLs deserve a polite refusal, not a 500."""
    from deepsecurity import backup as backup_mod
    from deepsecurity import config as cfg_mod

    monkeypatch.setenv("DEEPSEC_DATABASE_URL", "mysql://user:pw@host/db")
    cfg_mod.get_settings.cache_clear()

    res = backup_mod.full_backup(initialized_db / "backups", keep=3)
    assert not res.ok
    assert "unsupported" in (res.error or "").lower()


# ---------------------------------------------------------------------------
# Rotation.
# ---------------------------------------------------------------------------


def test_rotation_keeps_newest_n_only(initialized_db: Path) -> None:
    """Synthesise 5 backup files with descending timestamps; rotation with
    keep=3 should delete exactly the 2 oldest."""
    from deepsecurity.backup import _format_filename, _rotate, list_backups

    out_dir = initialized_db / "backups"
    out_dir.mkdir()

    # Hand-write files with controlled timestamps.
    base = datetime(2026, 4, 25, 12, 0, 0, tzinfo=UTC)
    paths: list[Path] = []
    for i in range(5):
        ts = base + timedelta(hours=i)
        p = out_dir / _format_filename(ts, "db")
        p.write_bytes(b"placeholder content")
        paths.append(p)

    deleted = _rotate(out_dir, keep=3)

    survivors = list_backups(out_dir)
    assert len(survivors) == 3
    # The 3 survivors should be the NEWEST three.
    surviving_names = {s.path.name for s in survivors}
    expected_survivor_names = {paths[i].name for i in (4, 3, 2)}
    assert surviving_names == expected_survivor_names

    # The 2 deletions should be the oldest pair.
    deleted_names = {p.name for p in deleted}
    assert deleted_names == {paths[0].name, paths[1].name}


def test_rotation_ignores_unrelated_files(initialized_db: Path) -> None:
    """A README.md or operator's own zip in the backup dir must survive."""
    from deepsecurity.backup import _format_filename, _rotate

    out_dir = initialized_db / "backups"
    out_dir.mkdir()

    # 2 valid backups + 2 unrelated files.
    base = datetime(2026, 4, 25, 12, 0, 0, tzinfo=UTC)
    valid = []
    for i in range(2):
        ts = base + timedelta(hours=i)
        p = out_dir / _format_filename(ts, "db")
        p.write_bytes(b"x")
        valid.append(p)
    unrelated_a = out_dir / "README.md"
    unrelated_a.write_text("hand-curated archive notes")
    unrelated_b = out_dir / "snapshot_2025_archived.zip"
    unrelated_b.write_bytes(b"PK\x03\x04junk")

    # keep=1 should delete one of the valid backups but neither unrelated file.
    _rotate(out_dir, keep=1)

    assert unrelated_a.exists(), "operator's README was deleted"
    assert unrelated_b.exists(), "operator's archive was deleted"
    # One of the two valid backups should survive.
    valid_remaining = [p for p in valid if p.exists()]
    assert len(valid_remaining) == 1


def test_list_backups_orders_newest_first(initialized_db: Path) -> None:
    from deepsecurity.backup import _format_filename, list_backups

    out_dir = initialized_db / "backups"
    out_dir.mkdir()

    base = datetime(2026, 4, 25, 12, 0, 0, tzinfo=UTC)
    timestamps = [base, base + timedelta(hours=2), base + timedelta(hours=1)]
    for ts in timestamps:
        (out_dir / _format_filename(ts, "db")).write_bytes(b"x")

    entries = list_backups(out_dir)
    assert [e.timestamp for e in entries] == [
        base + timedelta(hours=2),
        base + timedelta(hours=1),
        base,
    ]


def test_list_backups_returns_empty_for_missing_dir(tmp_path: Path) -> None:
    from deepsecurity.backup import list_backups

    assert list_backups(tmp_path / "does_not_exist") == []


# ---------------------------------------------------------------------------
# Restore.
# ---------------------------------------------------------------------------


def test_restore_refuses_without_confirm(initialized_db: Path) -> None:
    from deepsecurity import backup as backup_mod

    out_dir = initialized_db / "backups"
    snap = backup_mod.full_backup(out_dir, keep=3)
    assert snap.ok

    # Default: confirm=False — must refuse.
    res = backup_mod.restore(snap.path)  # type: ignore[arg-type]
    assert not res.ok
    assert "confirm" in (res.error or "").lower()


def test_restore_replaces_db_and_writes_safety_copy(
    initialized_db: Path,
) -> None:
    """Round-trip: snapshot → mutate live DB → restore → original row is back."""
    from deepsecurity import backup as backup_mod
    from deepsecurity.audit import audit_log
    from deepsecurity.db import get_engine, session_scope
    from deepsecurity.models import AuditLog

    # Seed the live DB.
    audit_log(
        actor="test",
        action="backup.preserve_me",
        status="ok",
    )

    out_dir = initialized_db / "backups"
    snap = backup_mod.full_backup(out_dir, keep=3)
    assert snap.ok

    # Mutate the live DB AFTER the snapshot.
    audit_log(
        actor="test",
        action="backup.AFTER_snapshot",
        status="ok",
    )

    # Dispose the engine so every pooled connection releases its handle
    # on the SQLite file BEFORE we overwrite it. On Windows this is
    # required; on POSIX it's harmless.
    get_engine().dispose()

    res = backup_mod.restore(snap.path, confirm=True)  # type: ignore[arg-type]
    assert res.ok, res.error
    assert res.safety_backup is not None
    assert res.safety_backup.exists()

    # Force fresh engine after the file swap.
    from deepsecurity import db as db_mod

    db_mod.get_engine.cache_clear()
    db_mod._session_factory.cache_clear()

    with session_scope() as session:
        preserve = session.query(AuditLog).filter(AuditLog.action == "backup.preserve_me").all()
        after = session.query(AuditLog).filter(AuditLog.action == "backup.AFTER_snapshot").all()
    assert preserve, "row from snapshot should be back after restore"
    assert not after, "post-snapshot row should be gone after restore"


def test_restore_missing_file(initialized_db: Path) -> None:
    from deepsecurity import backup as backup_mod

    res = backup_mod.restore(
        initialized_db / "no_such_file.db",
        confirm=True,
    )
    assert not res.ok
    assert "not found" in (res.error or "").lower()
