"""End-to-end scanner behaviour — focus on the v1.0-working bug class.

The single most important test: a JPEG-like high-entropy file is NOT quarantined
just because it has high entropy. This is the bug that ate the user's music library.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from deepsecurity.ml import MLClassifier
from deepsecurity.scanner import (
    compute_sha256,
    extract_features,
    iter_files,
    load_signatures,
    quarantine_copy,
    restore_from_quarantine,
    scan_directory,
    scan_file,
)


# --- SHA-256 helpers --------------------------------------------------------


def test_compute_sha256_known_value(tmp_path: Path) -> None:
    p = tmp_path / "x.txt"
    p.write_bytes(b"hello world")
    # sha256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    assert compute_sha256(p) == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"


# --- iter_files -------------------------------------------------------------


def test_iter_files_walks_recursively(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_text("b")
    found = sorted(p.name for p in iter_files(tmp_path))
    assert found == ["a.txt", "b.txt"]


# --- Signature loading ------------------------------------------------------


def test_load_signatures_parses_file(tmp_path: Path) -> None:
    sig = tmp_path / "s.txt"
    sig.write_text(
        "# a comment\n"
        "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9\n"
        "\n"
        "0000000000000000000000000000000000000000000000000000000000000000\n"
    )
    sigs = load_signatures(sig)
    assert len(sigs) == 2
    assert all(len(s) == 64 for s in sigs)
    # Case-folded to lower.
    assert "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" in sigs


def test_load_signatures_missing_is_empty(tmp_path: Path) -> None:
    assert load_signatures(tmp_path / "nope.txt") == frozenset()


# --- Feature extraction -----------------------------------------------------


def test_extract_features_skips_entropy_for_jpeg(tmp_path: Path) -> None:
    # A .jpg file (MIME guess from extension) — entropy check should be skipped.
    p = tmp_path / "photo.jpg"
    p.write_bytes(os.urandom(4096))  # high-entropy bytes
    feats = extract_features(p)
    assert feats.mime == "image/jpeg"
    assert feats.entropy_skipped is True
    assert feats.entropy == 0.0
    assert feats.anomaly_score == 0.0


def test_extract_features_runs_entropy_for_text(tmp_path: Path) -> None:
    p = tmp_path / "doc.txt"
    p.write_text("a" * 2000)
    feats = extract_features(p)
    assert feats.mime == "text/plain"
    assert feats.entropy_skipped is False
    # All-'a' text has near-zero entropy.
    assert feats.entropy < 1.0


# --- The critical test ------------------------------------------------------


def test_high_entropy_jpeg_is_not_quarantined(tmp_path: Path) -> None:
    """The v1.0-working bug: high-entropy JPEG was flagged as malware.

    Here: random-byte JPEG, no signature match, no ML model. Scanner must NOT
    mark it malicious.
    """
    p = tmp_path / "cat.jpg"
    p.write_bytes(os.urandom(8192))

    # ML disabled (no model); no signature list.
    ml = MLClassifier(model_path=None, confidence_threshold=0.85)
    sigs = frozenset()

    det = scan_file(p, signatures=sigs, ml=ml, quarantine_enabled=True)
    assert det.label == "clean"
    assert det.quarantined is False
    # And its reasons should NOT cite "entropy_spike" — the MIME whitelist
    # prevented the entropy check from running in the first place.
    assert not any("entropy_spike" in r for r in det.reasons)


def test_high_entropy_octet_stream_is_suspicious_not_malicious(tmp_path: Path) -> None:
    """Unknown binary with huge entropy anomaly → 'suspicious', never auto-quarantined."""
    p = tmp_path / "weird.bin"
    p.write_bytes(os.urandom(8192))

    ml = MLClassifier(model_path=None, confidence_threshold=0.85)
    sigs = frozenset()

    det = scan_file(p, signatures=sigs, ml=ml, quarantine_enabled=True)
    assert det.label == "suspicious"
    assert det.quarantined is False  # suspicious never quarantines


def test_signature_match_quarantines(tmp_path: Path) -> None:
    """A signature match should always quarantine (copy), never delete."""
    p = tmp_path / "known_bad.bin"
    p.write_bytes(b"attack payload")
    sha = compute_sha256(p)

    ml = MLClassifier(model_path=None, confidence_threshold=0.85)
    sigs = frozenset({sha})

    det = scan_file(p, signatures=sigs, ml=ml, quarantine_enabled=True)
    assert det.label == "malicious"
    assert det.quarantined is True
    assert det.quarantine_path is not None
    # Original must still exist — we only copy, never delete.
    assert p.exists()
    # Quarantine file must exist.
    assert Path(det.quarantine_path).exists()


# --- Quarantine round-trip --------------------------------------------------


def test_quarantine_then_restore_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Put the quarantine dir under tmp_path.
    from deepsecurity import config as cfg_mod

    qdir = tmp_path / "quarantine"
    original = tmp_path / "original.txt"
    original.write_text("hello")

    qpath = quarantine_copy(original, quarantine_dir=qdir)
    assert qpath.exists()
    assert original.exists()  # original not touched

    restored = tmp_path / "restored.txt"
    assert restore_from_quarantine(qpath, restored) is True
    assert restored.read_text() == "hello"
    assert not qpath.exists()  # restore moves, not copies


def test_quarantine_no_collision_on_dup(tmp_path: Path) -> None:
    """Same-second same-basename with DIFFERENT CONTENT must not collide.

    Audit regression: before v2.3.1 the quarantine filename was
    ``<ts>_<name>`` at second resolution, so two files with the same
    basename quarantined in the same second silently overwrote each
    other. We now add ``sha256[:8]`` so distinct content gets distinct
    filenames. Identical content still collapses (that's a feature —
    deduplication).
    """
    qdir = tmp_path / "quarantine"

    # Two DIFFERENT files, same basename, quarantined back-to-back.
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    file_a = dir_a / "invoice.pdf"
    file_b = dir_b / "invoice.pdf"
    file_a.write_bytes(b"alpha content")
    file_b.write_bytes(b"beta content different bytes")

    qa = quarantine_copy(file_a, quarantine_dir=qdir)
    qb = quarantine_copy(file_b, quarantine_dir=qdir)

    # Different filenames — no overwrite.
    assert qa != qb, (
        f"quarantine produced the same filename twice: {qa} / {qb} — "
        "same-second same-basename collision regressed"
    )
    # Both quarantine copies survived with their original bytes.
    assert qa.read_bytes() == b"alpha content"
    assert qb.read_bytes() == b"beta content different bytes"


def test_quarantine_dedups_identical_content(tmp_path: Path) -> None:
    """Identical content at the same second SHOULD collapse to one copy.

    Using sha256 (not a UUID) for disambiguation gives us free
    deduplication for the common case of "same malicious file delivered
    to two folders." Operators don't want N copies of the same bytes
    clogging quarantine."""
    qdir = tmp_path / "quarantine"
    a = tmp_path / "x" / "same.bin"
    b = tmp_path / "y" / "same.bin"
    a.parent.mkdir()
    b.parent.mkdir()
    payload = b"identical bytes"
    a.write_bytes(payload)
    b.write_bytes(payload)

    qa = quarantine_copy(a, quarantine_dir=qdir)
    qb = quarantine_copy(b, quarantine_dir=qdir)

    # Timestamp-to-the-second + same sha → identical target filename.
    # shutil.copy2 is idempotent on an existing file with same content,
    # so both calls are safe. This is desirable: one file = one quarantine
    # slot.
    assert qa.name == qb.name
    assert qa.read_bytes() == payload


# --- Directory scan (integrates DB) ----------------------------------------


def test_scan_directory_persists_and_returns_summary(
    initialized_db: Path, scan_root: Path, fresh_state: None
) -> None:
    # Three files: plain text, media (entropy-whitelisted), and a
    # signature-matched known-bad. Only the known-bad must count as a
    # detection — the text must be long/varied enough that its Shannon
    # entropy is close to the text/plain baseline (~4.0 bits/byte).
    # Using a five-byte string like "hello" produces entropy ≈ 1.9 which
    # sits just over the 2.0 anomaly threshold and falsely flags as
    # "suspicious". A realistic pangram keeps us near 4.0 and clean.
    (scan_root / "clean.txt").write_text(
        "The quick brown fox jumps over the lazy dog. "
        "Sphinx of black quartz, judge my vow. "
        "Pack my box with five dozen liquor jugs. "
        "How vexingly quick daft zebras jump!"
    )
    (scan_root / "photo.jpg").write_bytes(os.urandom(4096))
    bad = scan_root / "bad.bin"
    bad.write_bytes(b"evil payload here")
    sha = compute_sha256(bad)

    # Write the signature list.
    from deepsecurity.config import settings as s

    s.signature_path.parent.mkdir(parents=True, exist_ok=True)
    s.signature_path.write_text(sha + "\n")

    summary = scan_directory(scan_root, actor="test", user_role="admin")
    assert summary["total_files"] == 3
    assert summary["total_detections"] == 1
    assert summary["scan_root"] == str(scan_root.resolve())


def test_scan_directory_rejects_path_outside_root(initialized_db: Path, tmp_path: Path) -> None:
    """Trying to scan outside scan_root must raise."""
    from deepsecurity.paths import PathOutsideRootError

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "a.txt").write_text("x")

    with pytest.raises(PathOutsideRootError):
        scan_directory(outside, actor="test", user_role="admin")
