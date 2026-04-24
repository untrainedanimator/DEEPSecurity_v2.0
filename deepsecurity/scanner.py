"""The scan engine.

Three layers, evaluated in this order:

    1. Signature:     SHA-256 of file content matches a known-bad list   → detection
    2. ML classifier: entropy + size + anomaly features, confidence gate → detection
    3. Entropy alone: logged for review, NEVER used to quarantine

MIME whitelist:
    Files whose MIME type is in MEDIA_MIMES or ARCHIVE_MIMES are high-entropy
    by construction (MP3 / MP4 / JPEG / ZIP, etc.). We skip the entropy
    evaluation for them entirely. The signature check still runs so we catch
    known-bad binaries even if they're wrapped in a common container format.

    This is the single design decision that prevents the v1.0-working disaster
    of quarantining the user's entire music library.

Quarantine policy:
    "Quarantine" means a **copy** is made into the quarantine directory.
    The original is NEVER deleted automatically. That is an operator action.
"""
from __future__ import annotations

import hashlib
import math
import mimetypes
import os
import shutil
from collections.abc import Callable, Generator
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from deepsecurity.alerts import AlertEvent
from deepsecurity.alerts import bus as alert_bus
from deepsecurity.audit import audit_log
from deepsecurity.config import settings
from deepsecurity.db import session_scope
from deepsecurity.dlp import scan_file_for_secrets
from deepsecurity.logging_config import get_logger
from deepsecurity.metrics import metrics as _metrics
from deepsecurity.mitre import tags_for_reasons
from deepsecurity.ml import MLClassifier, MLVerdict
from deepsecurity.models import DLPFinding, ScanResult, ScanSession
from deepsecurity.paths import PathOutsideRootError, ensure_dir, resolve_under_root
from deepsecurity.scan_state import state
from deepsecurity.yara_engine import YaraEngine

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Tunables (overridable per-scan via `detection_config`)
# ---------------------------------------------------------------------------

DEFAULT_CHUNK_SIZE = 2048
DEFAULT_BASELINE_ENTROPY = 4.5
DEFAULT_ANOMALY_QUARANTINE_THRESHOLD = 2.0
DEFAULT_COMMIT_BATCH = 50

# Files of these types are almost always high-entropy for benign reasons
# (compression / encoding). We skip the entropy layer for them entirely.
MEDIA_MIMES: frozenset[str] = frozenset(
    {
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/webp",
        "image/bmp",
        "image/tiff",
        "audio/mpeg",
        "audio/mp4",
        "audio/ogg",
        "audio/wav",
        "audio/webm",
        "audio/flac",
        "video/mp4",
        "video/mpeg",
        "video/webm",
        "video/quicktime",
        "video/x-matroska",
    }
)

ARCHIVE_MIMES: frozenset[str] = frozenset(
    {
        "application/zip",
        "application/x-rar-compressed",
        "application/vnd.rar",
        "application/x-7z-compressed",
        "application/gzip",
        "application/x-tar",
        "application/x-bzip2",
        "application/x-xz",
    }
)


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FileFeatures:
    """What we measure about a file, before any classification."""

    path: Path
    size_bytes: int
    mime: str
    sha256: str
    entropy: float
    anomaly_score: float
    entropy_skipped: bool  # True if we applied the MIME whitelist


@dataclass(frozen=True)
class Detection:
    """A scan verdict for one file."""

    path: str
    sha256: str
    label: str  # "clean" | "malicious" | "suspicious"
    confidence: float
    anomaly_score: float
    entropy: float
    reasons: tuple[str, ...]
    mitre_tags: tuple[str, ...]
    quarantined: bool
    quarantine_path: str | None


# ---------------------------------------------------------------------------
# Hashing / entropy
# ---------------------------------------------------------------------------


def compute_sha256(path: Path, chunk: int = 65536) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def _byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c == 0:
            continue
        p = c / n
        ent -= p * math.log2(p)
    return ent


def calculate_entropy(path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> float:
    """Shannon entropy (bits/byte) of the first `chunk_size` bytes of the file.

    Streaming: never reads more than `chunk_size` bytes regardless of file size.
    Clamped to [0.0, 8.0].
    """
    try:
        with path.open("rb") as f:
            head = f.read(chunk_size)
    except OSError:
        _log.exception("entropy.read_failed", path=str(path))
        return 0.0
    return round(min(max(_byte_entropy(head), 0.0), 8.0), 4)


def detect_mime(path: Path) -> str:
    t, _ = mimetypes.guess_type(str(path))
    return t or "application/octet-stream"


def adaptive_baseline(mime: str, override: float | None = None) -> float:
    """Return a sensible baseline entropy for a given MIME type."""
    if override is not None:
        return override
    if mime.startswith("text/") or mime in {"application/json", "application/xml"}:
        return 4.0
    if mime.startswith(("image/", "audio/", "video/")):
        return 6.0
    return 5.0


def is_mime_whitelisted(mime: str) -> bool:
    """True if entropy evaluation should be skipped for this MIME type."""
    return mime in MEDIA_MIMES or mime in ARCHIVE_MIMES


# ---------------------------------------------------------------------------
# Signature loading
# ---------------------------------------------------------------------------


def load_signatures(path: Path) -> frozenset[str]:
    """Load a file containing one SHA-256 hex digest per line. Missing file is not fatal."""
    if not path.exists():
        _log.info("signatures.absent", path=str(path))
        return frozenset()
    try:
        with path.open("r", encoding="utf-8") as f:
            hashes = {
                line.strip().lower()
                for line in f
                if line.strip() and not line.strip().startswith("#")
            }
        _log.info("signatures.loaded", count=len(hashes), path=str(path))
        return frozenset(hashes)
    except OSError:
        _log.exception("signatures.load_failed", path=str(path))
        return frozenset()


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------


def extract_features(path: Path, detection_config: dict | None = None) -> FileFeatures:
    """Read the file once, compute everything we need for classification."""
    cfg = detection_config or {}
    chunk_size = int(cfg.get("chunk_size", DEFAULT_CHUNK_SIZE))
    baseline_override = cfg.get("baseline_entropy")

    size = path.stat().st_size
    mime = detect_mime(path)
    sha = compute_sha256(path)

    skipped = is_mime_whitelisted(mime)
    if skipped:
        entropy = 0.0
        anomaly = 0.0
    else:
        entropy = calculate_entropy(path, chunk_size=chunk_size)
        baseline = adaptive_baseline(mime, baseline_override)
        anomaly = round(abs(entropy - baseline), 4)

    return FileFeatures(
        path=path,
        size_bytes=size,
        mime=mime,
        sha256=sha,
        entropy=entropy,
        anomaly_score=anomaly,
        entropy_skipped=skipped,
    )


# ---------------------------------------------------------------------------
# Quarantine / safelist / restore
# ---------------------------------------------------------------------------


def quarantine_copy(path: Path, quarantine_dir: Path | None = None) -> Path:
    """Copy the file into the quarantine directory. The original is left in place.

    Returns the path of the quarantine copy.

    Filename shape: ``<UTC timestamp>_<sha256[:8]>_<original name>``. The
    hash prefix defeats the same-second same-basename collision case the
    v2.3 audit flagged — two files named ``invoice.pdf`` quarantined in
    the same second no longer overwrite each other in the quarantine
    directory. Using the content hash (not a random UUID) also means two
    *identical* files quarantined simultaneously still collapse into one
    entry, which is the behaviour operators expect.
    """
    qdir = ensure_dir(quarantine_dir or settings.quarantine_dir)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    sha_short = compute_sha256(path)[:8]
    target = qdir / f"{timestamp}_{sha_short}_{path.name}"
    shutil.copy2(str(path), str(target))
    _log.info("quarantine.copied", source=str(path), target=str(target))
    return target


def restore_from_quarantine(quarantine_path: Path, original_path: Path) -> bool:
    """Move a quarantined copy back to `original_path`. Parent dir created if needed."""
    try:
        if not quarantine_path.exists():
            _log.warning("restore.missing", path=str(quarantine_path))
            return False
        ensure_dir(original_path.parent)
        shutil.move(str(quarantine_path), str(original_path))
        _log.info("restore.ok", source=str(quarantine_path), target=str(original_path))
        return True
    except OSError:
        _log.exception("restore.failed", source=str(quarantine_path))
        return False


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def classify(
    features: FileFeatures,
    signatures: frozenset[str],
    ml: MLClassifier,
    yara: YaraEngine | None = None,
    anomaly_threshold: float = DEFAULT_ANOMALY_QUARANTINE_THRESHOLD,
) -> Detection:
    """Apply signature + YARA + ML + entropy layers and return a Detection.

    No side effects (no I/O, no DB, no quarantine move). Pure function over features.
    Precedence (highest to lowest): signature > YARA > ML(high-conf) > entropy spike.
    """
    reasons: list[str] = []
    label = "clean"
    confidence = 0.0

    # 1. Signature match — deterministic, highest precision.
    if features.sha256 in signatures:
        reasons.append("signature_match")
        label = "malicious"
        confidence = 1.0

    # 2. YARA (optional) — named rules with metadata.
    if yara is not None and yara.enabled:
        matches = yara.match(features.path)
        if matches:
            names = ",".join(m.rule for m in matches[:5])
            reasons.append(f"yara:{names}")
            label = "malicious"
            confidence = max(confidence, 0.95)

    # 3. ML layer — only counts if it crosses the threshold.
    ml_verdict: MLVerdict = ml.classify(
        [features.entropy, max(1.0, features.size_bytes / 1024.0), features.anomaly_score]
    )
    if ml_verdict.enabled and ml_verdict.malicious:
        reasons.append(ml_verdict.reason)
        label = "malicious"
        confidence = max(confidence, ml_verdict.confidence)
    elif ml_verdict.enabled:
        reasons.append(ml_verdict.reason)

    # 4. Entropy-only → suspicious but never malicious.
    # Assign a calibrated heuristic confidence so downstream consumers
    # (SIEM, dashboard, alerts) don't all see ``confidence: 0.0`` on
    # entropy-spike hits. We bound it into [0.3, 0.8] because entropy
    # alone is a soft signal: useful for prioritisation, never a
    # sole basis for blocking.
    if not features.entropy_skipped and features.anomaly_score >= anomaly_threshold:
        reasons.append(f"entropy_spike({features.anomaly_score})")
        if label == "clean":
            label = "suspicious"
        # Linear map of anomaly_score ∈ [threshold, threshold+6] → [0.3, 0.8].
        span = 6.0
        raw = 0.3 + ((features.anomaly_score - anomaly_threshold) / span) * 0.5
        heuristic_conf = max(0.3, min(0.8, raw))
        confidence = max(confidence, heuristic_conf)

    reasons_t = tuple(reasons) or ("none",)
    return Detection(
        path=str(features.path),
        sha256=features.sha256,
        label=label,
        confidence=round(confidence, 4),
        anomaly_score=features.anomaly_score,
        entropy=features.entropy,
        reasons=reasons_t,
        mitre_tags=tuple(tags_for_reasons(list(reasons_t))),
        quarantined=False,
        quarantine_path=None,
    )


# ---------------------------------------------------------------------------
# Per-file scan
# ---------------------------------------------------------------------------


def scan_file(
    path: Path,
    *,
    signatures: frozenset[str],
    ml: MLClassifier,
    yara: YaraEngine | None = None,
    detection_config: dict | None = None,
    quarantine_enabled: bool = False,
) -> Detection:
    """Scan a single file. Does not persist."""
    features = extract_features(path, detection_config)
    verdict = classify(
        features,
        signatures,
        ml,
        yara=yara,
        anomaly_threshold=(detection_config or {}).get(
            "anomaly_quarantine_threshold", DEFAULT_ANOMALY_QUARANTINE_THRESHOLD
        ),
    )

    _metrics.inc("files_scanned")
    if verdict.label != "clean":
        _metrics.inc("detections_total")

    # Quarantine is only for "malicious", never for "suspicious".
    if verdict.label == "malicious" and quarantine_enabled:
        qpath = quarantine_copy(path)
        _metrics.inc("quarantine_actions")
        verdict = Detection(
            **{**asdict(verdict), "quarantined": True, "quarantine_path": str(qpath)}
        )
        alert_bus.dispatch(
            AlertEvent(
                kind="detection.malicious",
                severity="high",
                summary=f"malicious file quarantined: {path.name}",
                file_path=str(path),
                details={
                    "sha256": verdict.sha256,
                    "reasons": list(verdict.reasons),
                    "confidence": verdict.confidence,
                    "quarantine_path": verdict.quarantine_path,
                },
            )
        )
    return verdict


def run_dlp(path: Path, mime: str, session_id: int | None) -> list[DLPFinding]:
    """Run DLP on a file; persist findings; fire an alert for critical hits.

    Returns persisted ORM rows (so the caller can report counts).
    """
    if not settings.dlp_enabled:
        return []

    raw_findings = scan_file_for_secrets(path, mime, max_bytes=settings.dlp_max_bytes)
    if not raw_findings:
        return []

    rows: list[DLPFinding] = []
    with session_scope() as sdb:
        for f in raw_findings:
            row = DLPFinding(
                session_id=session_id,
                file_path=f.file_path,
                pattern_name=f.pattern_name,
                severity=f.severity,
                line_number=f.line_number,
                redacted_preview=f.redacted_preview,
            )
            sdb.add(row)
            rows.append(row)
    _metrics.inc("dlp_findings_total", by=len(raw_findings))

    # Raise an alert for anything high/critical.
    for f in raw_findings:
        if f.severity in {"critical", "high"}:
            alert_bus.dispatch(
                AlertEvent(
                    kind=f"dlp.{f.severity}",
                    severity=f.severity,
                    summary=f"{f.pattern_name} detected in {Path(f.file_path).name}:{f.line_number}",
                    file_path=f.file_path,
                    details={"pattern": f.pattern_name, "line": f.line_number},
                )
            )
    return rows


# ---------------------------------------------------------------------------
# Directory scan
# ---------------------------------------------------------------------------


def iter_files(root: Path) -> Generator[Path, None, None]:
    """Yield every regular file at or under `root`.

    Accepts either a directory (walked recursively) or a single file (yielded
    as-is). Unreadable entries are skipped silently.
    """
    try:
        if root.is_file():
            yield root
            return
    except OSError:
        pass

    if not root.is_dir():
        _log.warning("scan.not_a_dir_or_file", path=str(root))
        return

    for dirpath, _dirnames, filenames in os.walk(root):
        for fname in filenames:
            p = Path(dirpath) / fname
            try:
                if p.is_file():
                    yield p
            except OSError:
                continue


def scan_directory(
    directory: str | Path,
    *,
    actor: str = "cli",
    user_role: str = "admin",
    quarantine_enabled: bool = True,
    detection_config: dict | None = None,
    progress: Callable[[Detection], None] | None = None,
) -> dict:
    """Walk a directory, scan every file, persist results, return a summary.

    `directory` must be inside the configured scan_root. Path traversal is rejected.
    `quarantine_enabled` requires the actor's role to be admin or security.
    """
    root = resolve_under_root(directory, settings.scan_roots)

    # Privilege gate — belt and braces with the API layer.
    may_quarantine = quarantine_enabled and user_role.lower() in {"admin", "security"}

    ml = MLClassifier(settings.ml_model_path, settings.ml_confidence_threshold)
    yara = YaraEngine(settings.yara_rules_dir)
    signatures = load_signatures(settings.signature_path)

    detection_cfg = detection_config or {}
    commit_batch = int(detection_cfg.get("commit_batch", DEFAULT_COMMIT_BATCH))

    with session_scope() as sdb:
        scan = ScanSession(
            actor=actor,
            status="in_progress",
            scan_root=str(root),
        )
        sdb.add(scan)
        sdb.flush()  # obtain id
        session_id = scan.id

    state.start(session_id=session_id)
    _metrics.inc("scans_started")
    _metrics.set("active_scans", 1)
    import time as _t

    scan_started = _t.monotonic()
    total = 0
    detections = 0

    audit_log(
        actor=actor,
        action="scan.start",
        file_path=root,
        details={"session_id": session_id, "role": user_role, "quarantine": may_quarantine},
    )

    try:
        with session_scope() as sdb:
            buffer: list[ScanResult] = []
            for file_path in iter_files(root):
                if state.snapshot()["cancelled"]:
                    _log.info("scan.cancelled", session_id=session_id)
                    break

                try:
                    det = scan_file(
                        file_path,
                        signatures=signatures,
                        ml=ml,
                        yara=yara,
                        detection_config=detection_cfg,
                        quarantine_enabled=may_quarantine,
                    )
                    # DLP runs in parallel with the main detection layers.
                    # Feature extraction already happened; reuse the MIME.
                    run_dlp(file_path, extract_features(file_path).mime, session_id)
                except PathOutsideRootError:
                    _log.warning("scan.rejected_path", path=str(file_path))
                    continue
                except OSError:
                    _log.exception("scan.file_error", path=str(file_path))
                    continue

                total += 1
                if det.label != "clean":
                    detections += 1
                state.mark_file(det.path, detected=det.label == "malicious")

                if progress is not None:
                    try:
                        progress(det)
                    except Exception:  # noqa: BLE001 — callback is untrusted
                        _log.exception("scan.progress_callback_failed")

                buffer.append(
                    ScanResult(
                        session_id=session_id,
                        file_path=det.path,
                        sha256=det.sha256,
                        label=det.label,
                        ml_confidence=det.confidence,
                        anomaly_score=det.anomaly_score,
                        entropy=det.entropy,
                        file_status="quarantined" if det.quarantined else "allowed",
                        detection_reason=", ".join(det.reasons),
                        quarantine_path=det.quarantine_path,
                    )
                )

                if len(buffer) >= commit_batch:
                    sdb.add_all(buffer)
                    sdb.flush()
                    buffer.clear()

            if buffer:
                sdb.add_all(buffer)

        with session_scope() as sdb:
            scan_row = sdb.get(ScanSession, session_id)
            if scan_row is not None:
                scan_row.status = "cancelled" if state.snapshot()["cancelled"] else "completed"
                scan_row.total_files = total
                scan_row.total_detections = detections
                scan_row.ended_at = datetime.now(timezone.utc)
    finally:
        state.finish()
        duration = _t.monotonic() - scan_started
        _metrics.observe("scan_duration_seconds", duration)
        _metrics.set("active_scans", 0)
        _metrics.inc("scans_completed")
        audit_log(
            actor=actor,
            action="scan.finish",
            file_path=root,
            details={
                "session_id": session_id,
                "total_files": total,
                "total_detections": detections,
                "duration_seconds": round(duration, 2),
            },
        )

    return {
        "session_id": session_id,
        "total_files": total,
        "total_detections": detections,
        "scan_root": str(root),
    }
