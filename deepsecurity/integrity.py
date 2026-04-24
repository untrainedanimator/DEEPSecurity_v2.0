"""Self-integrity: hash our own Python modules and detect tampering.

Tamper-AWARE, not tamper-PROOF. A privileged attacker can overwrite both
the code AND our snapshot file. What this buys you:

  - Accidental corruption / bad deploy / forgotten local edit detected on boot.
  - A tripwire that fires an alert through the bus → your SIEM.
  - Evidence for an incident investigation that the binary was modified.

What this does NOT buy you:

  - Protection against an admin-privileged attacker. For that you need code
    signing + kernel-enforced verification (CI artefact signing, secure boot,
    Windows' Process Protection Light, Linux IMA). All out of scope.

Run:
  deepsec integrity snapshot  # compute and save
  deepsec integrity check     # compare and report
  /api/system/integrity       # same, via API
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from deepsecurity.config import settings
from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)

# Directories within the installed package that we fingerprint.
_PACKAGE_ROOT = Path(__file__).resolve().parent


@dataclass(frozen=True)
class IntegrityReport:
    status: str  # "ok" | "tampered" | "no_snapshot" | "error"
    total_files: int
    mismatched: list[str]
    missing: list[str]
    added: list[str]
    snapshot_at: str | None
    snapshot_path: str


def _walk_package() -> list[Path]:
    out: list[Path] = []
    for p in sorted(_PACKAGE_ROOT.rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        out.append(p)
    return out


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def _hash_str(value: str) -> str:
    """SHA-256 of a UTF-8-encoded string. Used for the policy-blob entry."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# Auxiliary artefacts we fingerprint alongside the .py tree. A tampered
# .env or a swapped signatures.txt would otherwise slip past the v2.3
# integrity check — the attacker doesn't need to touch code if they can
# just flip DEEPSEC_DLP_ENABLED=false in the env file.
_EXTRA_ARTIFACTS: tuple[str, ...] = (
    ".env",
    "data/signatures.txt",
)


def _policy_blob() -> str:
    """Serialize the subset of settings whose tampering materially changes
    posture. Order is stable so the hash is reproducible across boots."""
    # We serialize rather than import-time snapshot because the proxy
    # settings object reads live values; this captures the effective
    # configuration at the moment of snapshot/check.
    from deepsecurity.config import settings as _s

    try:
        policy = {
            "watchdog_autostart": _s.watchdog_autostart,
            "user_risk_paths": _s.user_risk_paths,
            "watch_exclude_globs": _s.watch_exclude_globs,
            "dlp_enabled": _s.dlp_enabled,
            "auto_kill_known_bad": _s.auto_kill_known_bad,
            "ransomware_auto_kill": _s.ransomware_auto_kill,
        }
    except Exception:
        # If settings fail to load, return an empty blob — check() still
        # succeeds, but any future mismatch will surface the problem.
        return ""
    return json.dumps(policy, sort_keys=True)


def _current_fingerprint() -> dict[str, str]:
    """Return {relative_path: sha256} for every artefact we watch.

    Includes:
      - every ``.py`` under the package
      - ``.env`` if present at the repo root
      - ``data/signatures.txt`` if present
      - a synthetic ``<policy>`` entry hashing the runtime policy blob
    """
    files = _walk_package()
    out: dict[str, str] = {
        str(p.relative_to(_PACKAGE_ROOT.parent)).replace("\\", "/"): _hash_file(p)
        for p in files
    }

    repo_root = _PACKAGE_ROOT.parent
    for rel in _EXTRA_ARTIFACTS:
        full = repo_root / rel
        if full.exists():
            out[rel] = _hash_file(full)

    # Policy blob — hashed from live settings, not from a file, so we
    # detect environment-only overrides too (e.g. docker-compose env).
    out["<policy>"] = _hash_str(_policy_blob())
    return out


def snapshot() -> IntegrityReport:
    """Compute the current fingerprint and save it."""
    snap = _current_fingerprint()
    path = settings.integrity_snapshot_path
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "package_root": str(_PACKAGE_ROOT.parent),
        "files": snap,
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)
    _log.info("integrity.snapshot", count=len(snap), path=str(path))
    return IntegrityReport(
        status="ok",
        total_files=len(snap),
        mismatched=[],
        missing=[],
        added=[],
        snapshot_at=payload["created_at"],
        snapshot_path=str(path),
    )


def check() -> IntegrityReport:
    """Compare the current fingerprint against the saved snapshot."""
    path = settings.integrity_snapshot_path
    if not path.exists():
        return IntegrityReport(
            status="no_snapshot",
            total_files=0,
            mismatched=[],
            missing=[],
            added=[],
            snapshot_at=None,
            snapshot_path=str(path),
        )
    try:
        saved = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        _log.exception("integrity.snapshot_unreadable", path=str(path))
        return IntegrityReport(
            status="error",
            total_files=0,
            mismatched=[],
            missing=[],
            added=[],
            snapshot_at=None,
            snapshot_path=str(path),
        )

    saved_files: dict[str, str] = saved.get("files", {})
    current = _current_fingerprint()

    mismatched = sorted([k for k, v in current.items() if k in saved_files and saved_files[k] != v])
    missing = sorted([k for k in saved_files if k not in current])
    added = sorted([k for k in current if k not in saved_files])

    if mismatched or missing or added:
        status = "tampered"
    else:
        status = "ok"

    return IntegrityReport(
        status=status,
        total_files=len(current),
        mismatched=mismatched,
        missing=missing,
        added=added,
        snapshot_at=saved.get("created_at"),
        snapshot_path=str(path),
    )


def boot_check() -> None:
    """Run at application startup if `integrity_check_on_boot` is set.
    Emits an alert bus event on any deviation; never raises."""
    if not settings.integrity_check_on_boot:
        return
    try:
        report = check()
    except Exception:
        _log.exception("integrity.boot_check_failed")
        return
    _log.info(
        "integrity.boot_check",
        status=report.status,
        mismatched=len(report.mismatched),
        missing=len(report.missing),
        added=len(report.added),
    )
    if report.status in {"tampered", "no_snapshot"}:
        try:
            from deepsecurity.alerts import AlertEvent
            from deepsecurity.alerts import bus as alert_bus

            severity = "critical" if report.status == "tampered" else "low"
            alert_bus.dispatch(
                AlertEvent(
                    kind=f"integrity.{report.status}",
                    severity=severity,
                    summary=(
                        f"self-integrity check: {report.status} "
                        f"(mismatched={len(report.mismatched)}, "
                        f"missing={len(report.missing)}, added={len(report.added)})"
                    ),
                    details={
                        "mitre_tags": ["T1055"] if report.status == "tampered" else [],
                        "mismatched": report.mismatched[:20],
                        "missing": report.missing[:20],
                        "added": report.added[:20],
                        "snapshot_path": report.snapshot_path,
                    },
                )
            )
        except Exception:
            _log.exception("integrity.alert_failed")


def report_as_dict(r: IntegrityReport) -> dict[str, Any]:
    return {
        "status": r.status,
        "total_files": r.total_files,
        "mismatched": r.mismatched,
        "missing": r.missing,
        "added": r.added,
        "snapshot_at": r.snapshot_at,
        "snapshot_path": r.snapshot_path,
    }
