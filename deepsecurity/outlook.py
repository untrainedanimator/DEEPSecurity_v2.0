"""Outlook attachment scanner (Windows only, opt-in).

Security-relevant changes from the v2.0 original:

    - NEVER calls `delete_file(..., soft_delete=False)` on a detection.
      Detections go to quarantine. The operator decides what to do next.

    - Gated behind `settings.outlook_enabled` AND `sys.platform == "win32"`.
      Calling this on non-Windows raises OutlookUnavailableError.

    - `settings.outlook_delete_on_detect` is frozen to False by the config
      layer. There is no runtime knob to turn it back on.
"""
from __future__ import annotations

import hashlib
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from deepsecurity.audit import audit_log
from deepsecurity.config import settings
from deepsecurity.logging_config import get_logger
from deepsecurity.ml import MLClassifier
from deepsecurity.scanner import load_signatures, quarantine_copy, scan_file

_log = get_logger(__name__)


class OutlookUnavailableError(RuntimeError):
    """Raised when Outlook scanning is requested but not supported."""


ALLOWED_EXTENSIONS: frozenset[str] = frozenset(
    {".exe", ".dll", ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".zip", ".js", ".vbs", ".ps1"}
)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_outlook_mailbox(
    *,
    actor: str,
    user_role: str,
) -> dict[str, Any]:
    """Scan attachments from Inbox / Sent / Outbox.

    Every detection is quarantined (copied to the quarantine directory).
    No message is deleted, no attachment is removed from the mailbox.
    """
    if not settings.outlook_enabled:
        raise OutlookUnavailableError("DEEPSEC_OUTLOOK_ENABLED is false")
    if sys.platform != "win32":
        raise OutlookUnavailableError("Outlook scanning is Windows-only")

    try:
        import pythoncom  # type: ignore[import-not-found]
        import win32com.client  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover — Windows-only
        raise OutlookUnavailableError(
            "pywin32 not installed — run `pip install .[windows]`"
        ) from exc

    ml = MLClassifier(settings.ml_model_path, settings.ml_confidence_threshold)
    signatures = load_signatures(settings.signature_path)

    total = 0
    detections = 0
    temp_dir = Path(tempfile.mkdtemp(prefix="deepsec_outlook_"))

    pythoncom.CoInitialize()
    try:
        outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
        folders = [outlook.GetDefaultFolder(i) for i in (6, 5, 4)]  # Inbox, Sent, Outbox
        seen_hashes: set[str] = set()

        for folder in folders:
            messages = folder.Items
            messages.Sort("[ReceivedTime]", True)
            for msg in messages:
                try:
                    attachments = getattr(msg, "Attachments", [])
                    for i in range(1, attachments.Count + 1):
                        att = attachments.Item(i)
                        fname = att.FileName
                        ext = Path(fname).suffix.lower()
                        if ext not in ALLOWED_EXTENSIONS:
                            continue

                        save_path = temp_dir / fname
                        att.SaveAsFile(str(save_path))
                        sha = _sha256(save_path)
                        if sha in seen_hashes:
                            continue
                        seen_hashes.add(sha)
                        total += 1

                        det = scan_file(
                            save_path,
                            signatures=signatures,
                            ml=ml,
                            quarantine_enabled=False,  # quarantine done explicitly below
                        )

                        action = "none"
                        if det.label == "malicious":
                            qpath = quarantine_copy(save_path)
                            action = f"quarantined:{qpath}"
                            detections += 1

                        audit_log(
                            actor=actor,
                            action="outlook.attachment",
                            status=det.label,
                            file_path=save_path,
                            details={
                                "role": user_role,
                                "sender": getattr(msg, "SenderEmailAddress", "unknown"),
                                "subject": getattr(msg, "Subject", "")[:200],
                                "sha256": sha,
                                "confidence": det.confidence,
                                "action": action,
                            },
                        )
                except Exception:  # noqa: BLE001 — per-message isolation
                    _log.exception("outlook.message_error")

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
        pythoncom.CoUninitialize()

    return {"total_attachments": total, "detections": detections}
