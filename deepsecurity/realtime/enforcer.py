"""Policy enforcer — turn a Detection into an action.

Per-severity policy:

    severity   default action
    --------   --------------
    info       audit-log only
    low        audit-log + alert
    medium     audit-log + alert
    high       audit-log + alert + (optional) kill
    critical   audit-log + alert + kill (if auto_kill enabled)

Killing requires our token to have the right to terminate the target.
On Windows that means the same UID OR Administrator. The enforcer is
deliberately conservative — auto-kill is OFF by default and gated by
``DEEPSEC_AUTO_KILL_KNOWN_BAD`` (already in v2.5 config).

The enforcer never deletes files. Quarantine = COPY only, same as the
v2.5 scanner.quarantine_copy() contract.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from deepsecurity.alerts import AlertEvent
from deepsecurity.alerts import bus as alert_bus
from deepsecurity.audit import audit_log
from deepsecurity.config import settings
from deepsecurity.logging_config import get_logger
from deepsecurity.realtime.correlator import Detection

_log = get_logger(__name__)


_KILL_SEVERITIES = {"critical"}
_KILL_AND_ALERT_SEVERITIES = {"high", "critical"}


def handle(detection: Detection) -> dict[str, Any]:
    """Apply the configured policy. Returns a structured outcome dict."""
    outcome = {
        "rule_id": detection.rule_id,
        "severity": detection.severity,
        "audited": False,
        "alerted": False,
        "killed": False,
    }

    # 1. Always audit-log the detection.
    try:
        audit_log(
            actor="deepsec.realtime",
            action=f"detection.{detection.rule_id}",
            status=detection.severity,
            details={
                "summary": detection.summary,
                "pid": detection.pid,
                "image": detection.image,
                "mitre_tags": list(detection.mitre_tags),
                "evidence": detection.evidence,
            },
        )
        outcome["audited"] = True
    except Exception:
        _log.exception("enforcer.audit_failed", rule=detection.rule_id)

    # 2. Alert at medium and above.
    if detection.severity in {"medium", "high", "critical"}:
        try:
            alert_bus.dispatch(
                AlertEvent(
                    kind=f"realtime.{detection.rule_id}",
                    severity=detection.severity,
                    summary=detection.summary,
                    file_path=None,
                    details={
                        "pid": detection.pid,
                        "image": detection.image,
                        "mitre_tags": list(detection.mitre_tags),
                        **detection.evidence,
                    },
                )
            )
            outcome["alerted"] = True
        except Exception:
            _log.exception("enforcer.alert_failed", rule=detection.rule_id)

    # 3. Optionally kill on critical (and high-with-auto-kill).
    auto = bool(getattr(settings, "auto_kill_known_bad", False))
    if detection.pid is not None and (
        detection.severity in _KILL_SEVERITIES
        or (auto and detection.severity in _KILL_AND_ALERT_SEVERITIES)
    ):
        outcome["killed"] = _kill(detection.pid)

    # 4. v3.1 — lateral-movement auto-block. Opt-in via env. When the
    # detection is R-LM-01 (lateral movement), add a Defender FW deny
    # rule for the offending image path. We block by image, not PID —
    # PIDs are short-lived; the image is the persistent identity.
    if (
        detection.rule_id == "R-LM-01"
        and bool(getattr(settings, "lateral_movement_block", False))
        and detection.image
    ):
        outcome["fw_blocked"] = _fw_block_image(detection)

    return outcome


def _fw_block_image(detection: Detection) -> bool:
    """Add a Defender FW outbound-deny rule for ``detection.image``.

    Rule name carries the timestamp + rule_id so an operator can
    identify and remove our additions later. We don't currently
    auto-expire — that's a v3.2 follow-up. Operators clean up via
    ``netsh advfirewall firewall delete rule name="DEEPSEC_LM_*"``.
    """
    try:
        import datetime as _dt

        from deepsecurity.firewall.wfwapi import DefenderFirewall

        fw = DefenderFirewall()
        if not fw.available:
            _log.warning("enforcer.fw_block_unavailable", rule=detection.rule_id)
            return False
        ts = _dt.datetime.now(_dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        ok = fw.add_block(
            name=f"DEEPSEC_LM_{ts}_{detection.rule_id}",
            program_path=detection.image,
            direction="outbound",
            description=(
                f"DEEPSecurity v3.1 auto-block — {detection.rule_id} "
                f"on pid={detection.pid} ({detection.summary})"
            ),
        )
        if ok:
            try:
                audit_log(
                    actor="deepsec.realtime",
                    action="firewall.lateral_block",
                    status="ok",
                    file_path=detection.image,
                    details={
                        "rule_id": detection.rule_id,
                        "pid": detection.pid,
                        "summary": detection.summary,
                        **detection.evidence,
                    },
                )
            except Exception:
                _log.exception("enforcer.fw_block.audit_failed")
            _log.info(
                "enforcer.fw_blocked",
                rule=detection.rule_id,
                image=detection.image,
            )
        else:
            _log.warning("enforcer.fw_block_rejected", image=detection.image)
        return bool(ok)
    except Exception:
        _log.exception("enforcer.fw_block_crashed", rule=detection.rule_id)
        return False


def _kill(pid: int) -> bool:
    """Best-effort terminate. Returns True iff the OS confirmed.

    On POSIX uses os.kill(pid, SIGKILL). On Windows uses psutil if
    available (which calls TerminateProcess).
    """
    try:
        import psutil

        psutil.Process(pid).kill()
        _log.info("enforcer.killed", pid=pid)
        return True
    except Exception as exc:
        _log.warning("enforcer.kill_failed", pid=pid, error=str(exc))
        return False


def detection_to_dict(d: Detection) -> dict[str, Any]:
    """Serialisable view of a Detection — used by tests and the API."""
    return {**asdict(d), "mitre_tags": list(d.mitre_tags)}
