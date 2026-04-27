"""v3.0 BEASTMODE status surface.

One endpoint, one shape — ``GET /api/v3/status`` returns everything the
dashboard needs to render the v3 panel:

    * Realtime: ETW providers, Sysmon channel, WinDivert, Defender FW
    * Audit sinks: webhook / syslog / file — configured + queue depth
    * TLS: mode (off / cert / self-signed) + cert expiry + HSTS
    * Platform: OS detection + capability matrix (Windows / Linux / macOS)
    * Mitigations: which process-mitigation policies the host accepted

Read-only, cheap (no live network calls), authenticated. Frontend polls
this every few seconds for a live status panel; we deliberately keep it
under one DB round-trip so a slow endpoint can't drag the dashboard.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from flask import Blueprint, jsonify

from deepsecurity.api.auth import require_role
from deepsecurity.config import settings
from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)

v3_bp = Blueprint("v3", __name__)


# ---------------------------------------------------------------------------
# Sub-collectors. Each returns a small dict; failures fall back to
# ``{"available": False, "error": "..."}`` so a partial outage doesn't
# blank the whole status page.
# ---------------------------------------------------------------------------


def _probe_defender_fw() -> dict[str, Any]:
    """COM-thread-safe Defender Firewall probe.

    Initialises COM on this (Flask worker) thread, instantiates the
    Defender Firewall wrapper, reads the connection state, then tears
    COM back down so the worker thread isn't permanently dirty.
    """
    com_initialised_here = False
    try:
        try:
            import pythoncom  # type: ignore[import-not-found]
        except ImportError:
            return {
                "available": False,
                "error": "pythoncom not importable — pywin32 missing on this thread",
            }

        # CoInitialize is idempotent per-thread; if Flask or another
        # subsystem already did it, this is a no-op and we don't try
        # to uninitialise. ``CoInitializeEx`` returns S_OK (0) on first
        # init or S_FALSE (1) when already initialised.
        try:
            pythoncom.CoInitialize()
            com_initialised_here = True
        except Exception:
            # Already initialised in a different model — that's fine.
            com_initialised_here = False

        from deepsecurity.firewall.wfwapi import DefenderFirewall

        fw = DefenderFirewall()
        connected = getattr(fw, "_policy", None) is not None
        out: dict[str, Any] = {"available": connected}
        if connected:
            try:
                out["rule_count"] = int(fw._rules.Count)
            except Exception:
                pass
        return out
    except Exception as exc:
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        # Only uninitialise if we initialised — otherwise we'd tear down
        # COM out from under another caller on this thread.
        if com_initialised_here:
            try:
                import pythoncom  # type: ignore[import-not-found]

                pythoncom.CoUninitialize()
            except Exception:
                pass


def _realtime_status() -> dict[str, Any]:
    """ETW + Sysmon + WinDivert + Defender FW + DNS + memory scan."""
    out: dict[str, Any] = {}

    # ETW. ``pywintrace`` exposes the module as ``etw``. Provider list lives
    # on ``EtwListener.PROVIDERS`` as a class attribute, not a module constant.
    try:
        import etw  # type: ignore[import-not-found]

        from deepsecurity.realtime.etw import EtwListener

        out["etw"] = {
            "available": True,
            "providers": list(EtwListener.PROVIDERS),
            "module": "pywintrace",
            "version": getattr(etw, "__version__", "unknown"),
        }
    except ImportError:
        out["etw"] = {
            "available": False,
            "hint": 'pip install "deepsecurity[edr]"',
        }
    except Exception as exc:  # pragma: no cover  # defensive
        out["etw"] = {"available": False, "error": f"{type(exc).__name__}: {exc}"}

    # Sysmon channel.
    try:
        import win32evtlog  # type: ignore[import-not-found]

        from deepsecurity.realtime.sysmon import CHANNEL, _channel_exists

        installed = _channel_exists(win32evtlog, CHANNEL)
        out["sysmon"] = {
            "available": True,
            "channel": CHANNEL,
            "installed": installed,
            "consumer_class": "SysmonConsumer",
        }
    except ImportError:
        out["sysmon"] = {
            "available": False,
            "hint": 'pip install "deepsecurity[windows-edr]"',
        }
    except Exception as exc:  # pragma: no cover
        out["sysmon"] = {"available": False, "error": f"{type(exc).__name__}: {exc}"}

    # WinDivert.
    try:
        import pydivert  # type: ignore[import-not-found]

        out["windivert"] = {
            "available": True,
            "version": getattr(pydivert, "__version__", "unknown"),
        }
    except ImportError:
        out["windivert"] = {
            "available": False,
            "hint": 'pip install "deepsecurity[firewall]"',
        }
    except Exception as exc:  # pragma: no cover
        out["windivert"] = {"available": False, "error": f"{type(exc).__name__}: {exc}"}

    # Defender Firewall (HNetCfg.FwPolicy2 COM).
    #
    # COM Dispatch fails on threads that haven't called CoInitialize. Flask
    # request handlers run in a worker thread where this hasn't happened —
    # so a naive ``DefenderFirewall()`` from the request thread reports
    # "unavailable" even when the underlying COM object is reachable from
    # the main thread (proven by ``verify_v3_beastmode.py`` showing
    # ``wfwapi.connected``). Initialise COM for this thread before probing,
    # then uninitialise on the way out so we don't leak state.
    out["defender_fw"] = _probe_defender_fw()

    # DNS sinkhole — config-only check (don't actually start it).
    out["dns_sinkhole"] = {
        "configured_bind": getattr(settings, "dns_sinkhole_bind", "127.0.0.1"),
        "configured_port": getattr(settings, "dns_sinkhole_port", 53),
        "blocklist_path": str(getattr(settings, "dns_sinkhole_blocklist_path", "")),
    }

    # Memory scanner — simple presence check.
    try:
        from deepsecurity.memory_scan.inspector import scan_pid  # noqa: F401

        out["memory_scan"] = {"available": True}
    except Exception as exc:
        out["memory_scan"] = {"available": False, "error": f"{type(exc).__name__}: {exc}"}

    return out


def _audit_sinks_status() -> dict[str, Any]:
    """Configured external audit sinks + queue depth."""
    try:
        from deepsecurity import audit_sinks

        sink = audit_sinks.get_global()
    except Exception as exc:
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}

    if sink is None:
        # No env vars set → no replication configured. That's a valid
        # state, not an error.
        return {
            "configured": False,
            "sinks": [],
            "queue_size": 0,
            "dropped": 0,
        }

    try:
        return {
            "configured": True,
            "sinks": [s.name for s in sink._sinks],
            "queue_size": sink._queue.qsize(),
            "queue_max": sink._queue.maxsize,
            "batch_size": sink._batch_size,
            "flush_interval_s": sink._flush_interval,
            "dropped": sink.dropped,
        }
    except Exception as exc:
        return {"configured": True, "error": f"{type(exc).__name__}: {exc}"}


def _tls_status() -> dict[str, Any]:
    """TLS mode + cert details (if applicable)."""
    mode = getattr(settings, "tls_mode", "off")
    out: dict[str, Any] = {
        "mode": mode,
        "hsts_max_age": int(getattr(settings, "tls_hsts_max_age", 31_536_000)),
    }
    if mode == "off":
        out["hint"] = "TLS termination expected at reverse proxy / Ingress"
        return out

    cert_path = settings.tls_cert
    if not cert_path:
        from deepsecurity.tls_runtime import default_cert_path

        cert_path = default_cert_path()
    cert_path = Path(cert_path)
    out["cert_path"] = str(cert_path)
    out["cert_exists"] = cert_path.exists()
    if cert_path.exists():
        try:
            from cryptography import x509

            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            not_after = cert.not_valid_after_utc
            now = datetime.now(UTC)
            days_remaining = (not_after - now).days
            out["cert_not_after"] = not_after.isoformat()
            out["cert_days_remaining"] = days_remaining
            out["cert_subject"] = cert.subject.rfc4514_string()
        except Exception as exc:
            out["cert_parse_error"] = f"{type(exc).__name__}: {exc}"
    return out


def _platform_status() -> dict[str, Any]:
    """OS detection + realtime capability matrix."""
    try:
        from deepsecurity.realtime.platform import detect_capabilities

        caps = detect_capabilities()
        return {
            "os_name": caps.os_name,
            "os_release": caps.os_release,
            "is_windows": caps.is_windows(),
            "is_linux": caps.is_linux(),
            "is_darwin": caps.is_darwin(),
            "realtime_supported": caps.realtime_supported(),
            "capabilities": {
                "etw": caps.has_etw,
                "sysmon": caps.has_sysmon,
                "windivert": caps.has_windivert,
                "defender_fw": caps.has_defender_fw,
                "ebpf": caps.has_ebpf,
                "auditd": caps.has_auditd,
                "endpoint_security": caps.has_endpoint_security,
            },
            "notes": list(caps.notes),
        }
    except Exception as exc:
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}


def _mitigations_status() -> dict[str, Any]:
    """Process-mitigation layer status.

    The protection layer is a single boolean switch
    (``protection_mitigations_enabled``) that triggers all five SetProcess-
    MitigationPolicy calls when the server boots. There are no per-policy
    config flags — Windows tells us at apply-time which it accepted, and
    the result is logged at boot. We expose:

      * ``layer_enabled`` — operator's switch
      * ``policies`` — the five we attempt, each with whether it's
        attempted (always true when layer_enabled) and the
        Windows-version ceiling note where applicable

    For ground-truth on what's applied, run ``verify_v3_beastmode.py``.
    """
    try:
        from deepsecurity.protection import mitigations as mit

        layer_enabled = bool(getattr(settings, "protection_mitigations_enabled", False))
        policies = [
            "dynamic_code_prohibit",
            "extension_point_disable",
            "strict_handle_check",
            "image_load_no_remote",
            "child_process_disallow",
        ]
        return {
            "available": True,
            "layer_enabled": layer_enabled,
            "attempted": dict.fromkeys(policies, layer_enabled),
            "ground_truth_hint": "run scripts/verify_v3_beastmode.py for live apply results",
            "module": mit.__name__,
        }
    except Exception as exc:
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@v3_bp.route("/status", methods=["GET"])
@require_role("admin", "security", "analyst")
def status() -> Any:
    """One-shot v3 status. Cheap, read-only, no DB hit."""
    return jsonify(
        {
            "version": "3.0.0",
            "ts": datetime.now(UTC).isoformat(),
            "realtime": _realtime_status(),
            "audit_sinks": _audit_sinks_status(),
            "tls": _tls_status(),
            "platform": _platform_status(),
            "mitigations": _mitigations_status(),
        }
    ), 200
