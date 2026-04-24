"""System + per-process telemetry.

Distinguishes the DEEPSecurity process from system-wide numbers so an
operator can tell "we're burning CPU" from "the rest of the OS is burning CPU".
"""
from __future__ import annotations

import os
from typing import Any

import psutil
from flask import Blueprint, jsonify

from deepsecurity.api.auth import require_role

system_bp = Blueprint("system", __name__)


def _safe(fn, default=None):  # type: ignore[no-untyped-def]
    try:
        return fn()
    except (psutil.Error, OSError):
        return default


@system_bp.route("/summary", methods=["GET"])
@require_role("admin", "security", "analyst")
def summary() -> Any:
    proc = psutil.Process(os.getpid())
    # Prime the CPU counter (first call returns 0.0 on most platforms).
    proc.cpu_percent(interval=None)

    with proc.oneshot():
        mem_info = _safe(proc.memory_info)
        cpu_self = _safe(lambda: proc.cpu_percent(interval=0.1), 0.0)
        num_threads = _safe(proc.num_threads, 0)
        open_files = len(_safe(proc.open_files, []) or [])
        connections = len(_safe(proc.net_connections, []) or [])
        create_time = _safe(proc.create_time, 0.0)

    vm = psutil.virtual_memory()
    sw = psutil.swap_memory()
    disk = _safe(lambda: psutil.disk_usage("/"), None)

    return jsonify(
        {
            "process": {
                "pid": proc.pid,
                "cpu_percent": round(float(cpu_self), 2),
                "rss_bytes": getattr(mem_info, "rss", 0) if mem_info else 0,
                "vms_bytes": getattr(mem_info, "vms", 0) if mem_info else 0,
                "threads": num_threads,
                "open_files": open_files,
                "open_sockets": connections,
                "started_at": create_time,
            },
            "system": {
                "cpu_percent": psutil.cpu_percent(interval=0.1),
                "cpu_count": psutil.cpu_count(logical=True) or 0,
                "ram_total_bytes": vm.total,
                "ram_used_bytes": vm.used,
                "ram_percent": vm.percent,
                "swap_percent": sw.percent,
                "disk_total_bytes": getattr(disk, "total", 0) if disk else 0,
                "disk_used_bytes": getattr(disk, "used", 0) if disk else 0,
                "disk_percent": getattr(disk, "percent", 0.0) if disk else 0.0,
                "boot_time": psutil.boot_time(),
            },
        }
    )


@system_bp.route("/integrity", methods=["GET"])
@require_role("admin", "security")
def integrity() -> Any:
    from deepsecurity.integrity import check, report_as_dict

    return jsonify(report_as_dict(check()))


@system_bp.route("/integrity/snapshot", methods=["POST"])
@require_role("admin")
def integrity_snapshot() -> Any:
    from deepsecurity.integrity import report_as_dict, snapshot

    return jsonify(report_as_dict(snapshot()))


@system_bp.route("/top", methods=["GET"])
@require_role("admin", "security")
def top_processes() -> Any:
    """Top 20 processes by CPU + RSS — for the operator to spot neighbours."""
    procs = []
    for p in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_info"]):
        try:
            info = p.info
            mem = info.get("memory_info")
            procs.append(
                {
                    "pid": info.get("pid"),
                    "name": info.get("name"),
                    "user": info.get("username"),
                    "cpu_percent": info.get("cpu_percent") or 0.0,
                    "rss_bytes": getattr(mem, "rss", 0) if mem else 0,
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    # Sort by CPU then RSS.
    procs.sort(key=lambda r: (r["cpu_percent"], r["rss_bytes"]), reverse=True)
    return jsonify({"processes": procs[:20]})
