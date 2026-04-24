"""Network surface visibility — open ports, established connections.

Not a firewall. A view of what's listening and what's talking, so an
operator can notice "why is port 4444 open?" or "who opened this
connection to a suspicious IP?"

Cross-platform via psutil. On Windows / macOS some fields (pid, process
name) may be unavailable without elevated privileges; in that case we
surface what we can and say so.
"""
from __future__ import annotations

from typing import Any

import psutil
from flask import Blueprint, jsonify, request

from deepsecurity.api.auth import require_role
from deepsecurity.ip_reputation import reputation

network_bp = Blueprint("network", __name__)


# Map psutil connection-family and type constants to readable strings.
_FAMILY = {
    getattr(__import__("socket"), "AF_INET", 2): "ipv4",
    getattr(__import__("socket"), "AF_INET6", 23): "ipv6",
    getattr(__import__("socket"), "AF_UNIX", 1): "unix",
}
_KIND = {
    getattr(__import__("socket"), "SOCK_STREAM", 1): "tcp",
    getattr(__import__("socket"), "SOCK_DGRAM", 2): "udp",
}


def _addr(a: Any) -> dict[str, Any]:
    if a is None or a == ():
        return {}
    try:
        return {"ip": a.ip, "port": a.port}
    except AttributeError:
        # It might be a simple tuple (ip, port) on some psutil paths.
        try:
            return {"ip": a[0], "port": a[1]}
        except Exception:
            return {}


def _process_name(pid: int | None) -> str | None:
    if not pid:
        return None
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


@network_bp.route("/connections", methods=["GET"])
@require_role("admin", "security", "analyst")
def connections() -> Any:
    """List all TCP/UDP sockets visible to this process.

    Query params:
      - kind: "all" | "inet" | "inet4" | "inet6" | "tcp" | "udp" (default: "inet")
      - state: "LISTEN" | "ESTABLISHED" | "any" (default: "any")
    """
    kind = request.args.get("kind", "inet")
    state = request.args.get("state", "any").upper()

    try:
        raw = psutil.net_connections(kind=kind)
    except (psutil.AccessDenied, PermissionError):
        return jsonify({"error": "insufficient_privileges",
                        "message": "psutil.net_connections requires elevated rights on this OS"}), 403

    out: list[dict[str, Any]] = []
    for c in raw:
        if state != "ANY" and c.status != state:
            continue
        remote = _addr(c.raddr)
        row = {
            "family": _FAMILY.get(c.family, str(c.family)),
            "kind": _KIND.get(c.type, str(c.type)),
            "local": _addr(c.laddr),
            "remote": remote,
            "status": c.status,
            "pid": c.pid,
            "process": _process_name(c.pid),
            "reputation": reputation.lookup(remote.get("ip", "")) if remote else {"known_bad": False},
        }
        out.append(row)

    listening = [x for x in out if x["status"] == "LISTEN"]
    known_bad = sum(1 for x in out if x.get("reputation", {}).get("known_bad"))
    return jsonify(
        {
            "total": len(out),
            "listening": len(listening),
            "known_bad_remotes": known_bad,
            "reputation_size": reputation.size,
            "connections": out,
        }
    )


@network_bp.route("/io", methods=["GET"])
@require_role("admin", "security", "analyst")
def io_counters() -> Any:
    """Bytes in / out per interface — basic network-activity telemetry."""
    try:
        per_nic = psutil.net_io_counters(pernic=True)
    except Exception:
        return jsonify({"error": "unavailable"}), 503

    out = {}
    for name, c in per_nic.items():
        out[name] = {
            "bytes_sent": c.bytes_sent,
            "bytes_recv": c.bytes_recv,
            "packets_sent": c.packets_sent,
            "packets_recv": c.packets_recv,
            "errin": c.errin,
            "errout": c.errout,
            "dropin": c.dropin,
            "dropout": c.dropout,
        }
    return jsonify({"interfaces": out})
