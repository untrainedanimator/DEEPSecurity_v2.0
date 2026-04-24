"""Agent main loop.

Cycle:
    1. heartbeat (with a small system summary)
    2. if heartbeat response's policy_sha ≠ local, fetch + persist
       the new policy (FLEET_POLICY, v2.4)
    3. pull pending commands
    4. execute each locally
    5. post result
    6. sleep
"""
from __future__ import annotations

import json
import os
import platform
import time
from pathlib import Path
from typing import Any

from deepsecurity.agent import __version__
from deepsecurity.agent.config import AgentConfig
from deepsecurity.agent.transport import AgentTransport, TransportError
from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)


def _policy_file_for(cfg: AgentConfig) -> Path:
    """Where the agent persists the most-recent pushed policy on disk.

    Sits next to the agent config file so the operator can inspect it.
    """
    cfg_path = Path(cfg.path) if hasattr(cfg, "path") else Path("deepsec-agent.json")
    return cfg_path.parent / "deepsec-agent.policy.json"


def _load_local_policy(cfg: AgentConfig) -> dict[str, Any]:
    """Read the cached policy (sha + body) from disk. Empty dict if absent."""
    p = _policy_file_for(cfg)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _log.warning("agent.policy.local_read_failed", error=str(exc))
        return {}


def _save_local_policy(cfg: AgentConfig, policy: dict[str, Any]) -> None:
    """Write the cached policy (sha + body) to disk atomically."""
    p = _policy_file_for(cfg)
    tmp = p.with_suffix(p.suffix + ".tmp")
    try:
        tmp.write_text(json.dumps(policy, indent=2), encoding="utf-8")
        tmp.replace(p)
        _log.info("agent.policy.applied", sha=policy.get("policy_sha", "")[:12])
    except OSError as exc:
        _log.warning("agent.policy.local_write_failed", error=str(exc))


def _maybe_fetch_and_apply_policy(
    transport: AgentTransport, cfg: AgentConfig, server_policy_sha: str
) -> None:
    """On policy_sha mismatch, fetch the full policy and persist locally.

    Why separate persistence from "application": hot-applying every
    policy field at runtime (watchdog scope reload, DLP override hot-
    swap, signatures.txt re-download) is a bigger surface than one
    commit can ship cleanly. For v2.4 the policy is persisted and logged;
    subsequent command invocations read from the cached policy file.
    """
    if not server_policy_sha:
        return  # no policy set server-side

    local = _load_local_policy(cfg)
    if local.get("policy_sha") == server_policy_sha:
        return  # already in sync

    try:
        fresh = transport.get_policy()
    except TransportError as exc:
        _log.warning("agent.policy.fetch_failed", error=str(exc))
        return

    # fresh shape: {policy_sha, policy, updated_at, updated_by}
    if fresh.get("policy_sha") != server_policy_sha:
        _log.warning(
            "agent.policy.sha_drift",
            heartbeat_sha=server_policy_sha,
            fetched_sha=fresh.get("policy_sha"),
        )
        # Still persist — the operator's latest wins.

    _save_local_policy(cfg, fresh)


def _system_summary() -> dict[str, Any]:
    """Lightweight host fingerprint sent with every heartbeat."""
    try:
        import psutil

        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent
    except Exception:
        cpu = 0.0
        ram = 0.0

    return {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_version": platform.version(),
        "agent_version": __version__,
        "cpu_percent": cpu,
        "ram_percent": ram,
        "pid": os.getpid(),
    }


# ---------------------------------------------------------------------------
# Command dispatcher
# ---------------------------------------------------------------------------


def execute_command(cmd: dict[str, Any]) -> tuple[bool, Any]:
    """Run one command locally. Returns (success, result)."""
    kind = cmd["kind"]
    payload = cmd.get("payload") or {}

    try:
        if kind == "scan":
            from deepsecurity.scanner import scan_directory
            from pathlib import Path

            path = payload.get("path")
            if not path:
                return False, {"error": "missing_path"}
            summary = scan_directory(
                Path(path),
                actor="agent",
                user_role="admin",
                quarantine_enabled=bool(payload.get("quarantine", True)),
            )
            return True, summary

        if kind == "kill":
            from deepsecurity.processes import kill_process

            pid = payload.get("pid")
            force = bool(payload.get("force", False))
            if not isinstance(pid, int):
                return False, {"error": "bad_pid"}
            return True, kill_process(pid, force=force)

        if kind == "watchdog_start":
            from deepsecurity.watchdog_monitor import controller

            return True, controller.start(
                paths=payload.get("paths"),
                scope=payload.get("scope"),
            )

        if kind == "watchdog_stop":
            from deepsecurity.watchdog_monitor import controller

            return True, controller.stop()

        if kind == "processes_scan":
            from deepsecurity.processes import scan_all_processes
            from deepsecurity.config import settings

            rows = scan_all_processes(
                auto_kill_known_bad=settings.auto_kill_known_bad,
            )
            # Drop cmdline + parent_chain verbosity before upload.
            trimmed = [
                {
                    k: v
                    for k, v in r.items()
                    if k in {"pid", "name", "user", "cpu_percent", "rss_bytes",
                             "label", "reasons", "mitre_tags"}
                }
                for r in rows
            ]
            return True, {
                "total": len(trimmed),
                "flagged": [r for r in trimmed if r["label"] != "clean"],
            }

        if kind == "self_test":
            return True, {
                "alive": True,
                "hostname": platform.node(),
                "agent_version": __version__,
            }

        if kind == "intel_update":
            from deepsecurity.threat_intel import update_all_feeds

            results = update_all_feeds()
            return True, [
                {
                    "feed": r.name,
                    "fetched": r.fetched,
                    "added": r.added,
                    "error": r.error,
                }
                for r in results
            ]

        return False, {"error": "unknown_kind", "kind": kind}

    except Exception as exc:  # noqa: BLE001
        _log.exception("agent.command_failed", kind=kind)
        return False, {"error": "exception", "detail": f"{type(exc).__name__}: {exc}"}


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


def run(cfg: AgentConfig, *, interval_seconds: float = 30.0) -> None:
    """Run forever. Caller (service wrapper / CLI) decides how this exits."""
    if not cfg.registered:
        raise RuntimeError("agent is not registered — run `deepsec-agent register` first")

    transport = AgentTransport(
        server_url=cfg.server_url,
        agent_id=cfg.agent_id,
        api_key=cfg.api_key,
    )
    _log.info(
        "agent.starting",
        server=cfg.server_url,
        agent_id=cfg.agent_id,
        hostname=platform.node(),
    )

    backoff = 1.0
    while True:
        try:
            hb_response = transport.heartbeat(_system_summary())
            backoff = 1.0  # reset on success
        except TransportError as exc:
            _log.warning("agent.heartbeat_failed", error=str(exc), backoff=backoff)
            time.sleep(min(backoff, 300.0))
            backoff *= 2
            continue

        # v2.4 FLEET_POLICY — reconcile local policy with whatever the
        # server's saying. Errors here are logged but never abort the
        # cycle: falling back to env-var defaults is always safe.
        try:
            _maybe_fetch_and_apply_policy(
                transport, cfg, str(hb_response.get("policy_sha", ""))
            )
        except Exception:  # noqa: BLE001
            _log.exception("agent.policy.apply_failed")

        try:
            commands = transport.pull_commands()
        except TransportError as exc:
            _log.warning("agent.pull_failed", error=str(exc))
            commands = []

        for cmd in commands:
            cid = cmd.get("command_id")
            success, result = execute_command(cmd)
            try:
                transport.post_result(int(cid), success, result)
            except TransportError as exc:
                _log.warning("agent.post_result_failed", error=str(exc), command_id=cid)

        time.sleep(interval_seconds)
