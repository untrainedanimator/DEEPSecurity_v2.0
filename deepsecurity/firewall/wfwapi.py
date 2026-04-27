"""Defender Firewall rule API (HNetCfg.FwPolicy2).

Programmatically add / remove / enable / disable Windows Defender
Firewall rules. Persistent — rules survive reboot. Slower than
WinDivert (rules are evaluated by the kernel firewall), but cleaner
for "block this destination forever" use-cases.

Optional dep: pywin32 (already in deepsecurity[windows]).

Usage:

    from deepsecurity.firewall.wfwapi import DefenderFirewall
    fw = DefenderFirewall()
    fw.add_block(name="deepsec-block-c2", remote_ip="203.0.113.42", direction="outbound")
    fw.remove("deepsec-block-c2")

Constants reference:
    NET_FW_PROFILE2_DOMAIN  = 0x1
    NET_FW_PROFILE2_PRIVATE = 0x2
    NET_FW_PROFILE2_PUBLIC  = 0x4
    NET_FW_PROFILE2_ALL     = 0x7
    NET_FW_RULE_DIR_IN      = 1
    NET_FW_RULE_DIR_OUT     = 2
    NET_FW_ACTION_BLOCK     = 0
    NET_FW_ACTION_ALLOW     = 1
    NET_FW_IP_PROTOCOL_TCP  = 6
    NET_FW_IP_PROTOCOL_UDP  = 17
    NET_FW_IP_PROTOCOL_ANY  = 256
"""

from __future__ import annotations

from typing import Any

from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)


_DIR = {"inbound": 1, "outbound": 2}
_PROTO = {"any": 256, "tcp": 6, "udp": 17}


class DefenderFirewall:
    """Thin wrapper around HNetCfg.FwPolicy2."""

    def __init__(self) -> None:
        self._policy: Any = None
        self._rules: Any = None
        try:
            import win32com.client  # type: ignore[import-not-found]
        except ImportError:
            _log.warning(
                "wfwapi.unavailable",
                hint='pip install "deepsecurity[windows]" (Windows-only)',
            )
            return
        try:
            self._policy = win32com.client.Dispatch("HNetCfg.FwPolicy2")
            self._rules = self._policy.Rules
            _log.info("wfwapi.connected")
        except Exception:
            _log.exception("wfwapi.connect_failed")

    @property
    def available(self) -> bool:
        return self._rules is not None

    # ------------------------------------------------------------------
    def add_block(
        self,
        *,
        name: str,
        remote_ip: str | None = None,
        remote_port: int | None = None,
        local_port: int | None = None,
        protocol: str = "any",
        direction: str = "outbound",
        program_path: str | None = None,
        description: str = "managed by DEEPSecurity",
    ) -> bool:
        return self._add(
            name=name,
            action=0,
            remote_ip=remote_ip,
            remote_port=remote_port,
            local_port=local_port,
            protocol=protocol,
            direction=direction,
            program_path=program_path,
            description=description,
        )

    def add_allow(self, **kwargs: Any) -> bool:
        return self._add(action=1, **kwargs)

    # ------------------------------------------------------------------
    def _add(
        self,
        *,
        name: str,
        action: int,
        remote_ip: str | None = None,
        remote_port: int | None = None,
        local_port: int | None = None,
        protocol: str = "any",
        direction: str = "outbound",
        program_path: str | None = None,
        description: str = "managed by DEEPSecurity",
    ) -> bool:
        if not self.available:
            return False
        try:
            import win32com.client  # type: ignore[import-not-found]

            rule = win32com.client.Dispatch("HNetCfg.FWRule")
            rule.Name = name
            rule.Description = description
            rule.Direction = _DIR.get(direction, 2)
            rule.Enabled = True
            rule.Profiles = 0x7  # all profiles
            rule.Action = action
            rule.Protocol = _PROTO.get(protocol, 256)
            if remote_ip:
                rule.RemoteAddresses = remote_ip
            if remote_port is not None:
                rule.RemotePorts = str(remote_port)
            if local_port is not None:
                rule.LocalPorts = str(local_port)
            if program_path:
                rule.ApplicationName = program_path
            self._rules.Add(rule)
            _log.info(
                "wfwapi.rule_added",
                name=name,
                direction=direction,
                action=action,
                remote=remote_ip,
            )
            return True
        except Exception:
            _log.exception("wfwapi.rule_add_failed", name=name)
            return False

    # ------------------------------------------------------------------
    def remove(self, name: str) -> bool:
        if not self.available:
            return False
        try:
            self._rules.Remove(name)
            _log.info("wfwapi.rule_removed", name=name)
            return True
        except Exception:
            _log.exception("wfwapi.rule_remove_failed", name=name)
            return False

    # ------------------------------------------------------------------
    def list_managed(self, prefix: str = "deepsec-") -> list[dict[str, Any]]:
        """Return our own rules (those whose name starts with ``prefix``)."""
        if not self.available:
            return []
        out: list[dict[str, Any]] = []
        try:
            for r in self._rules:
                if not getattr(r, "Name", "").lower().startswith(prefix.lower()):
                    continue
                out.append(
                    {
                        "name": r.Name,
                        "direction": r.Direction,
                        "action": r.Action,
                        "enabled": bool(r.Enabled),
                        "protocol": r.Protocol,
                        "remote_addresses": r.RemoteAddresses,
                        "remote_ports": r.RemotePorts,
                        "program": r.ApplicationName,
                    }
                )
        except Exception:
            _log.exception("wfwapi.list_failed")
        return out
