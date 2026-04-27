"""Declarative firewall policy — single source of truth for both mechanisms.

The same policy file feeds both:
    - WinDivert packet matcher (inline drop)
    - Defender Firewall rule generator (persistent)

Rule shape:

    FirewallRule(
        name="block-known-c2",
        direction="outbound",            # "inbound" | "outbound"
        action="drop",                   # "drop" | "allow" | "alert"
        protocol="tcp",                  # "tcp" | "udp" | "any"
        remote_ip="203.0.113.42",        # CIDR or single
        remote_port=443,                 # int or None
        local_port=None,
        process_image=None,              # "C:\\Path\\bad.exe" or None
        severity="high",
    )
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path

from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)


@dataclass(frozen=True)
class FirewallRule:
    name: str
    direction: str  # inbound | outbound
    action: str  # drop | allow | alert
    protocol: str = "any"  # tcp | udp | icmp | any
    remote_ip: str | None = None
    remote_port: int | None = None
    local_port: int | None = None
    process_image: str | None = None
    severity: str = "medium"  # info | low | medium | high | critical

    def matches(
        self,
        *,
        direction: str,
        protocol: str,
        remote_ip: str | None,
        remote_port: int | None,
        local_port: int | None,
        image: str | None,
    ) -> bool:
        """True iff this rule applies to a packet/connection with these attrs."""
        if self.direction != direction:
            return False
        if self.protocol not in ("any", protocol):
            return False
        if self.remote_ip and not _ip_matches(remote_ip, self.remote_ip):
            return False
        if self.remote_port is not None and remote_port != self.remote_port:
            return False
        if self.local_port is not None and local_port != self.local_port:
            return False
        if self.process_image and self.process_image.lower() != (image or "").lower():
            return False
        return True


def _ip_matches(addr: str | None, target: str) -> bool:
    if not addr:
        return False
    try:
        if "/" in target:
            return ipaddress.ip_address(addr) in ipaddress.ip_network(target, strict=False)
        return addr == target
    except ValueError:
        return False


@dataclass
class FirewallPolicy:
    rules: list[FirewallRule] = field(default_factory=list)

    def evaluate(
        self,
        *,
        direction: str,
        protocol: str,
        remote_ip: str | None = None,
        remote_port: int | None = None,
        local_port: int | None = None,
        image: str | None = None,
    ) -> FirewallRule | None:
        """Return the first rule that matches, or None for default-allow."""
        for r in self.rules:
            if r.matches(
                direction=direction,
                protocol=protocol,
                remote_ip=remote_ip,
                remote_port=remote_port,
                local_port=local_port,
                image=image,
            ):
                return r
        return None


def load(path: Path) -> FirewallPolicy:
    """Load a JSON policy file. Missing file yields an empty policy."""
    if not path.exists():
        _log.info("firewall.policy_absent", path=str(path))
        return FirewallPolicy()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _log.exception("firewall.policy_load_failed", path=str(path))
        return FirewallPolicy()
    rules = [FirewallRule(**r) for r in data.get("rules", [])]
    return FirewallPolicy(rules=rules)
