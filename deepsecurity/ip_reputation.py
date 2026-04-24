"""IP reputation — check a remote address against a locally-cached deny-list.

Uses abuse.ch Feodo Tracker (banking-trojan C2 IPs, free) as the default
feed. The list is refreshed by `deepsec intel-update` or
POST /api/intel/update. Lookups are in-memory set operations.

Honest caveats:
  - abuse.ch is a solid feed but not exhaustive. Real-world attackers use
    cloud IPs that rotate faster than any public feed tracks.
  - Private-range IPs (10.x, 192.168.x, 127.x) are ignored — they can't
    be attacker C2 and false hits on them are just noise.
"""
from __future__ import annotations

import ipaddress
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from deepsecurity.audit import audit_log
from deepsecurity.config import settings
from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)

FEODO_IP_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"


class IPReputation:
    def __init__(self, path: Path | None = None) -> None:
        self._path = path or settings.ip_reputation_path
        self._lock = threading.Lock()
        self._bad: set[str] = set()
        self._load_from_disk()

    @property
    def enabled(self) -> bool:
        return settings.ip_reputation_enabled

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._bad)

    def _load_from_disk(self) -> None:
        if not self._path.exists():
            return
        try:
            loaded: set[str] = set()
            for line in self._path.read_text(encoding="utf-8").splitlines():
                s = line.strip()
                if s and not s.startswith("#"):
                    loaded.add(s)
            with self._lock:
                self._bad = loaded
            _log.info("ip_reputation.loaded", count=len(loaded), path=str(self._path))
        except OSError:
            _log.exception("ip_reputation.load_failed", path=str(self._path))

    def lookup(self, ip: str) -> dict[str, Any]:
        if not ip or not self.enabled:
            return {"known_bad": False, "reason": "disabled" if not self.enabled else "no_ip"}
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return {"known_bad": False, "reason": "private_range"}
        except ValueError:
            return {"known_bad": False, "reason": "invalid_ip"}

        with self._lock:
            hit = ip in self._bad
        if hit:
            return {"known_bad": True, "source": "abuse.ch/feodotracker"}
        return {"known_bad": False}

    def refresh(self, url: str = FEODO_IP_URL, timeout: float = 30.0) -> dict[str, Any]:
        """Pull the latest list and atomically replace the cache. Returns
        per-refresh stats. Never raises."""
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
                raw = resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError) as exc:
            return {"refreshed": False, "error": str(exc)}

        ips: set[str] = set()
        for line in raw.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            try:
                ipaddress.ip_address(s)
                ips.add(s)
            except ValueError:
                continue

        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(self._path.suffix + ".tmp")
            tmp.write_text(
                "# DEEPSecurity IP reputation cache\n"
                "# source: abuse.ch Feodo Tracker\n"
                + "\n".join(sorted(ips))
                + "\n",
                encoding="utf-8",
            )
            tmp.replace(self._path)
        except OSError as exc:
            return {"refreshed": False, "error": f"write_failed: {exc}"}

        with self._lock:
            added = len(ips - self._bad)
            removed = len(self._bad - ips)
            self._bad = ips

        audit_log(
            actor="system",
            action="ip_reputation.refresh",
            status="ok",
            details={"count": len(ips), "added": added, "removed": removed},
        )
        return {"refreshed": True, "count": len(ips), "added": added, "removed": removed}


reputation = IPReputation()
