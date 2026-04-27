"""WinDivert-backed inline packet filter.

WinDivert is a Microsoft-signed kernel driver shipped pre-signed inside
the ``pydivert`` Python package — no driver-signing chore for us, no
Microsoft attestation needed. We open a divert handle on a BPF-style
filter expression, every matched packet flows through user-space, we
choose to forward or drop.

This is a real userland firewall. Latency is ~50 µs per packet on
modern hardware.

Optional dep:
    pip install "deepsecurity[firewall]"  # pulls pydivert

Usage:

    from deepsecurity.firewall.windivert import WinDivertFilter
    from deepsecurity.firewall.policy import load
    f = WinDivertFilter(load(Path("data/firewall.json")))
    f.start()
    ...
    f.stop()
"""

from __future__ import annotations

import threading
from typing import Any

from deepsecurity.firewall.policy import FirewallPolicy
from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)


# A reasonable default filter — matches all outbound IP traffic. Tighten
# in production to reduce overhead.
DEFAULT_FILTER = "outbound and ip"


class WinDivertFilter:
    """Pump packets through a divert handle, applying the FirewallPolicy."""

    def __init__(self, policy: FirewallPolicy, *, divert_filter: str = DEFAULT_FILTER) -> None:
        self._policy = policy
        self._filter = divert_filter
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._dropped = 0
        self._passed = 0

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def stats(self) -> dict[str, int]:
        return {"dropped": self._dropped, "passed": self._passed}

    # ------------------------------------------------------------------
    def start(self) -> bool:
        try:
            import pydivert  # type: ignore[import-not-found]
        except ImportError:
            _log.warning(
                "windivert.unavailable",
                hint='pip install "deepsecurity[firewall]" (Windows-only)',
            )
            return False

        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="windivert", args=(pydivert,), daemon=True
        )
        self._thread.start()
        _log.info("windivert.started", filter=self._filter)
        return True

    def stop(self, timeout: float = 5.0) -> None:
        if not self.running:
            return
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        _log.info("windivert.stopped", stats=self.stats)

    # ------------------------------------------------------------------
    def _loop(self, pydivert: Any) -> None:
        try:
            with pydivert.WinDivert(self._filter) as w:
                while not self._stop.is_set():
                    try:
                        packet = w.recv()
                    except Exception:
                        # Driver returned, e.g. on shutdown.
                        break
                    if self._should_drop(packet):
                        self._dropped += 1
                        # NOT calling w.send() == drop the packet.
                        continue
                    try:
                        w.send(packet)
                        self._passed += 1
                    except Exception:
                        _log.exception("windivert.send_failed")
        except Exception:
            _log.exception("windivert.loop_crashed")

    # ------------------------------------------------------------------
    def _should_drop(self, packet: Any) -> bool:
        try:
            direction = "outbound" if packet.is_outbound else "inbound"
            protocol = "tcp" if packet.tcp else ("udp" if packet.udp else "any")
            remote_ip = packet.dst_addr if direction == "outbound" else packet.src_addr
            remote_port = (
                packet.dst_port if direction == "outbound" and (packet.tcp or packet.udp) else None
            )
            local_port = (
                packet.src_port if direction == "outbound" and (packet.tcp or packet.udp) else None
            )
            rule = self._policy.evaluate(
                direction=direction,
                protocol=protocol,
                remote_ip=str(remote_ip) if remote_ip else None,
                remote_port=remote_port,
                local_port=local_port,
                image=None,  # WinDivert doesn't surface the owning PID's image cheaply
            )
            if rule and rule.action == "drop":
                _log.info(
                    "windivert.drop",
                    rule=rule.name,
                    direction=direction,
                    proto=protocol,
                    remote=f"{remote_ip}:{remote_port}",
                )
                return True
            return False
        except Exception:
            _log.exception("windivert.match_failed")
            return False
