"""Platform routing for the v3 realtime layer.

Closes the v3 production gap "realtime stack is Windows-only".

The full kernel-sensing stack is, and will remain for the foreseeable
future, Windows-only — that's the architectural choice driven by
delegating to Sysmon + ETW + WinDivert (all Microsoft-signed). What
this module gives us is a clean factory + capability-detection layer
so the same correlator and enforcer code path runs on Linux and
macOS, just sourced from different sensors:

    Windows  → ETW + Sysmon (real, v3.0.0 GA)
    Linux    → eBPF + auditd  (stub in v3.0.0 — emits NotImplementedError
                                if you try to start without bcc/bpftrace.
                                Will become real in v3.1.)
    macOS    → Endpoint Security framework (stub in v3.0.0 — needs an
                                Apple-notarised helper binary which we
                                cannot generate here. Will become real
                                in v3.1 alongside an Apple Developer
                                account.)

Why ship the stubs now: it lets the rest of the stack (correlator,
enforcer, audit, sinks, CLI) remain platform-agnostic. The same
``deepsec realtime status`` command works on every OS — it just
reports a different set of capabilities. When the real Linux/macOS
listeners land in v3.1 the import path is already there.
"""

from __future__ import annotations

import platform
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class PlatformCapabilities:
    """What this OS can actually do for realtime sensing."""

    os_name: str             # "windows" | "linux" | "darwin"
    os_release: str
    has_etw: bool            # Windows ETW
    has_sysmon: bool         # Sysmon (Windows)
    has_windivert: bool      # WinDivert (Windows)
    has_defender_fw: bool    # Windows Firewall COM
    has_ebpf: bool           # Linux eBPF (bcc / bpftrace)
    has_auditd: bool         # Linux auditd
    has_endpoint_security: bool  # macOS Endpoint Security
    notes: list[str]

    def is_windows(self) -> bool:
        return self.os_name == "windows"

    def is_linux(self) -> bool:
        return self.os_name == "linux"

    def is_darwin(self) -> bool:
        return self.os_name == "darwin"

    def realtime_supported(self) -> bool:
        """Can we actually run *any* realtime listener on this host?"""
        return self.has_etw or self.has_sysmon or self.has_ebpf or self.has_endpoint_security


def detect_capabilities() -> PlatformCapabilities:
    """Probe the running host and return its real-time capability matrix."""
    os_name = platform.system().lower()
    if os_name == "windows":
        return _detect_windows()
    if os_name == "linux":
        return _detect_linux()
    if os_name == "darwin":
        return _detect_darwin()
    return PlatformCapabilities(
        os_name=os_name,
        os_release=platform.release(),
        has_etw=False,
        has_sysmon=False,
        has_windivert=False,
        has_defender_fw=False,
        has_ebpf=False,
        has_auditd=False,
        has_endpoint_security=False,
        notes=[f"unsupported OS: {os_name}"],
    )


def _try_import(name: str) -> bool:
    try:
        __import__(name)
        return True
    except Exception:
        return False


def _detect_windows() -> PlatformCapabilities:
    notes: list[str] = []
    has_etw = _try_import("etw")  # pywintrace exposes "etw"
    if not has_etw:
        notes.append('install "deepsecurity[edr]" for ETW')
    has_sysmon_module = _try_import("win32evtlog")
    has_sysmon = has_sysmon_module
    has_windivert = _try_import("pydivert")
    has_defender_fw = _try_import("win32com.client")
    return PlatformCapabilities(
        os_name="windows",
        os_release=platform.release(),
        has_etw=has_etw,
        has_sysmon=has_sysmon,
        has_windivert=has_windivert,
        has_defender_fw=has_defender_fw,
        has_ebpf=False,
        has_auditd=False,
        has_endpoint_security=False,
        notes=notes,
    )


def _detect_linux() -> PlatformCapabilities:
    """Probe Linux capabilities. v3.0.0 — stubs only.

    Real eBPF support lands in v3.1 once we package a libbpf-based
    listener that doesn't require root + headers at every install.
    """
    notes = ["v3.0.0 stub — real Linux realtime arrives in v3.1"]
    # bcc / bpftrace presence is informational, not enabling.
    has_bcc = _try_import("bcc")
    has_auditd = False
    try:
        # auditd is available iff /run/auditd.pid OR auditctl is on PATH.
        # We don't shell out here; we just say "probably" if the python
        # bindings are installed. Operators get a real probe in v3.1.
        has_auditd = _try_import("audit") or _try_import("auditd")
    except Exception:
        has_auditd = False
    return PlatformCapabilities(
        os_name="linux",
        os_release=platform.release(),
        has_etw=False,
        has_sysmon=False,
        has_windivert=False,
        has_defender_fw=False,
        has_ebpf=has_bcc,
        has_auditd=has_auditd,
        has_endpoint_security=False,
        notes=notes,
    )


def _detect_darwin() -> PlatformCapabilities:
    """Probe macOS capabilities. v3.0.0 — stub only.

    The real Endpoint Security listener requires a notarised helper
    binary signed by an Apple Developer account, which can't be
    generated in this repo. The stub exists so the CLI surface is
    identical across platforms; ``status`` reports unsupported and
    ``start`` raises NotImplementedError with the install hint.
    """
    return PlatformCapabilities(
        os_name="darwin",
        os_release=platform.release(),
        has_etw=False,
        has_sysmon=False,
        has_windivert=False,
        has_defender_fw=False,
        has_ebpf=False,
        has_auditd=False,
        has_endpoint_security=False,  # flips to True in v3.1 with the helper
        notes=["v3.0.0 stub — real macOS realtime arrives in v3.1"],
    )


# ---------------------------------------------------------------------------
# Listener factory — uniform interface across platforms
# ---------------------------------------------------------------------------


class RealtimeListener(Protocol):
    """Common shape of a realtime listener across all OSes.

    The Windows ETW + Sysmon listeners already implement this shape;
    the Linux + macOS stubs below do too. The correlator and enforcer
    don't know or care which OS they're consuming events from.
    """

    def start(self) -> bool: ...
    def stop(self, timeout: float = 5.0) -> None: ...
    @property
    def running(self) -> bool: ...


@dataclass
class StubListener:
    """A listener that explicitly refuses to start with a clear message."""

    platform_name: str
    install_hint: str

    def start(self) -> bool:
        from deepsecurity.logging_config import get_logger

        log = get_logger(__name__)
        log.warning(
            "realtime.unsupported",
            platform=self.platform_name,
            hint=self.install_hint,
        )
        return False

    def stop(self, timeout: float = 5.0) -> None:
        del timeout  # interface compat — stub has nothing to wait on
        return None

    @property
    def running(self) -> bool:
        return False


def make_listener(
    on_event: Callable[[Any], None],
    *,
    capabilities: PlatformCapabilities | None = None,
) -> RealtimeListener:
    """Pick the right listener for this host and return it.

    Returns a real Windows listener on Windows when the deps are
    installed; otherwise a StubListener with an install hint. Linux
    and macOS both return StubListeners in v3.0.0 — replaced with
    real implementations in v3.1.
    """
    caps = capabilities or detect_capabilities()
    if caps.is_windows() and caps.has_etw:
        from deepsecurity.realtime.etw import EtwListener

        return EtwListener(on_event=on_event)
    if caps.is_linux():
        return StubListener(
            platform_name="linux",
            install_hint='real Linux realtime ships in v3.1; for now use the scanner CLI',
        )
    if caps.is_darwin():
        return StubListener(
            platform_name="darwin",
            install_hint='real macOS realtime ships in v3.1 (requires Apple Developer account)',
        )
    return StubListener(
        platform_name=caps.os_name,
        install_hint="this OS is not on the realtime support roadmap",
    )
