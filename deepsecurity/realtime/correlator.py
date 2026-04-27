"""Behavioural correlation — turn raw events into typed detections.

Receives ETW + Sysmon events, applies named rules, emits ``Detection``
records with severity + MITRE tag. Pure functions over an in-memory
process tree; no I/O; trivially testable.

Built-in rules (extensible):

    R-PC-001  Office → shell descendant       T1059
    R-PC-002  PDF reader → shell descendant   T1059
    R-PC-003  Browser → script-host launch    T1059.005
    R-LB-001  LOLBin invocation                T1218
    R-NET-01  Beaconing pattern (interval ±)  T1071
    R-IL-01   Suspicious DLL load path        T1574
    R-RW-01   Writes per second over threshold T1486

Rules are pluggable. Add a function with the right signature to
``RULES`` and it's live.
"""

from __future__ import annotations

import statistics
import time
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from deepsecurity.logging_config import get_logger
from deepsecurity.realtime.etw import EtwEvent
from deepsecurity.realtime.sysmon import SysmonEvent

_log = get_logger(__name__)


# A unified event view — either ETW or Sysmon, normalised.
@dataclass
class UnifiedEvent:
    kind: str
    pid: int | None
    parent_pid: int | None
    image: str | None
    cmdline: str | None
    timestamp: float = field(default_factory=time.time)
    remote_ip: str | None = None
    remote_port: int | None = None
    file_path: str | None = None
    source: str = "unknown"  # "etw" | "sysmon"
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class Detection:
    rule_id: str
    severity: str  # info | low | medium | high | critical
    summary: str
    pid: int | None
    image: str | None
    mitre_tags: tuple[str, ...]
    evidence: dict[str, Any]


# ---------------------------------------------------------------------------
# Built-in patterns
# ---------------------------------------------------------------------------

_OFFICE_NAMES = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "msaccess.exe",
    "visio.exe",
}
_PDF_READERS = {"acrord32.exe", "acrobat.exe", "foxitreader.exe"}
_BROWSERS = {"chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "brave.exe"}
_SHELLS = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "bash.exe",
    "wsl.exe",
}
# Microsoft-signed binaries commonly abused by attackers (LOLBins).
# This is a curated subset of LOLBAS — extend per environment.
_LOLBINS = {
    "certutil.exe",
    "bitsadmin.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "mshta.exe",
    "wmic.exe",
    "installutil.exe",
    "msbuild.exe",
    "regasm.exe",
    "regsvcs.exe",
    "regini.exe",
    "scriptrunner.exe",
    "cmstp.exe",
}


# ---------------------------------------------------------------------------
# Process-tree state (small and bounded)
# ---------------------------------------------------------------------------


class _ProcessTree:
    """Pid → parent_image lookup with bounded retention."""

    def __init__(self, max_entries: int = 4096) -> None:
        self._by_pid: dict[int, dict[str, Any]] = {}
        self._max = max_entries

    def add(self, pid: int, parent_pid: int | None, image: str | None) -> None:
        self._by_pid[pid] = {
            "parent_pid": parent_pid,
            "image": image,
            "ts": time.time(),
        }
        if len(self._by_pid) > self._max:
            # Drop the oldest 10% rather than rebuilding every insert.
            drop = sorted(self._by_pid.items(), key=lambda x: x[1]["ts"])[: self._max // 10]
            for k, _ in drop:
                self._by_pid.pop(k, None)

    def remove(self, pid: int) -> None:
        self._by_pid.pop(pid, None)

    def parent_image(self, pid: int) -> str | None:
        rec = self._by_pid.get(pid)
        if not rec:
            return None
        ppid = rec.get("parent_pid")
        if not ppid:
            return None
        prec = self._by_pid.get(ppid)
        return (prec or {}).get("image")

    def image_of(self, pid: int | None) -> str:
        """Return the image of ``pid`` if known; empty string otherwise."""
        if not pid:
            return ""
        rec = self._by_pid.get(pid)
        if not rec:
            return ""
        return rec.get("image") or ""


# ---------------------------------------------------------------------------
# Beaconing detector
# ---------------------------------------------------------------------------


class _BeaconDetector:
    """Track outbound-connect timestamps per (pid, dest). Flag suspicious cadence."""

    def __init__(self, window_n: int = 10, jitter_max: float = 1.5) -> None:
        self._buckets: dict[tuple[int, str], deque[float]] = defaultdict(
            lambda: deque(maxlen=window_n)
        )
        self._jitter_max = jitter_max

    def record(self, pid: int, dest: str) -> Detection | None:
        q = self._buckets[(pid, dest)]
        q.append(time.time())
        if len(q) < q.maxlen:
            return None
        deltas = [q[i + 1] - q[i] for i in range(len(q) - 1)]
        mean = statistics.mean(deltas)
        if mean < 1.0:  # noisy chatter, not beaconing
            return None
        stdev = statistics.pstdev(deltas)
        if stdev < self._jitter_max and mean > 5.0:
            return Detection(
                rule_id="R-NET-01",
                severity="high",
                summary=f"beaconing pattern: pid={pid} dest={dest} interval≈{mean:.1f}s",
                pid=pid,
                image=None,
                mitre_tags=("T1071",),
                evidence={
                    "interval_s": round(mean, 2),
                    "jitter_s": round(stdev, 2),
                    "samples": len(q),
                },
            )
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class Correlator:
    """Stateful event consumer that emits Detections."""

    def __init__(self, emit: Callable[[Detection], None]) -> None:
        self._emit = emit
        self._tree = _ProcessTree()
        self._beacon = _BeaconDetector()
        self._write_rates: dict[int, deque[float]] = defaultdict(lambda: deque(maxlen=128))

    # ------------------------------------------------------------------
    def consume_etw(self, e: EtwEvent) -> None:
        self.consume(self._normalise_etw(e))

    def consume_sysmon(self, e: SysmonEvent) -> None:
        self.consume(self._normalise_sysmon(e))

    def consume(self, e: UnifiedEvent) -> None:
        try:
            for rule in RULES:
                hit = rule(self, e)
                if hit is not None:
                    self._emit(hit)
        except Exception:
            _log.exception("correlator.rule_failed", kind=e.kind, image=e.image)

    # ------------------------------------------------------------------
    @staticmethod
    def _normalise_etw(e: EtwEvent) -> UnifiedEvent:
        return UnifiedEvent(
            kind=e.kind,
            pid=e.pid,
            parent_pid=e.parent_pid,
            image=e.image,
            cmdline=e.cmdline,
            remote_ip=e.remote_ip,
            remote_port=e.remote_port,
            file_path=e.file_path,
            source="etw",
            raw=e.raw,
        )

    @staticmethod
    def _normalise_sysmon(e: SysmonEvent) -> UnifiedEvent:
        kind_map = {
            1: "process_create",
            5: "process_term",
            3: "net_connect",
            7: "image_load",
            11: "file_create",
            22: "dns_query",
        }
        return UnifiedEvent(
            kind=kind_map.get(e.event_id, f"sysmon_{e.event_id}"),
            pid=e.pid,
            parent_pid=e.parent_pid,
            image=e.image,
            cmdline=e.cmdline,
            source="sysmon",
            raw=e.raw,
        )


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


def _rule_parent_chain_office_shell(c: Correlator, e: UnifiedEvent) -> Detection | None:
    if e.kind != "process_create" or not e.image:
        return None
    c._tree.add(e.pid or 0, e.parent_pid, e.image)
    image = (e.image or "").lower().rsplit("\\", 1)[-1]
    parent_image = (c._tree.parent_image(e.pid or 0) or "").lower().rsplit("\\", 1)[-1]
    if image in _SHELLS and parent_image in _OFFICE_NAMES:
        return Detection(
            rule_id="R-PC-001",
            severity="high",
            summary=f"Office → shell: {parent_image} → {image}",
            pid=e.pid,
            image=e.image,
            mitre_tags=("T1059",),
            evidence={"parent_image": parent_image, "cmdline": e.cmdline},
        )
    if image in _SHELLS and parent_image in _PDF_READERS:
        return Detection(
            rule_id="R-PC-002",
            severity="high",
            summary=f"PDF reader → shell: {parent_image} → {image}",
            pid=e.pid,
            image=e.image,
            mitre_tags=("T1059",),
            evidence={"parent_image": parent_image, "cmdline": e.cmdline},
        )
    if image in _SHELLS and parent_image in _BROWSERS:
        return Detection(
            rule_id="R-PC-003",
            severity="medium",
            summary=f"Browser → shell: {parent_image} → {image}",
            pid=e.pid,
            image=e.image,
            mitre_tags=("T1059.005",),
            evidence={"parent_image": parent_image, "cmdline": e.cmdline},
        )
    return None


def _rule_lolbin_invocation(c: Correlator, e: UnifiedEvent) -> Detection | None:
    if e.kind != "process_create" or not e.image:
        return None
    image = (e.image or "").lower().rsplit("\\", 1)[-1]
    if image in _LOLBINS:
        return Detection(
            rule_id="R-LB-001",
            severity="medium",
            summary=f"LOLBin invocation: {image}",
            pid=e.pid,
            image=e.image,
            mitre_tags=("T1218",),
            evidence={"cmdline": e.cmdline},
        )
    return None


def _rule_beaconing(c: Correlator, e: UnifiedEvent) -> Detection | None:
    if e.kind != "net_connect" or not e.pid or not e.remote_ip:
        return None
    return c._beacon.record(e.pid, f"{e.remote_ip}:{e.remote_port or '?'}")


def _rule_write_rate(c: Correlator, e: UnifiedEvent) -> Detection | None:
    if e.kind != "file_create" or not e.pid:
        return None
    q = c._write_rates[e.pid]
    q.append(time.time())
    if len(q) < 50:
        return None
    span = q[-1] - q[0]
    if span > 0 and len(q) / span > 50:  # >50 file writes per second
        return Detection(
            rule_id="R-RW-01",
            severity="critical",
            summary=f"high write rate: pid={e.pid} ~{int(len(q) / span)} files/s",
            pid=e.pid,
            image=e.image,
            mitre_tags=("T1486",),
            evidence={"rate_per_s": round(len(q) / span, 1), "samples": len(q)},
        )
    return None


def _rule_image_load_from_user_writable(c: Correlator, e: UnifiedEvent) -> Detection | None:
    if e.kind != "image_load" or not e.file_path:
        return None
    p = (e.file_path or "").lower()
    suspicious_roots = ("\\users\\", "\\appdata\\local\\temp", "\\downloads\\")
    if any(r in p for r in suspicious_roots) and p.endswith(".dll"):
        return Detection(
            rule_id="R-IL-01",
            severity="medium",
            summary=f"DLL load from user-writable path: {p}",
            pid=e.pid,
            image=e.image,
            mitre_tags=("T1574",),
            evidence={"loaded_path": e.file_path},
        )
    return None


# UAC-bypass binaries — Windows-shipped trusted binaries that auto-elevate
# to High integrity without prompting, and that classic UAC-bypass
# techniques abuse to launch a child shell at elevated privilege.
# Mapping: image basename → MITRE technique sub-id. Sources:
# UACMe project, MITRE ATT&CK T1548.002, hexacorn AutoElevate notes.
# This list covers the ~20 most-used auto-elevate primitives circa 2024.
_UAC_AUTO_ELEVATE_BINARIES = frozenset({
    "fodhelper.exe",         # Win10/11 — registry hijack
    "computerdefaults.exe",  # Win10/11 — registry hijack
    "eventvwr.exe",          # Win7+ — mscfile hijack (classic)
    "sdclt.exe",             # Win10 — App Paths or env vars
    "wsreset.exe",           # Win10/11 — AppX/Store reset hijack
    "slui.exe",              # licensing UI — registry hijack
    "perfmon.exe",           # performance monitor
    "compmgmtlauncher.exe",  # legacy compmgmt
    "sysprep.exe",           # admin-tool DLL hijack
    "dccw.exe",              # display calibration — DLL hijack
    "cttune.exe",            # ClearType tuner — DLL hijack
    "msconfig.exe",          # system config — registry hijack
    "wusa.exe",              # update standalone installer
    "consent.exe",           # UAC consent UI — should never spawn cmd
    "rundll32.exe",          # only when launching a UAC-related verb
    "explorer.exe",          # parent of consent.exe in some bypasses
    "dism.exe",              # deployment image servicing
    "mmc.exe",               # management console
    "taskmgr.exe",           # task manager (rare bypass primitive)
    "narrator.exe",          # narrator UI hijack (Win10)
})

# Children that, when spawned by the auto-elevating binaries above,
# almost always indicate a bypass attempt. A direct ``cmd.exe`` /
# ``powershell.exe`` / scripting-host child of fodhelper.exe in
# particular is a strong signal — those binaries have no legitimate
# reason to launch a shell.
_UAC_SUSPICIOUS_CHILDREN = frozenset({
    "cmd.exe",
    "powershell.exe",
    "powershell_ise.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "regsvr32.exe",
})


def _rule_uac_bypass(c: Correlator, e: UnifiedEvent) -> Detection | None:
    """R-PE-01 — privilege-escalation via known UAC-bypass primitives.

    Fires when a child process is spawned by a known auto-elevating
    Windows binary AND the child is a shell or scripting host. The
    parent-child pair is the high-confidence signal: fodhelper.exe
    legitimately runs in plenty of contexts, but fodhelper.exe →
    cmd.exe is essentially never a benign sequence.
    """
    if e.kind != "process_create" or not e.image:
        return None
    parent_image = c._tree.image_of(e.parent_pid).lower() if e.parent_pid else ""
    parent_name = parent_image.rsplit("\\", 1)[-1]
    child_name = (e.image or "").lower().rsplit("\\", 1)[-1]
    if parent_name in _UAC_AUTO_ELEVATE_BINARIES and child_name in _UAC_SUSPICIOUS_CHILDREN:
        return Detection(
            rule_id="R-PE-01",
            severity="high",
            summary=(
                f"UAC bypass: {parent_name} spawned {child_name} "
                f"(auto-elevating parent + shell child)"
            ),
            pid=e.pid,
            image=e.image,
            mitre_tags=("T1548.002",),
            evidence={
                "parent_image": parent_image,
                "parent_pid": e.parent_pid,
                "child_image": e.image,
                "cmdline": e.cmdline,
            },
        )
    return None


# Lateral-movement protocols by destination port. Outbound connections
# to RFC1918 IPs on these ports are the textbook signature of lateral
# movement after initial host compromise.
_LATERAL_PORTS = frozenset({
    445,    # SMB / file shares + remote service install
    139,    # NetBIOS
    3389,   # RDP
    5985,   # WinRM HTTP
    5986,   # WinRM HTTPS
    135,    # RPC endpoint mapper (DCOM, WMI, Service Control Manager)
})


def _is_rfc1918(ip: str) -> bool:
    """True if ``ip`` is in the private (RFC1918 / link-local) range."""
    if not ip:
        return False
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("169.254."):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".", 2)[1])
            return 16 <= second <= 31
        except (ValueError, IndexError):
            return False
    return False


def _rule_lateral_movement(c: Correlator, e: UnifiedEvent) -> Detection | None:
    """R-LM-01 — outbound connection on a lateral-movement protocol to
    a private IP. Detection only by default; the enforcer can be
    configured to auto-add a Defender FW deny rule via
    ``DEEPSEC_LATERAL_MOVEMENT_BLOCK=true``.
    """
    if e.kind != "net_connect" or not e.remote_ip or not e.remote_port:
        return None
    if e.remote_port not in _LATERAL_PORTS or not _is_rfc1918(e.remote_ip):
        return None
    return Detection(
        rule_id="R-LM-01",
        severity="high",
        summary=(
            f"lateral-movement connection: pid={e.pid} → "
            f"{e.remote_ip}:{e.remote_port}"
        ),
        pid=e.pid,
        image=e.image,
        mitre_tags=("T1021",),
        evidence={
            "remote_ip": e.remote_ip,
            "remote_port": e.remote_port,
            "protocol_hint": _LATERAL_PORT_NAMES.get(e.remote_port, "unknown"),
        },
    )


_LATERAL_PORT_NAMES = {
    445: "SMB",
    139: "NetBIOS",
    3389: "RDP",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    135: "RPC-endpoint-mapper",
}


# Plug-in list — order is dispatch order. Add yours here.
RULES: list[Callable[[Correlator, UnifiedEvent], Detection | None]] = [
    _rule_parent_chain_office_shell,
    _rule_lolbin_invocation,
    _rule_beaconing,
    _rule_write_rate,
    _rule_image_load_from_user_writable,
    _rule_uac_bypass,
    _rule_lateral_movement,
]
