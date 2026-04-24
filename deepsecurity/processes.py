"""User-space process inspection.

NOT an EDR. We cannot hook the kernel; what we CAN do is look at what
psutil shows us (process names, CPU, memory, cmdline, parent chain,
hashes where readable) and flag:

  - known-bad executable names (cryptominers, common malware binaries)
  - suspicious LOLBin parent chains (e.g. winword.exe → powershell.exe)
  - CPU-anomaly sustained offenders (likely crypto miners)
  - processes whose executable hash matches our signature set

Every detection is tagged with MITRE ATT&CK technique IDs for downstream
SOC tooling.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psutil

from deepsecurity.audit import audit_log
from deepsecurity.config import settings
from deepsecurity.logging_config import get_logger
from deepsecurity.mitre import PROCESS_REASON_TAGS, tags_for_reasons
from deepsecurity.scanner import compute_sha256, load_signatures

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Known-bad process-name denylist.
#
# Names seen in the wild as cryptominers, coinminer droppers, generic
# malware families. Matched case-insensitively on the executable name
# (not the full path). Add-as-needed; pattern works across OS.
# ---------------------------------------------------------------------------

KNOWN_MINERS: frozenset[str] = frozenset(
    {
        "xmrig",
        "xmrig.exe",
        "xmrig-notls",
        "xmrig-cuda",
        "ccminer",
        "ccminer.exe",
        "cgminer",
        "cgminer.exe",
        "bfgminer",
        "minerd",
        "minerd.exe",
        "nheqminer",
        "nsgpucnminer",
        "t-rex",
        "t-rex.exe",
        "phoenixminer",
        "phoenixminer.exe",
        "lolminer",
        "ethminer",
        "ethminer.exe",
        "nbminer",
        "teamredminer",
        "gminer",
        "srbminer-multi",
        "mining.exe",
    }
)

# Generic suspicious processes (not definitely malware, but often LOLBins
# used in live-off-the-land attacks). Flag for operator review.
SUSPICIOUS_NAMES: frozenset[str] = frozenset(
    {
        "mimikatz",
        "mimikatz.exe",
        "procdump.exe",
        "psexec.exe",
        "nc.exe",
        "netcat",
        "ncat.exe",
        "socat",
    }
)


# Parent → child chains that are routinely abused for code execution.
# Match on lowercase exe names. These are heuristics — a legitimate macro
# developer WILL hit some of these — but they're worth surfacing.
SUSPICIOUS_PARENT_CHAINS: frozenset[tuple[str, str]] = frozenset(
    {
        # Office → shell (macro-dropped malware classic)
        ("winword.exe", "powershell.exe"),
        ("winword.exe", "cmd.exe"),
        ("winword.exe", "wscript.exe"),
        ("winword.exe", "cscript.exe"),
        ("excel.exe", "powershell.exe"),
        ("excel.exe", "cmd.exe"),
        ("excel.exe", "wscript.exe"),
        ("powerpnt.exe", "powershell.exe"),
        ("outlook.exe", "powershell.exe"),
        ("outlook.exe", "cmd.exe"),
        # PDF reader → shell
        ("acrord32.exe", "powershell.exe"),
        ("acrord32.exe", "cmd.exe"),
        # Browser → shell
        ("chrome.exe", "powershell.exe"),
        ("firefox.exe", "powershell.exe"),
        ("msedge.exe", "powershell.exe"),
        # Archive tool → shell (unusual, unpacker → runner pattern)
        ("7zg.exe", "cmd.exe"),
        ("winrar.exe", "cmd.exe"),
    }
)


def _parent_chain(pid: int | None, max_depth: int = 8) -> list[dict[str, Any]]:
    """Walk up from `pid`. Returns [{pid, name}] most-recent-first.

    Skips anything that isn't a valid PID. psutil refuses 0 (System Idle
    Process on Windows) and any negative number with ValueError, so we
    filter those out before even asking.
    """
    chain: list[dict[str, Any]] = []
    if not isinstance(pid, int) or pid <= 0:
        return chain
    try:
        p: psutil.Process | None = psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
        return chain
    for _ in range(max_depth):
        if p is None:
            break
        try:
            chain.append({"pid": p.pid, "name": (p.name() or "").lower()})
            p = p.parent()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            break
    return chain


def _has_suspicious_chain(chain: list[dict[str, Any]]) -> tuple[bool, str | None]:
    """Inspect a parent chain for a known-abused parent→child transition."""
    for i in range(len(chain) - 1):
        child = chain[i]["name"]
        parent = chain[i + 1]["name"]
        if (parent, child) in SUSPICIOUS_PARENT_CHAINS:
            return True, f"{parent} → {child}"
    return False, None


@dataclass(frozen=True)
class ProcessVerdict:
    label: str  # "clean" | "suspicious" | "known_bad"
    reasons: tuple[str, ...]
    mitre_tags: tuple[str, ...]


def classify_process(
    info: dict[str, Any],
    *,
    signatures: frozenset[str],
    parent_chain: list[dict[str, Any]] | None = None,
    cpu_threshold_percent: float = 80.0,
) -> ProcessVerdict:
    """Apply every process-level check to a single psutil.process_iter row."""
    reasons: list[str] = []
    label = "clean"

    name = (info.get("name") or "").lower()
    exe = info.get("exe")

    # 1. Known-miner deny-list.
    if name in KNOWN_MINERS:
        reasons.append(f"known_miner:{name}")
        label = "known_bad"

    # 2. Known suspicious tool.
    if name in SUSPICIOUS_NAMES:
        reasons.append(f"lolbin:{name}")
        if label == "clean":
            label = "suspicious"

    # 3. Sustained CPU usage — proxy for mining / abuse.
    cpu = float(info.get("cpu_percent") or 0.0)
    if cpu >= cpu_threshold_percent:
        reasons.append(f"high_cpu:{cpu:.0f}%")
        if label == "clean":
            label = "suspicious"

    # 4. Signature match on the executable file (if we can read it).
    if exe and signatures:
        try:
            exe_path = Path(exe)
            if exe_path.exists() and exe_path.is_file():
                sha = compute_sha256(exe_path)
                if sha in signatures:
                    reasons.append(f"signature_match:{sha[:12]}")
                    label = "known_bad"
        except (OSError, PermissionError):
            pass

    # 5. Parent-chain heuristic (Office → shell, PDF → shell, …).
    if parent_chain:
        hit, chain_desc = _has_suspicious_chain(parent_chain)
        if hit:
            reasons.append(f"suspicious_parent:{chain_desc}")
            if label == "clean":
                label = "suspicious"

    reasons_t = tuple(reasons) or ("none",)
    tags = tuple(tags_for_reasons(list(reasons_t)))
    return ProcessVerdict(label=label, reasons=reasons_t, mitre_tags=tags)


# ---------------------------------------------------------------------------
# Enforcement (opt-in)
# ---------------------------------------------------------------------------


def kill_process(pid: int, *, force: bool = False) -> dict[str, Any]:
    """Terminate a process. Returns a structured result, never raises.

    - force=False: SIGTERM / Windows terminate — graceful.
    - force=True:  SIGKILL / Windows kill — forceful.

    On Windows we can only terminate processes we own unless we're admin.
    On POSIX we need matching UID or root. AccessDenied is a valid outcome
    and is reported honestly.
    """
    try:
        p = psutil.Process(pid)
        name = p.name()
        if force:
            p.kill()
        else:
            p.terminate()
        try:
            p.wait(timeout=5)
        except psutil.TimeoutExpired:
            return {
                "killed": False,
                "pid": pid,
                "name": name,
                "reason": "process still alive after 5s",
            }
        return {"killed": True, "pid": pid, "name": name, "force": force}
    except psutil.NoSuchProcess:
        return {"killed": False, "pid": pid, "reason": "no_such_process"}
    except psutil.AccessDenied:
        return {
            "killed": False,
            "pid": pid,
            "reason": "access_denied — run the server as admin / root to kill this PID",
        }
    except Exception as exc:  # noqa: BLE001 — enforcement must not raise
        _log.exception("process.kill_failed", pid=pid)
        return {"killed": False, "pid": pid, "reason": f"{type(exc).__name__}: {exc}"}


def scan_all_processes(
    *,
    cpu_sample_seconds: float = 0.5,
    auto_kill_known_bad: bool = False,
) -> list[dict[str, Any]]:
    """Walk every visible process and classify each."""
    import time

    procs = [p for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "username"])]
    for p in procs:
        try:
            p.cpu_percent(interval=None)
        except psutil.Error:
            continue

    time.sleep(cpu_sample_seconds)
    signatures = load_signatures(settings.signature_path)

    out: list[dict[str, Any]] = []
    for p in procs:
        try:
            info = p.info
            cpu = p.cpu_percent(interval=None)
            mem = p.memory_info()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        # ``info.get("pid") or -1`` is wrong here: pid=0 is the System Idle
        # Process on Windows and 0 is falsy, so ``or -1`` would swap it
        # for -1 which psutil rejects. Hand the raw value to _parent_chain,
        # which does its own validation.
        chain = _parent_chain(info.get("pid"))

        row = {
            "pid": info.get("pid"),
            "name": info.get("name"),
            "exe": info.get("exe"),
            "cmdline": " ".join(info.get("cmdline") or []),
            "user": info.get("username"),
            "cpu_percent": round(float(cpu), 1),
            "rss_bytes": getattr(mem, "rss", 0),
            "parent_chain": chain,
        }
        verdict = classify_process(
            {**info, "cpu_percent": cpu},
            signatures=signatures,
            parent_chain=chain,
        )
        row["label"] = verdict.label
        row["reasons"] = list(verdict.reasons)
        row["mitre_tags"] = list(verdict.mitre_tags)

        if verdict.label == "known_bad" and auto_kill_known_bad:
            result = kill_process(row["pid"])
            row["auto_kill_result"] = result
            audit_log(
                actor="system",
                action="process.auto_killed" if result.get("killed") else "process.auto_kill_failed",
                status="ok" if result.get("killed") else "failed",
                file_path=row.get("exe"),
                details={
                    "pid": row["pid"],
                    "name": row["name"],
                    "reasons": row["reasons"],
                    "mitre_tags": row["mitre_tags"],
                    "result": result,
                },
            )

        out.append(row)

    def _rank(r: dict[str, Any]) -> tuple[int, float]:
        order = {"known_bad": 0, "suspicious": 1, "clean": 2}
        return (order.get(r["label"], 2), -r["cpu_percent"])

    out.sort(key=_rank)
    return out
