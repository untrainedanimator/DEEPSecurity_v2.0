"""Read process memory and scan for high-value strings.

The scan walks the target's committed regions, copies a bounded chunk
of each, runs the DLP regex set over it (since secrets in memory look
the same as secrets in files), and emits redacted findings.

This is best-effort: many regions will be unreadable, encrypted, or
guarded by the OS. We log and continue. Coverage on a typical browser
or LLM client is enough to catch session tokens / API keys that the
caller mishandled.

Use ``scan_pid(pid)`` from a thread or queue — the scan can take
seconds on a process with hundreds of MB of mapped memory.

Optional dep: pywin32 not strictly required (pure ctypes), but
pywin32 makes priv elevation simpler.
"""

from __future__ import annotations

import ctypes
from collections.abc import Iterator
from ctypes import wintypes
from dataclasses import dataclass

from deepsecurity.dlp import scan_text
from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)


PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100


@dataclass(frozen=True)
class MemoryFinding:
    pid: int
    address: int
    region_size: int
    pattern_name: str
    severity: str
    redacted_preview: str


# ---------------------------------------------------------------------------
# Win32 plumbing
# ---------------------------------------------------------------------------


class _MemoryBasicInformation(ctypes.Structure):  # pragma: no cover — Windows-only
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


def _open(pid: int) -> int | None:  # pragma: no cover — Windows-only
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return None
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        _log.warning("memory.open_failed", pid=pid, err=ctypes.get_last_error())
        return None
    return int(handle)


def _close(handle: int) -> None:  # pragma: no cover
    try:
        kernel32 = ctypes.WinDLL("kernel32")  # type: ignore[attr-defined]
        kernel32.CloseHandle(handle)
    except Exception:
        pass


def _iter_regions(
    handle: int, max_bytes: int = 256 * 1024 * 1024
) -> Iterator[tuple[int, int, bytes]]:  # pragma: no cover
    """Yield (base, size, contents) for every committed readable region.

    Caps total scanned bytes at ``max_bytes`` to keep walltime bounded.
    """
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return
    addr = 0
    info = _MemoryBasicInformation()
    bytes_total = 0
    while bytes_total < max_bytes:
        rc = kernel32.VirtualQueryEx(
            ctypes.c_void_p(handle),
            ctypes.c_void_p(addr),
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if rc == 0:
            break
        size = int(info.RegionSize or 0)
        if size == 0:
            break
        # Only commit + readable + not guarded.
        if (
            info.State == MEM_COMMIT
            and info.Protect not in (0, PAGE_NOACCESS)
            and not (info.Protect & PAGE_GUARD)
        ):
            chunk = min(size, 4 * 1024 * 1024, max_bytes - bytes_total)
            buf = ctypes.create_string_buffer(chunk)
            read = ctypes.c_size_t(0)
            ok = kernel32.ReadProcessMemory(
                ctypes.c_void_p(handle),
                ctypes.c_void_p(int(info.BaseAddress or 0)),
                buf,
                chunk,
                ctypes.byref(read),
            )
            if ok and read.value > 0:
                yield int(info.BaseAddress or 0), size, bytes(buf.raw[: read.value])
                bytes_total += int(read.value)
        addr = int(info.BaseAddress or 0) + size


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_pid(pid: int, *, max_bytes: int = 256 * 1024 * 1024) -> list[MemoryFinding]:
    """Scan a process's memory for DLP patterns. Returns findings list.

    The DLP-pattern scan is always run. v3.1 — when YARA is enabled
    (via ``settings.memory_scan_yara_enabled``) and ``yara-python`` is
    installed, every memory region is also matched against the rule
    set under ``settings.memory_scan_yara_rules_dir``. YARA matches
    are surfaced as ``MemoryFinding`` rows with ``pattern_name`` set
    to ``"yara:<rule_name>"`` so callers don't need to know about two
    finding shapes.
    """
    handle = _open(pid)
    if handle is None:
        return []
    out: list[MemoryFinding] = []

    # Lazy YARA setup — None on every error / unavailable path. We
    # compile-once-per-scan rather than once-per-region; the underlying
    # compile_rules() has its own cache keyed on rules-dir mtime.
    yara_rules = None
    try:
        from deepsecurity.config import settings as _settings

        if bool(getattr(_settings, "memory_scan_yara_enabled", False)):
            from deepsecurity.memory_scan import yara_scan as _y

            rules_dir = getattr(
                _settings,
                "memory_scan_yara_rules_dir",
                None,
            )
            if rules_dir is not None:
                yara_rules = _y.compile_rules(rules_dir)
    except Exception:
        _log.exception("memory.yara_setup_failed", pid=pid)
        yara_rules = None

    try:
        for base, size, blob in _iter_regions(handle, max_bytes=max_bytes):
            # 1. DLP-pattern scan (existing behaviour).
            try:
                text = blob.decode("utf-8", errors="replace")
            except Exception:
                _log.debug("memory.decode_failed", pid=pid, base=base)
                continue
            for f in scan_text(text, file_path=f"<memory:pid={pid} @ 0x{base:x}>"):
                out.append(
                    MemoryFinding(
                        pid=pid,
                        address=base,
                        region_size=size,
                        pattern_name=f.pattern_name,
                        severity=f.severity,
                        redacted_preview=f.redacted_preview,
                    )
                )
            # 2. YARA scan (v3.1, opt-in).
            if yara_rules is not None:
                try:
                    from deepsecurity.memory_scan.yara_scan import match_bytes

                    for m in match_bytes(yara_rules, blob):
                        meta = getattr(m, "meta", {}) or {}
                        severity = str(meta.get("severity", "medium")).lower()
                        idents = ", ".join(
                            sorted({s[1] for s in (m.strings or ())})
                        )[:120]
                        out.append(
                            MemoryFinding(
                                pid=pid,
                                address=base,
                                region_size=size,
                                pattern_name=f"yara:{getattr(m, 'rule', 'unknown')}",
                                severity=severity,
                                redacted_preview=idents or "(no string capture)",
                            )
                        )
                except Exception:
                    _log.debug("memory.yara_match_failed", pid=pid, base=base)
    finally:
        _close(handle)
    _log.info("memory.scan_done", pid=pid, findings=len(out))
    return out
