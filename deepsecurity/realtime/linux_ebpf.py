"""Linux eBPF listener — v3.0.0 stub, real implementation in v3.1.

Why a stub now:

    * The cross-platform CLI surface (``deepsec realtime status`` etc.)
      should not 500 on Linux. It should report "unsupported, see hint".
    * The correlator code path is platform-agnostic. We want the
      factory in ``platform.py`` to be able to return *some* listener
      object on Linux even if it just refuses to start.
    * The shape of the listener interface is set by Windows v3.0; we
      lock it in here so the v3.1 Linux work is purely the real ETW
      → eBPF translation, no API design.

Real plan for v3.1:

    * Use libbpf-rs (preferred) or python-bcc to attach to:
        - tracepoint:syscalls:sys_enter_execve   → process_create
        - tracepoint:sched:sched_process_exit    → process_terminate
        - kprobe:do_sys_openat2                  → file_open  (filtered)
        - tracepoint:net:netif_receive_skb       → network_packet
    * Translate each event into the same SysmonEvent / EtwEvent dataclass
      already consumed by the correlator. Equivalent fields:
        - process_create   ↔ ETW Microsoft-Windows-Kernel-Process / Sysmon EID 1
        - file_open        ↔ ETW Microsoft-Windows-Kernel-File / Sysmon EID 11
        - network_connect  ↔ ETW Microsoft-Windows-Kernel-Network / Sysmon EID 3
    * Package the BPF object as a wheel data file so install doesn't
      need clang/llvm at every host.

Failure semantics in v3.0.0: ``start()`` returns False with a logged
hint. The correlator continues to work — it just sees no events. This
is the correct behaviour for a stub: don't pretend, don't crash.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any

from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)


class LinuxEbpfListener:
    """v3.0.0 stub for the Linux eBPF realtime listener."""

    def __init__(self, on_event: Callable[[Any], None]) -> None:
        self._on_event = on_event
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> bool:
        _log.warning(
            "linux_ebpf.unimplemented",
            hint="Linux realtime ships in v3.1 — use the scanner CLI for now",
        )
        return False

    def stop(self, timeout: float = 5.0) -> None:
        del timeout  # interface compat — stub has nothing to wait on
        self._stop.set()

    # Future surface (v3.1) — methods exist as no-ops so consumers can
    # write code that uses them without polyfills.

    def attach_program(self, _name: str, _path: str) -> bool:
        """Future v3.1: attach a BPF program by name + bytecode path."""
        return False

    def detach_program(self, _name: str) -> bool:
        """Future v3.1: detach a previously-attached program."""
        return False
