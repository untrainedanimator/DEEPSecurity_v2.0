r"""One-shot smoke: import every v3 BEASTMODE module + show what's wired.

Doesn't START anything (no listeners, no driver loads, no DNS bind) — just
checks that the modules import cleanly and report their optional-dep
availability. Safe to run as a normal user; idempotent.

    python scripts\smoke_v3_imports.py
"""

from __future__ import annotations

import importlib
import os
import sys
import traceback
from pathlib import Path

# Ensure pydantic-settings has enough to instantiate.
os.environ.setdefault("DEEPSEC_SECRET_KEY", "0123456789abcdef0123456789abcdef")
os.environ.setdefault("DEEPSEC_JWT_SECRET", "fedcba9876543210fedcba9876543210")
os.environ.setdefault("DEEPSEC_DEV_PASSWORD", "smoke-only-dev-password")
os.environ.setdefault("DEEPSEC_ENV", "development")
os.environ.setdefault("DEEPSEC_WATCHDOG_AUTOSTART", "")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


MODULES = [
    # Pure-python (cross-platform).
    "deepsecurity.realtime.correlator",
    "deepsecurity.realtime.enforcer",
    "deepsecurity.firewall.policy",
    "deepsecurity.protection.watchdog_twin",
    "deepsecurity.protection.mitigations",
    "deepsecurity.dns_sinkhole.blocklists",
    # Optional-dep wrappers (graceful no-op when dep missing).
    "deepsecurity.realtime.etw",
    "deepsecurity.realtime.sysmon",
    "deepsecurity.firewall.windivert",
    "deepsecurity.firewall.wfwapi",
    "deepsecurity.dns_sinkhole.server",
    "deepsecurity.protection.service",
    "deepsecurity.tls_proxy.proxy",
    "deepsecurity.tls_proxy.ca",
    "deepsecurity.memory_scan.inspector",
]


def _check_optional() -> dict[str, str]:
    """Probe each optional dep without crashing if it's missing."""
    out: dict[str, str] = {}
    for name in (
        "etw",
        "pydivert",
        "dnslib",
        "dnspython",
        "win32evtlog",
        "win32serviceutil",
        "mitmproxy",
        "authlib",
        "redis",
        "fakeredis",
        "alembic",
    ):
        try:
            mod = importlib.import_module(name if name != "dnspython" else "dns")
            ver = getattr(mod, "__version__", "?")
            out[name] = f"OK  {ver}"
        except ImportError as exc:
            out[name] = f"MISSING ({exc.__class__.__name__})"
        except Exception as exc:
            out[name] = f"ERROR {type(exc).__name__}: {exc}"
    return out


def main() -> int:
    print(f"DEEPSecurity v3 smoke — Python {sys.version.split()[0]}")
    print(f"  ROOT: {ROOT}\n")

    print("=== Optional dependencies ===")
    for name, status in _check_optional().items():
        print(f"  {name:20s} {status}")
    print()

    print("=== Importing v3 modules ===")
    failures: list[tuple[str, str]] = []
    for mod in MODULES:
        try:
            importlib.import_module(mod)
            print(f"  OK    {mod}")
        except Exception:
            tb = traceback.format_exc(limit=2)
            print(f"  FAIL  {mod}\n{tb}")
            failures.append((mod, tb))
    print()

    print("=== Quick correlator self-test ===")
    try:
        from deepsecurity.realtime.correlator import (
            Correlator,
            UnifiedEvent,
        )

        hits: list = []
        c = Correlator(emit=lambda d: hits.append(d))
        # Synthetic: cmd.exe spawned by winword.exe → R-PC-001.
        c.consume(
            UnifiedEvent(
                kind="process_create",
                pid=1001,
                parent_pid=999,
                image=r"C:\Windows\System32\cmd.exe",
                cmdline="cmd /c whoami",
            )
        )
        # We need to seed the parent first for the chain check to fire:
        c._tree.add(999, None, r"C:\Program Files\Microsoft Office\winword.exe")
        c.consume(
            UnifiedEvent(
                kind="process_create",
                pid=1002,
                parent_pid=999,
                image=r"C:\Windows\System32\cmd.exe",
                cmdline="cmd /c whoami",
            )
        )
        if any(d.rule_id == "R-PC-001" for d in hits):
            print("  OK    R-PC-001 (Office → shell) fired correctly")
        else:
            got = [d.rule_id for d in hits]
            print(f"  WARN  R-PC-001 did not fire on synthetic event (got {got})")
    except Exception:
        traceback.print_exc()
        failures.append(("correlator self-test", "exception"))

    print()
    if failures:
        print(f"FAILED: {len(failures)} module(s)")
        return 1
    print(f"PASS — {len(MODULES)}/{len(MODULES)} v3 modules import cleanly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
