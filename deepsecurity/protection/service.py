"""Run DEEPSecurity as a Windows Service.

Install / start / stop:

    deepsec service install
    deepsec service start
    deepsec service stop
    deepsec service uninstall

Behind the scenes this uses pywin32's ``win32serviceutil`` —
the canonical way to register a Python program as a Windows Service.
After install the service appears in services.msc as
``DEEPSecurity``.

We additionally call ``sc.exe`` to set:
    - delayed-auto-start = true
    - failure-recovery   = restart after 30 s, up to 3 times

so the OS itself revives DEEPSecurity if it crashes.

Optional dep: pywin32 (already in deepsecurity[windows]).
"""

from __future__ import annotations

import subprocess
import sys

from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)


SERVICE_NAME = "DEEPSecurity"
SERVICE_DISPLAY = "DEEPSecurity Policy / DLP Overlay"
SERVICE_DESCRIPTION = (
    "DEEPSecurity v3.0 — user-space policy, DLP, compliance overlay. "
    "Real-time process surveillance, host firewall, DNS sinkhole."
)


# ---------------------------------------------------------------------------
# Service entry — only imported on Windows when running under SCM.
# ---------------------------------------------------------------------------


def _service_main() -> None:  # pragma: no cover — Windows-only path
    """The actual service body. Boots the API + realtime layers, blocks until stop."""
    import servicemanager  # type: ignore[import-not-found]
    import win32event  # type: ignore[import-not-found]
    import win32service  # type: ignore[import-not-found]
    import win32serviceutil  # type: ignore[import-not-found]

    class DeepsecService(win32serviceutil.ServiceFramework):  # type: ignore[misc]
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)
            self._stop_requested = False

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._stop_requested = True
            win32event.SetEvent(self._stop_event)

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            try:
                from deepsecurity import lifecycle

                lifecycle.start(host=None, port=None, foreground=False)
            except Exception:
                _log.exception("service.start_failed")
                return
            # Block until SvcStop is called.
            win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)
            try:
                from deepsecurity import lifecycle

                lifecycle.stop()
            except Exception:
                _log.exception("service.stop_failed")

    win32serviceutil.HandleCommandLine(DeepsecService, argv=sys.argv)


# ---------------------------------------------------------------------------
# Installer / lifecycle helpers — usable from the CLI.
# ---------------------------------------------------------------------------


def install() -> bool:
    """Register DEEPSecurity as a Windows Service."""
    if not _is_windows():
        _log.warning("service.install.not_windows")
        return False
    try:
        # We re-exec this module — Python sees the right __main__ and
        # win32serviceutil installs the service.
        subprocess.run(
            [sys.executable, "-m", "deepsecurity.protection.service", "install"],
            check=True,
        )
        # Tighten failure-recovery so the OS revives us.
        subprocess.run(
            [
                "sc.exe",
                "failure",
                SERVICE_NAME,
                "reset=",
                "86400",
                "actions=",
                "restart/30000/restart/30000/restart/60000",
            ],
            check=False,
        )
        subprocess.run(
            ["sc.exe", "config", SERVICE_NAME, "start=", "delayed-auto"],
            check=False,
        )
        _log.info("service.installed", name=SERVICE_NAME)
        return True
    except subprocess.CalledProcessError:
        _log.exception("service.install_failed")
        return False


def uninstall() -> bool:
    if not _is_windows():
        return False
    try:
        subprocess.run(
            [sys.executable, "-m", "deepsecurity.protection.service", "remove"],
            check=True,
        )
        _log.info("service.uninstalled", name=SERVICE_NAME)
        return True
    except subprocess.CalledProcessError:
        _log.exception("service.uninstall_failed")
        return False


def start_service() -> bool:
    return _sc("start")


def stop_service() -> bool:
    return _sc("stop")


def status_service() -> str:
    """Return the SCM-reported state ('RUNNING', 'STOPPED', 'NOT_INSTALLED')."""
    if not _is_windows():
        return "NOT_WINDOWS"
    proc = subprocess.run(["sc.exe", "query", SERVICE_NAME], capture_output=True, text=True)
    if proc.returncode != 0:
        return "NOT_INSTALLED"
    for line in proc.stdout.splitlines():
        if "STATE" in line:
            for token in ("RUNNING", "STOPPED", "START_PENDING", "STOP_PENDING"):
                if token in line:
                    return token
    return "UNKNOWN"


def _sc(action: str) -> bool:
    if not _is_windows():
        return False
    proc = subprocess.run(["sc.exe", action, SERVICE_NAME], capture_output=True, text=True)
    if proc.returncode == 0:
        _log.info(f"service.{action}", name=SERVICE_NAME)
        return True
    _log.warning(f"service.{action}_failed", stderr=proc.stderr.strip()[:200])
    return False


def _is_windows() -> bool:
    import os

    return os.name == "nt"


if __name__ == "__main__":  # pragma: no cover
    _service_main()
