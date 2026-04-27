"""CA install / uninstall helpers for the TLS proxy.

mitmproxy generates a CA on first run and stores the cert + key under
``~/.mitmproxy/``. We just need to:
    1. Push that cert into the OS Trusted Root store.
    2. On uninstall, remove it.

Windows: ``certutil -addstore Root <cert>``.
macOS:   ``sudo security add-trusted-cert -d -r trustRoot``
         ``-k /Library/Keychains/System.keychain <cert>``.
Linux:   distro-specific (``update-ca-certificates`` after copying).

This module is helpers only; the CLI wires them into ``deepsec tls install-ca``.
"""

from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path

from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)


MITMPROXY_DIR = Path(os.path.expanduser("~/.mitmproxy"))
CA_PEM = MITMPROXY_DIR / "mitmproxy-ca-cert.pem"
CA_CER = MITMPROXY_DIR / "mitmproxy-ca-cert.cer"


def install() -> bool:
    """Install the mitmproxy CA into the OS trusted-root store."""
    cert = CA_CER if CA_CER.exists() else CA_PEM
    if not cert.exists():
        _log.warning(
            "tls.ca.absent",
            hint="run mitmproxy/mitmdump once to bootstrap ~/.mitmproxy",
        )
        return False
    system = platform.system()
    try:
        if system == "Windows":
            subprocess.run(
                ["certutil", "-addstore", "Root", str(cert)],
                check=True,
                capture_output=True,
            )
        elif system == "Darwin":
            subprocess.run(
                [
                    "sudo",
                    "security",
                    "add-trusted-cert",
                    "-d",
                    "-r",
                    "trustRoot",
                    "-k",
                    "/Library/Keychains/System.keychain",
                    str(cert),
                ],
                check=True,
                capture_output=True,
            )
        elif system == "Linux":
            target = Path("/usr/local/share/ca-certificates/deepsec-mitmproxy.crt")
            subprocess.run(["sudo", "cp", str(cert), str(target)], check=True)
            subprocess.run(["sudo", "update-ca-certificates"], check=True)
        else:
            _log.warning("tls.ca.unsupported_os", os=system)
            return False
        _log.info("tls.ca.installed", os=system)
        return True
    except subprocess.CalledProcessError:
        _log.exception("tls.ca.install_failed")
        return False


def uninstall() -> bool:
    """Remove the mitmproxy CA from the OS trusted-root store."""
    system = platform.system()
    try:
        if system == "Windows":
            # Find by friendly name and delete.
            subprocess.run(
                ["certutil", "-delstore", "Root", "mitmproxy"],
                check=False,
                capture_output=True,
            )
        elif system == "Darwin":
            subprocess.run(
                [
                    "sudo",
                    "security",
                    "delete-certificate",
                    "-c",
                    "mitmproxy",
                    "/Library/Keychains/System.keychain",
                ],
                check=False,
                capture_output=True,
            )
        elif system == "Linux":
            target = Path("/usr/local/share/ca-certificates/deepsec-mitmproxy.crt")
            if target.exists():
                subprocess.run(["sudo", "rm", str(target)], check=False)
                subprocess.run(["sudo", "update-ca-certificates", "--fresh"], check=False)
        _log.info("tls.ca.uninstalled", os=system)
        return True
    except Exception:
        _log.exception("tls.ca.uninstall_failed")
        return False
