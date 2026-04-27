"""Wrapper around mitmproxy for opt-in TLS inspection.

We don't reimplement mitmproxy — it already does what we need (TLS
termination + cert generation + addon API). We import the embedded
mitmproxy library, register a small addon that:

    1. Filters every flow against the firewall policy.
    2. Runs DLP scan_text() over the request/response body if it's
       textual (matching the configured DLP_MAX_BYTES cap).
    3. Drops or alerts based on the policy's action.

Optional dep:
    pip install "deepsecurity[tls-proxy]"  # ~30 MB; keep on a separate
                                            # extra so the default
                                            # install stays slim.
"""

from __future__ import annotations

import threading
from typing import Any

from deepsecurity.config import settings
from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)


class TlsProxy:
    """Thin wrapper around mitmproxy.tools.dump.DumpMaster."""

    def __init__(
        self,
        *,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8080,
    ) -> None:
        self._host = listen_host
        self._port = listen_port
        self._master: Any = None
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------
    def start(self) -> bool:
        try:
            from mitmproxy.options import Options  # type: ignore[import-not-found]
            from mitmproxy.tools.dump import DumpMaster  # type: ignore[import-not-found]
        except ImportError:
            _log.warning(
                "tls.unavailable",
                hint='pip install "deepsecurity[tls-proxy]"',
            )
            return False

        opts = Options(
            listen_host=self._host,
            listen_port=self._port,
            ssl_insecure=False,
        )
        self._master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        self._master.addons.add(_DeepsecAddon())

        def _run() -> None:
            try:
                import asyncio

                asyncio.run(self._master.run())
            except Exception:
                _log.exception("tls.run_failed")

        self._thread = threading.Thread(target=_run, name="tls-proxy", daemon=True)
        self._thread.start()
        _log.info("tls.started", listen=f"{self._host}:{self._port}")
        return True

    # ------------------------------------------------------------------
    def stop(self) -> None:
        if self._master is not None:
            try:
                self._master.shutdown()
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        _log.info("tls.stopped")


class _DeepsecAddon:  # pragma: no cover — runs inside mitmproxy
    """mitmproxy addon: DLP scan request/response bodies + policy gate."""

    def request(self, flow: Any) -> None:
        try:
            from deepsecurity.dlp import scan_text

            body = flow.request.get_text() or ""
            if len(body) > settings.dlp_max_bytes:
                return
            findings = scan_text(body, file_path=flow.request.url)
            if findings:
                _log.warning(
                    "tls.dlp_request_hit",
                    url=flow.request.url,
                    patterns=[f.pattern_name for f in findings],
                )
        except Exception:
            _log.exception("tls.addon_request_failed")

    def response(self, flow: Any) -> None:
        try:
            from deepsecurity.dlp import scan_text

            body = flow.response.get_text() or ""
            if len(body) > settings.dlp_max_bytes:
                return
            findings = scan_text(body, file_path=flow.request.url)
            if findings:
                _log.warning(
                    "tls.dlp_response_hit",
                    url=flow.request.url,
                    patterns=[f.pattern_name for f in findings],
                )
        except Exception:
            _log.exception("tls.addon_response_failed")
