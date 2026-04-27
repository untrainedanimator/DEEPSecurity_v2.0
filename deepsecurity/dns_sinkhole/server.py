"""Local DNS sinkhole server (UDP).

Listens on 127.0.0.1:53 by default. For every query:
    1. Lower-case the queried name.
    2. Look it up in the blocklist (loaded from
       ``data/sinkhole_blocklist.txt`` on start; reload via SIGHUP).
    3. If blocked → return NXDOMAIN with our sinkhole IP in the reply
       hint (so a paranoid client won't get a successful response).
    4. Otherwise → forward to the configured upstream and relay the
       answer.

To use:
    netsh interface ipv4 set dns name="Wi-Fi" static 127.0.0.1
    deepsec dns start

To revert:
    netsh interface ipv4 set dns name="Wi-Fi" source=dhcp

Optional dep:
    pip install "deepsecurity[dns]"  # pulls dnslib + dnspython
"""

from __future__ import annotations

import socket
import threading
from pathlib import Path

from deepsecurity.audit import audit_log
from deepsecurity.dns_sinkhole.blocklists import load as load_blocklist
from deepsecurity.logging_config import get_logger

_log = get_logger(__name__)


SINKHOLE_IP = "0.0.0.0"


class DnsSinkhole:
    """Small UDP DNS server with a domain blocklist."""

    def __init__(
        self,
        *,
        bind: str = "127.0.0.1",
        port: int = 53,
        upstream: tuple[str, int] = ("1.1.1.1", 53),
        blocklist_path: Path = Path("./data/sinkhole_blocklist.txt"),
    ) -> None:
        self._bind = bind
        self._port = port
        self._upstream = upstream
        self._blocklist_path = blocklist_path
        self._block: set[str] = set()
        self._sock: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stats = {"forwarded": 0, "blocked": 0, "errors": 0}

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ------------------------------------------------------------------
    def reload_blocklist(self) -> int:
        self._block = load_blocklist(self._blocklist_path)
        _log.info("dns.blocklist_reloaded", count=len(self._block))
        return len(self._block)

    # ------------------------------------------------------------------
    def start(self) -> bool:
        try:
            import dnslib  # noqa: F401  # type: ignore[import-not-found]
        except ImportError:
            _log.warning(
                "dns.unavailable",
                hint='pip install "deepsecurity[dns]"',
            )
            return False

        self.reload_blocklist()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self._sock.bind((self._bind, self._port))
        except PermissionError:
            _log.error(
                "dns.bind_denied",
                hint="port 53 needs admin rights — run as administrator",
            )
            self._sock.close()
            self._sock = None
            return False
        except OSError as exc:
            _log.error("dns.bind_failed", error=str(exc))
            self._sock.close()
            self._sock = None
            return False

        self._stop.clear()
        self._thread = threading.Thread(target=self._serve, name="dns-sinkhole", daemon=True)
        self._thread.start()
        _log.info(
            "dns.started",
            bind=f"{self._bind}:{self._port}",
            upstream=f"{self._upstream[0]}:{self._upstream[1]}",
            blocked=len(self._block),
        )
        return True

    # ------------------------------------------------------------------
    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        _log.info("dns.stopped", stats=self.stats)

    # ------------------------------------------------------------------
    def _serve(self) -> None:
        from dnslib import RCODE, RR, A, DNSRecord  # type: ignore[import-not-found]

        assert self._sock is not None
        sock = self._sock
        sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except (TimeoutError, OSError):
                continue

            try:
                request = DNSRecord.parse(data)
                qname = str(request.q.qname).rstrip(".").lower()
            except Exception:
                self._stats["errors"] += 1
                continue

            if self._is_blocked(qname):
                reply = request.reply()
                reply.header.rcode = RCODE.NXDOMAIN
                # Hint with the sinkhole IP so a misbehaving client gets 0.0.0.0.
                try:
                    reply.add_answer(RR(qname, rdata=A(SINKHOLE_IP), ttl=60))
                except Exception:
                    pass
                self._stats["blocked"] += 1
                try:
                    sock.sendto(reply.pack(), addr)
                    audit_log(
                        actor="deepsec.dns",
                        action="dns.block",
                        status="ok",
                        details={"qname": qname, "client": f"{addr[0]}:{addr[1]}"},
                    )
                except Exception:
                    self._stats["errors"] += 1
                continue

            # Forward upstream.
            try:
                fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                fwd.settimeout(2.0)
                fwd.sendto(data, self._upstream)
                resp_data, _ = fwd.recvfrom(4096)
                fwd.close()
                sock.sendto(resp_data, addr)
                self._stats["forwarded"] += 1
            except Exception:
                self._stats["errors"] += 1

    # ------------------------------------------------------------------
    def _is_blocked(self, qname: str) -> bool:
        # Direct match or any parent label match (so blocking ``ads.example``
        # also blocks ``a.b.ads.example``).
        if qname in self._block:
            return True
        labels = qname.split(".")
        return any(".".join(labels[i:]) in self._block for i in range(len(labels) - 1))
