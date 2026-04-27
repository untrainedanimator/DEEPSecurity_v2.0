"""Live-Windows tests for v3.0 BEASTMODE — skipped by default in CI.

These tests require:
    * Windows 10/11
    * Administrator elevation (UAC prompt at process start)
    * Optionally: Sysmon installed with deploy/sysmon-config.xml

To run them locally:

    REM 1. Open an ADMIN PowerShell / cmd.
    REM 2. Activate the venv.
    REM 3. Tell pytest to run the live mark.
    .venv\\Scripts\\activate.bat
    pytest tests\\test_v3_live.py -v -m live_windows

In CI (GitHub Actions ubuntu-latest), these tests are auto-skipped via
the ``live_windows`` mark — no Windows runner needed.

Each test below is intentionally narrow: just enough to prove the v3
module talks to its underlying Windows primitive, with cleanup after.
"""
from __future__ import annotations

import ctypes
import os
import socket
from pathlib import Path

import pytest

# Skip the entire module on non-Windows systems.
pytestmark = [
    pytest.mark.live_windows,
    pytest.mark.skipif(os.name != "nt", reason="Windows-only"),
]


def _is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return False


# ---------------------------------------------------------------------------
# ETW — needs Administrator; pywintrace must be installed.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _is_admin(), reason="ETW needs Administrator")
def test_etw_listener_starts_and_stops_cleanly() -> None:
    pytest.importorskip("etw")
    from deepsecurity.realtime.etw import EtwEvent, EtwListener

    seen: list[EtwEvent] = []
    listener = EtwListener(on_event=seen.append)
    started = listener.start()
    try:
        assert started, "EtwListener.start() returned False"
        assert listener.running
    finally:
        listener.stop(timeout=3.0)
    assert not listener.running


# ---------------------------------------------------------------------------
# Sysmon — needs Sysmon installed and Administrator (to read the channel).
# ---------------------------------------------------------------------------


def test_sysmon_channel_reachable_when_installed() -> None:
    pytest.importorskip("win32evtlog")
    import win32evtlog  # type: ignore[import-not-found]

    from deepsecurity.realtime.sysmon import CHANNEL, _channel_exists

    if not _channel_exists(win32evtlog, CHANNEL):
        pytest.skip(f"Sysmon channel {CHANNEL} not present — install Sysmon first")


@pytest.mark.skipif(not _is_admin(), reason="Sysmon Event Log needs Administrator")
def test_sysmon_consumer_drains_one_record() -> None:
    pytest.importorskip("win32evtlog")
    from deepsecurity.realtime.sysmon import SysmonConsumer

    received: list = []
    c = SysmonConsumer(on_event=received.append, poll_interval_s=0.1)
    started = c.start()
    if not started:
        pytest.skip("Sysmon channel missing")
    try:
        # Trigger a process_create event by spawning a short-lived child.
        import subprocess
        subprocess.run(["cmd.exe", "/c", "echo deepsec_e2e_probe"], check=False)
        # Give the consumer up to 5s to see it.
        import time
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not received:
            time.sleep(0.1)
    finally:
        c.stop(timeout=3.0)
    assert received, "Sysmon consumer received no events in 5s"


# ---------------------------------------------------------------------------
# WinDivert — needs Administrator to load the .sys driver.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _is_admin(), reason="WinDivert needs Administrator")
def test_windivert_handle_opens_and_closes() -> None:
    pydivert = pytest.importorskip("pydivert")
    # Just open + close. Don't run a packet pump — that interferes with
    # whatever the user is doing on the network.
    with pydivert.WinDivert("false") as w:  # "false" matches no packets
        assert w is not None
    # If we got here, the driver loaded and closed cleanly.


# ---------------------------------------------------------------------------
# Defender Firewall — needs Administrator.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _is_admin(), reason="Defender Firewall API needs Administrator")
def test_defender_firewall_add_remove_round_trip() -> None:
    pytest.importorskip("win32com.client")
    from deepsecurity.firewall.wfwapi import DefenderFirewall

    fw = DefenderFirewall()
    assert fw.available
    name = "deepsec-live-test-block"
    # Clean slate (no-op if it doesn't exist).
    fw.remove(name)
    try:
        ok = fw.add_block(
            name=name, remote_ip="203.0.113.42", protocol="any", direction="outbound",
        )
        assert ok
        managed = fw.list_managed("deepsec-live-test")
        assert any(r["name"] == name for r in managed)
    finally:
        fw.remove(name)


# ---------------------------------------------------------------------------
# Process mitigations — applies to the running interpreter; one-shot.
# ---------------------------------------------------------------------------


def test_process_mitigations_apply_returns_results() -> None:
    from deepsecurity.protection.mitigations import apply_recommended

    result = apply_recommended()
    # On non-Windows the function returns {} cleanly.
    # On Windows we expect the dict to have at least one True (older
    # Windows refuse some policies but never all of them).
    if os.name == "nt":
        assert isinstance(result, dict)
        assert any(v for v in result.values()), f"No mitigation policy applied: {result}"
    else:
        assert result == {}


# ---------------------------------------------------------------------------
# DNS sinkhole — bind on a non-admin port (5353) and send one query.
# ---------------------------------------------------------------------------


def _free_udp_port() -> int:
    """Ask the OS for a free UDP port on loopback. Best-effort — there's
    a tiny race window between close and the sinkhole's bind, but on
    Windows the port is rarely re-used that fast."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


def test_dns_sinkhole_serves_a_query(tmp_path: Path) -> None:
    pytest.importorskip("dnslib")
    from deepsecurity.dns_sinkhole.server import DnsSinkhole

    blocklist = tmp_path / "blocked.txt"
    blocklist.write_text("malicious.example\n", encoding="utf-8")

    # 5353 is reserved on most Windows hosts (mDNS, Bonjour, Hyper-V vSwitch).
    # Use an ephemeral port the OS hands us instead so the test is portable.
    port = _free_udp_port()
    server = DnsSinkhole(
        bind="127.0.0.1",
        port=port,
        upstream=("1.1.1.1", 53),
        blocklist_path=blocklist,
    )
    if not server.start():
        pytest.skip("DnsSinkhole.start() returned False — port busy or dnslib missing")
    try:
        # Build a minimal A query for malicious.example, send to our server.
        import dnslib  # type: ignore[import-not-found]

        q = dnslib.DNSRecord.question("malicious.example")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2.0)
        s.sendto(q.pack(), ("127.0.0.1", port))
        data, _ = s.recvfrom(4096)
        s.close()
        reply = dnslib.DNSRecord.parse(data)
        # NXDOMAIN expected when domain is in the blocklist.
        assert reply.header.rcode == dnslib.RCODE.NXDOMAIN
        assert server.stats["blocked"] >= 1
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Memory scanner — scan our own pid; should return without crashing.
# ---------------------------------------------------------------------------


def test_memory_scan_own_pid_completes() -> None:
    from deepsecurity.memory_scan.inspector import scan_pid

    findings = scan_pid(os.getpid(), max_bytes=8 * 1024 * 1024)
    # Output is opaque (DLP patterns may or may not match in the heap).
    # The contract is: scan returns a list and doesn't crash.
    assert isinstance(findings, list)
