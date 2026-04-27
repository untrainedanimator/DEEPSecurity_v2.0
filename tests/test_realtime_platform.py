"""Smoke tests for the cross-platform realtime listener factory."""

from __future__ import annotations

import platform

from deepsecurity.realtime import platform as rt_platform
from deepsecurity.realtime.darwin_es import DarwinEndpointSecurityListener
from deepsecurity.realtime.linux_ebpf import LinuxEbpfListener


def test_detect_returns_capabilities_for_current_os() -> None:
    caps = rt_platform.detect_capabilities()
    assert caps.os_name in ("windows", "linux", "darwin")
    assert caps.os_release == platform.release()
    # Realtime support state is consistent with OS:
    if caps.is_windows():
        # Windows might or might not have ETW deps installed in this env.
        assert isinstance(caps.has_etw, bool)
    elif caps.is_linux():
        assert caps.has_etw is False
        assert caps.has_sysmon is False
    elif caps.is_darwin():
        assert caps.has_etw is False
        assert caps.has_endpoint_security is False  # v3.0 stub


def test_make_listener_returns_stub_on_unsupported_os() -> None:
    """Linux and macOS in v3.0 always return StubListener.start()=False."""
    received: list = []
    caps = rt_platform.PlatformCapabilities(
        os_name="linux",
        os_release="6.0",
        has_etw=False, has_sysmon=False, has_windivert=False,
        has_defender_fw=False, has_ebpf=False, has_auditd=False,
        has_endpoint_security=False,
        notes=[],
    )
    listener = rt_platform.make_listener(received.append, capabilities=caps)
    assert listener.running is False
    assert listener.start() is False
    listener.stop()


def test_linux_ebpf_listener_is_stub() -> None:
    received: list = []
    listener = LinuxEbpfListener(on_event=received.append)
    assert listener.running is False
    assert listener.start() is False
    assert listener.attach_program("test", "/path") is False
    listener.stop()


def test_darwin_es_listener_is_stub() -> None:
    received: list = []
    listener = DarwinEndpointSecurityListener(on_event=received.append)
    assert listener.running is False
    assert listener.start() is False
    listener.stop()


def test_unsupported_os_capabilities() -> None:
    """An exotic OS string returns capabilities with everything off."""
    # We can't actually change platform.system(), but the helper handles
    # the unknown branch deterministically.
    caps = rt_platform.PlatformCapabilities(
        os_name="haiku",
        os_release="r1beta5",
        has_etw=False, has_sysmon=False, has_windivert=False,
        has_defender_fw=False, has_ebpf=False, has_auditd=False,
        has_endpoint_security=False,
        notes=["unsupported OS: haiku"],
    )
    assert not caps.is_windows()
    assert not caps.is_linux()
    assert not caps.is_darwin()
    assert caps.realtime_supported() is False


def test_make_listener_falls_through_on_windows_without_etw() -> None:
    """On Windows without ETW deps, factory returns a StubListener."""
    caps = rt_platform.PlatformCapabilities(
        os_name="windows",
        os_release="11",
        has_etw=False, has_sysmon=False, has_windivert=False,
        has_defender_fw=False, has_ebpf=False, has_auditd=False,
        has_endpoint_security=False,
        notes=['install "deepsecurity[edr]" for ETW'],
    )
    listener = rt_platform.make_listener(lambda _ev: None, capabilities=caps)
    # Falls through past the Windows branch (no ETW) → StubListener
    assert listener.start() is False
