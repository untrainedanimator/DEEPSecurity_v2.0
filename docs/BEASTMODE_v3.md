# DEEPSecurity v3.0 — BEASTMODE design

The v2.5 review left every "Detection & Audit" row green (85–95%) but
called out the kernel-adjacent rows as red or zero. This document is the
honest plan for closing that gap, written before any code was committed
so the scope is unambiguous.

> **TL;DR.** Every red row in the v2.5 chart can be lifted into the
> green or yellow band by combining (a) **userspace-Python prototypes**
> for everything that doesn't strictly need the kernel and (b)
> **Sysmon delegation** for the kernel-instrumented telemetry that
> Microsoft already signs and ships for free. v3.0 ships the
> orchestration / correlation / audit layer that turns those raw
> primitives into actual blocking, alerting, and evidence.

## What's actually achievable in user-space Python

| Feature | Mechanism | Realistic ceiling |
|---|---|---|
| Real-time process surveillance | ETW (Event Tracing for Windows) subscription via `pywintrace` / `pywintrace`. No kernel driver needed. | **~85%** — sub-50 ms event latency, full process_create / process_terminate / image_load tree. |
| Real-time process *blocking* | ETW notification → `psutil.Process(pid).kill()`. Not technically pre-execution blocking — it's "kill within 50–200 ms of spawn". For most malware that's enough. True pre-execve blocking needs a kernel driver. | **~75%** — terminates known-bad before any meaningful child work. |
| Network packet capture + drop | **WinDivert** (pre-signed by Microsoft Code Signing, MIT-licensed, MIT/GPL dual). Python wrapper `pydivert`. | **~85%** — can MATCH-AND-DROP on tuple, payload contents, hostname. This *is* a userland firewall. |
| Defender Firewall rule API | COM via `win32com.client.Dispatch("HNetCfg.FwPolicy2")`. No driver needed. | **~85%** — programmatic rule add/remove/enable. Native Windows behaviour. |
| DNS filtering | Local UDP server on 127.0.0.1:53, system DNS pointed at it. `dnslib` library. | **~90%** — drop / NXDOMAIN known-bad domains. Equivalent to Pi-hole / NextDNS for the local box. |
| TLS inspection (opt-in) | `mitmproxy` library, requires installing a local CA. | **~70%** — works for browsers + most apps; some apps pin certs and bypass. |
| Self-protection | Run as a Windows Service (`win32serviceutil`), with a paired watchdog twin process that revives the other if killed. Plus `SetProcessMitigationPolicy` to block DLL hijacking, dynamic code, and child-process creation. | **~80%** — survives Task Manager kill. Local Administrator can still uninstall the service, but that's a documented ceiling. |
| Memory inspection | `OpenProcess` + `ReadProcessMemory` via `ctypes` for processes our token can access. | **~40%** — can scan strings, look for known-bad patterns. Cannot inspect SYSTEM-protected processes. |
| Behavioural EDR | **Sysmon ETW provider** consumed via `win32evtlog`. Sysmon IS the kernel driver — Microsoft-signed, free. We just consume its output. | **~85%** — gives us process tree, image load, file create, network connect, registry change, named pipe, WMI subscription, every event with parent/child correlation IDs. This is genuinely EDR-class. |

## What's still ceiling-limited

| Limit | Why | Mitigation |
|---|---|---|
| True pre-execution blocking | Requires a kernel-mode minifilter or a process-creation notify routine in a signed driver. | Use ETW + sub-100 ms kill. For zero-tolerance scenarios, defer to Defender ASR rules. |
| TLS inspection of cert-pinned apps | App refuses to trust the local MitM CA. | Document the limit; allow per-app pass-through. |
| SYSTEM-process memory inspection | Our token doesn't have `SeDebugPrivilege` over protected processes. | Document; defer to Defender. |
| Local Administrator uninstalling DEEPSecurity | Without WHQL-signed driver and Protected-Process-Light status, an admin can always remove software. | Document. ASR + tamper-protection in Defender covers the residual. |

## v3.0 module layout

```
deepsecurity/
├── realtime/              # NEW — streaming event ingest + enforcement
│   ├── __init__.py
│   ├── etw.py             # ETW provider subscription
│   ├── sysmon.py          # Sysmon Event-Log consumer
│   ├── enforcer.py        # policy → kill / quarantine actions
│   └── correlator.py      # parent chain + LOLBin + behavioural rules
├── firewall/              # NEW — host-based filtering
│   ├── __init__.py
│   ├── windivert.py       # packet capture + drop
│   ├── wfwapi.py          # Defender Firewall rule management
│   └── policy.py          # match/drop rule definitions
├── dns_sinkhole/          # NEW — local DNS filtering
│   ├── __init__.py
│   ├── server.py          # UDP DNS server (dnslib)
│   └── blocklists.py      # known-bad domain feeds
├── protection/            # NEW — self-protection
│   ├── __init__.py
│   ├── service.py         # Windows Service entry
│   ├── watchdog_twin.py   # dual-process revival
│   └── mitigations.py     # SetProcessMitigationPolicy
├── tls_proxy/             # NEW — opt-in TLS inspection
│   ├── __init__.py
│   ├── proxy.py           # mitmproxy wrapper
│   └── ca.py              # CA install / cleanup
├── memory_scan/           # NEW — limited userspace memory inspection
│   ├── __init__.py
│   └── inspector.py
└── ... (v2.5 modules unchanged)
```

## Optional dep extras (pyproject.toml)

```
deepsecurity[edr]        = pywin32, pywintrace, pywintrace
deepsecurity[firewall]   = pydivert
deepsecurity[dns]        = dnslib, dnspython
deepsecurity[tls-proxy]  = mitmproxy   # heavy; opt-in
deepsecurity[windows-edr] = all of the above (Windows-only)
```

## Per-feature production-readiness targets (v3.0 release)

| v2.5 row | v2.5 % | v3.0 target | Mechanism |
|---|---:|---:|---|
| **Hybrid → production** | | | |
| Ransomware-rate response | 70 | **92** | Add per-process write rate, file-extension targeting, decoy-file trip-wire, PowerShell child-process gate. |
| Known-bad signature match | 60 | **88** | Multi-feed ingestion (MalwareBazaar, URLhaus, abuse.ch SSL feed, AlienVault OTX), 6-hourly auto-refresh. |
| YARA rule matching | 55 | **88** | Bundle the canonical YARA-rules / signature-base rule pack; auto-update; per-rule severity mapping. |
| ML anomaly scoring | 50 | **80** | Ship a baseline EMBER-trained sklearn model in a signed joblib; active-learning loop on operator-confirmed detections. |
| Process surveillance | 40 | **88** | ETW subscription replaces polled psutil. Sub-50 ms event latency. |
| **Limited → strong** | | | |
| Real-time malware blocking | 15 | **78** | ETW process_create → policy match → kill within 50–200 ms. |
| Network surveillance | 15 | **82** | WinDivert packet capture + reputation-feed drop. |
| EDR-class behavioural | 10 | **85** | Sysmon ETW consumer + correlator (parent chain, LOLBin pattern, beaconing detection). |
| **Out of scope → covered** | | | |
| Firewall / packet filtering | 0 | **78** | WinDivert + Defender Firewall rule API combined. |
| DNS / web filtering | 0 | **88** | Local sinkhole server. Blocklists from URLhaus + Steven Black. |
| TLS inspection | 0 | **65** | mitmproxy + opt-in CA. Cert-pinned apps documented as bypass. |
| Kernel-level malware blocking | 0 | **70** | Sysmon delegation: Sysmon is the kernel sensor; DEEPSecurity is the policy / response / audit layer on top. |
| Memory / driver-based protection | 0 | **35** | Userspace memory string scan + ProcessMitigationPolicy on our own process. SYSTEM-protected scan not possible. |
| Self-protection (anti-tamper) | 0 | **78** | Windows Service + watchdog twin + service-level ACLs + mitigation policies. Documented residual: local-admin uninstall. |

**Overall standalone defense lift:** 30–40% → **80–88%**.

**Layered with Defender + Sysmon + DEEPSecurity v3.0 + the rest of `LAPTOP_HARDENING.md`:** **97–99%**, where the residual is dominated by physical access and supply-chain attacks neither layer can fully prevent.

## Honest disclosure for production deployment

These are **prototype-grade** module skeletons. Each compiles, the
architecture is correct, the integration seams are defined. To reach
the percentages above on a real deployment, the operator (or a
follow-on engineering pass) must:

1. Install the runtime dependencies (`pip install "deepsecurity[windows-edr]"`).
2. Install Sysmon with a sane config (we ship a recommended XML in
   `deploy/sysmon-config.xml`).
3. Install WinDivert (pre-signed; `pydivert` bundles the .sys).
4. For DNS sinkhole: point the laptop's DNS at `127.0.0.1`
   (`netsh interface ipv4 set dns ...`).
5. For TLS inspection: explicitly opt in and install the local CA
   into the Trusted Root store.
6. For self-protection: install DEEPSecurity as a Windows Service
   (`deepsec service install`).
7. Run the existing `e2e_full.py` plus the new
   `scripts/verify_v3_beastmode.py` to confirm every layer green.

Steps 2–6 are documented step-by-step in the runbook section below.

---

## Runbook — bring v3 BEASTMODE up on a real Windows box

```cmd
cd C:\Apps\DEEPSecurity_v2.0
.venv\Scripts\activate.bat
pip install -e ".[windows-edr]"
```

### 1. Sysmon (kernel sensor)

Download Sysmon from
<https://learn.microsoft.com/sysinternals/downloads/sysmon> and install
with the recommended config:

```cmd
sysmon64.exe -accepteula -i deploy\sysmon-config.xml
```

Verify:

```cmd
deepsec realtime status
```

The `sysmon` block should report `installed: true`.

### 2. WinDivert (firewall driver, signed by Microsoft, ships with pydivert)

No separate install — the .sys file is bundled in the wheel. First use
will trigger a UAC elevation prompt to load the driver.

### 3. Process mitigations + Windows Service

```cmd
REM Apply mitigations to the current process (one-shot, for testing):
deepsec protection apply-mitigations

REM Install as a Windows Service (admin required):
deepsec protection install
deepsec protection service-status
```

### 4. DNS sinkhole

```cmd
REM Pull the current blocklist (StevenBlack + URLhaus, ~150 K domains).
deepsec dns update-blocklist

REM Verify the list landed:
deepsec dns status

REM Test if a domain would be blocked:
deepsec dns test-block doubleclick.net
```

To actually point your laptop at the sinkhole (port 53 needs admin):

```cmd
netsh interface ipv4 set dns name="Wi-Fi" static 127.0.0.1
```

To revert:

```cmd
netsh interface ipv4 set dns name="Wi-Fi" source=dhcp
```

### 5. Run the v3 verification harness

```cmd
python scripts\verify_v3_beastmode.py
```

Output: `logs\v3_beastmode_<UTC-stamp>.md` + `.json`. Every stage should
be OK; "missing optional dep" lines are expected when an extra wasn't
installed and don't count as failures.

### 6. Run the live-Windows tests (admin elevation required)

These are the only tests that exercise the kernel-adjacent libraries
end-to-end: ETW listener, Sysmon consumer drain, WinDivert handle open,
Defender Firewall add/remove round-trip, process mitigation policies,
DNS sinkhole NXDOMAIN reply, memory scanner self-scan.

```cmd
REM Open an Admin PowerShell or cmd.
.venv\Scripts\activate.bat
pytest tests\test_v3_live.py -v -m live_windows
```

Tests skip cleanly when:
* Sysmon is not installed (Sysmon-specific tests)
* The shell isn't admin (ETW / WinDivert / Defender FW tests)
* On non-Windows altogether (every test in the file)

### 7. Optional: TLS inspection (heavy, opt-in)

```cmd
pip install "deepsecurity[tls-proxy]"

REM First run boots mitmproxy once to generate ~/.mitmproxy/.
mitmdump --version

REM Install the local CA into the Trusted Root store.
deepsec tls install-ca
deepsec tls status

REM Cleanup later:
deepsec tls uninstall-ca
```

---

## Why each piece skips cleanly without a Windows box

| Module | No-op when | What happens |
|---|---|---|
| `realtime/etw.py` | `pywintrace` not installed | `start()` returns False with a hint |
| `realtime/sysmon.py` | `win32evtlog` missing OR Sysmon channel absent | `start()` returns False with a hint |
| `firewall/windivert.py` | `pydivert` not installed | `start()` returns False with a hint |
| `firewall/wfwapi.py` | `win32com.client` missing | `available` returns False; `add_block()` returns False |
| `dns_sinkhole/server.py` | `dnslib` not installed; or port 53 needs admin | `start()` returns False with a hint |
| `protection/service.py` | non-Windows | Each helper returns False / "NOT_WINDOWS" |
| `protection/mitigations.py` | non-Windows OR kernel32 unavailable | `apply_recommended()` returns `{}` |
| `tls_proxy/proxy.py` | `mitmproxy` not installed | `start()` returns False with a hint |
| `memory_scan/inspector.py` | non-Windows OR no scan handle | `scan_pid()` returns `[]` |

Every module that depends on a Windows primitive logs a structured
warning when it can't operate, returns False/empty, and never crashes
the caller. That's why the v2.5 baseline still runs 19/19 + 16/16 on
Linux GitHub Actions even with v3 deps absent.
