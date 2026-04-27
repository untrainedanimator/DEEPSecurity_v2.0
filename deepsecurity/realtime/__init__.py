"""Real-time event ingest and enforcement (v3.0).

Three stacked layers:

    etw.py        — subscribe to ETW providers for process, image-load,
                    file-create, network-connect events. Sub-50 ms latency.
    sysmon.py     — consume the Sysmon ETW provider via the Windows Event
                    Log. Sysmon is the kernel sensor (Microsoft-signed,
                    free); DEEPSecurity is the analytics + response layer.
    correlator.py — turn raw events into typed behavioural detections
                    (parent-chain anomaly, LOLBin invocation, beaconing).
    enforcer.py   — apply the configured policy to a detection: alert,
                    audit-log, kill the process, quarantine the file.

The four pieces are deliberately decoupled. Tests can feed synthetic
events into the correlator without touching ETW; the enforcer can be
unit-tested with a fake event stream.
"""

from __future__ import annotations
