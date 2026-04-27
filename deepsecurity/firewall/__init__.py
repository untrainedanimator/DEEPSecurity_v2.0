"""Host-based packet filtering (v3.0).

Two complementary mechanisms:

    windivert.py  — userspace packet capture + drop via the WinDivert
                    driver (Microsoft-signed, MIT-licensed, bundled in
                    pydivert). True inline filtering.
    wfwapi.py     — programmatic Windows Defender Firewall rules via the
                    HNetCfg.FwPolicy2 COM object. Persistent rules
                    survive reboot.
    policy.py     — declarative FirewallPolicy that the operator
                    configures once and both mechanisms enforce.

Use-case split:
    - Need to drop a specific TCP flow RIGHT NOW based on payload?
      → windivert.py (inline, sub-millisecond decision).
    - Need to block a destination forever? → wfwapi.py (persistent
      Defender Firewall rule).
"""

from __future__ import annotations
