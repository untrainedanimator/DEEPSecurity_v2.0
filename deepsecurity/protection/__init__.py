"""Self-protection layer (v3.0).

Three complementary mechanisms — none is a kernel driver, but the
combination buys ~80% of "you can't easily kill DEEPSecurity":

    service.py        Run as a Windows Service. Auto-restart on crash.
                      Service-control ACLs make 'sc stop' admin-only.
    watchdog_twin.py  A second tiny process that monitors the main one
                      and re-spawns it if it disappears. The main
                      process monitors the twin. Killing both at the
                      same instant is the only way through.
    mitigations.py    SetProcessMitigationPolicy at startup: block
                      child-process creation, block dynamic code,
                      block remote image loading, etc. Limits what an
                      attacker can do FROM INSIDE our process even if
                      they get RCE.

Documented residual: a local Administrator can ``sc delete`` the
service or terminate both processes simultaneously. That's the ceiling
without a Protected-Process-Light status, which requires a WHQL-signed
binary. We document it; we don't pretend otherwise.
"""

from __future__ import annotations
