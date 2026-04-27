# BEASTMODE v3.0 megaprompt — paste into a future Claude session

This file is a **single self-contained prompt** to hand to a fresh
Claude / Cowork session so it can pick up the v3.0 BEASTMODE work
without the entire conversation history. It includes the goal,
the architecture, the residual gaps with file paths, and the
verification protocol.

---

## How to use it

1. Open Cowork in `C:\Apps\DEEPSecurity_v2.0`.
2. Start a new conversation.
3. Paste the entire **`>>> MEGAPROMPT BELOW <<<`** block.
4. Claude will scope, plan, ship, and verify the next iteration.

---

## >>> MEGAPROMPT BELOW <<<

```
You are continuing work on DEEPSecurity v3.0 BEASTMODE — a user-space
policy / DLP / compliance overlay for Windows endpoints. The repo is
at C:\Apps\DEEPSecurity_v2.0. Read docs/BEASTMODE_v3.md first; it has
the design, the per-domain readiness targets, and the honest
ceiling-vs-mechanism mapping.

CURRENT STATE
-------------
- v3.0 alpha shipped: realtime/, firewall/, dns_sinkhole/, protection/,
  tls_proxy/, memory_scan/ — all AST-clean, prototype-grade.
- v2.5 baseline still 100% green: 19/19 verify, 16/16 e2e, 265 unit
  tests pass, all 6 P0 blockers closed.
- pyproject.toml is at 3.0.0a1 with new optional extras: edr,
  firewall, dns, tls-proxy, windows-edr.
- 30+ new DEEPSEC_* env vars in deepsecurity/config.py (search for
  "v3.0 BEASTMODE").

YOUR JOB
--------
Move the v3.0 modules from "prototype-grade ~74%" to "production
~90%" by closing these gaps in priority order:

  1. CLI wiring. The new modules have no `deepsec` subcommands yet.
     Add: `deepsec realtime start|stop|status`, `deepsec firewall
     add|remove|list`, `deepsec dns start|stop|update-blocklist`,
     `deepsec protection install-twin|uninstall-twin`,
     `deepsec tls install-ca|start|stop|uninstall-ca`,
     `deepsec memory scan <pid>`. Wire each subcommand to the
     existing module's start/stop helpers.

  2. Service entry-point. `deepsec service install` exists in
     deepsecurity/protection/service.py but pyproject.toml's
     [project.scripts] doesn't yet expose it. Add:
        deepsec-service = "deepsecurity.protection.service:_service_main"

  3. Tests for the new modules. Use fakeredis-style mocks where
     possible. tests/test_correlator.py is the highest-value
     target — every rule in deepsecurity/realtime/correlator.py
     needs at least one positive + one negative.

  4. Sysmon config. Ship a recommended XML at
     deploy/sysmon-config.xml (use SwiftOnSecurity's modular config
     as a starting point — Apache 2.0 licensed; copy + adapt).

  5. verify_v3_beastmode.py harness. New script under scripts/
     that exercises every v3 module: imports, ETW availability,
     Sysmon channel exists, WinDivert driver loaded, DNS bind
     succeeds, mitigation policies apply, memory scan can read
     own pid. Output a Markdown report alongside verify_v2_5's.

  6. README + LAPTOP_HARDENING.md updates. Reference the new
     features. Update the strength matrix (it's already in
     docs/BEASTMODE_v3.md — copy the table into LAPTOP_HARDENING).

  7. CHANGELOG.md v3.0.0a1 entry with the same shape as the v2.5
     entry — what changed, where, what's still residual.

CONSTRAINTS
-----------
- Honest scope. No claims that DEEPSecurity blocks malware at the
  kernel — the doc is explicit that Sysmon does that and we sit on
  top. Same for "98% laptop secured" — that's a stack number, not a
  DEEPSecurity number.
- Don't break v2.5 tests. 265 must still pass. Re-run
  scripts\verify_v2_5.py + scripts\e2e_full.py after every change.
- Cross-platform fallback. Every new Windows-specific path must
  no-op cleanly on Linux/macOS so the test suite stays green on
  GitHub Actions ubuntu-latest.
- AST-clean minimum bar. Run `ruff format && ruff check` before
  declaring done.
- Lightweight default. The 24h soak loop must still run with <1%
  average CPU.

VERIFICATION
------------
After every chunk of work:
    cd C:\Apps\DEEPSecurity_v2.0
    .venv\Scripts\activate.bat
    ruff format deepsecurity tests scripts
    ruff check deepsecurity tests scripts
    mypy deepsecurity
    pytest -m "not slow" -q
    python scripts\verify_v2_5.py
    python scripts\verify_v3_beastmode.py     # new in this iteration
    python scripts\e2e_full.py

All seven must be green. Anything red gets fixed before the next
chunk starts.

SCOPE LIMITS
------------
DO NOT in this iteration:
  - Try to write a kernel driver. Sysmon is our kernel layer.
  - Try to ship Microsoft-signed binaries. We're userspace.
  - Try to bypass cert-pinning in TLS inspection. Document the
    bypass instead.
  - Add new DLP patterns without a Luhn-style validator function
    (they cause false-positive floods).

DELIVERABLES
------------
- All new code AST-clean and committed.
- New tests covering the new modules.
- Updated CHANGELOG.md.
- A pass result for every check in the VERIFICATION block.
- A short run-summary at the end: what shipped, what didn't,
  what's still residual for the next session.

Begin by reading docs/BEASTMODE_v3.md, the existing CLI in
deepsecurity/cli.py, and one of the v3 modules
(deepsecurity/realtime/correlator.py is the most self-contained).
Then propose the order you'll work in, and start.
```

## <<< END MEGAPROMPT >>>

---

## Why this works as a single-shot prompt

- **Self-contained.** A fresh Claude session needs only this text plus
  the repo to make progress. No conversation history required.
- **Honest about ceiling.** Tells the next agent that kernel work is
  not in scope, which prevents weeks of wasted effort.
- **Verification baked in.** The seven green-checks act as the
  acceptance criteria — the agent doesn't get to declare done without
  them.
- **Priority-ordered.** Items 1–7 are listed in the order that
  unblocks the most downstream work.
- **Linked to the design doc.** Every cross-reference (`docs/`
  `realtime/`, `firewall/`) is a real path the agent can follow.
