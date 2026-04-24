# Coverage model — how CrowdStrike does it, how DEEPSecurity inverts it

A real-time endpoint scanner has exactly one hard question: **given
millions of file events per day, which ones do we actually look at?**
The answer determines your CPU bill, your false-positive rate, your
detection coverage, and whether users disable your agent out of
frustration. This document explains how the market-leading EDR
(CrowdStrike) resolves that question, where DEEPSecurity deliberately
takes a different shape, and how we approximate the CrowdStrike UX
inside our user-space ceiling.

## How CrowdStrike does it

The short version: **CrowdStrike doesn't let the operator pick what to
watch. The agent watches everything by default, and operators manage
the noise via exclusions and suppression rules, not by selecting
paths.** The entire operating model depends on that inversion.

### The stack, bottom up

**1. Kernel driver (`CSAgent.sys`).** Signed Microsoft-approved
minifilter + ETW-TI consumer + WFP callout. It receives every file
operation, every process creation, every network connection, every
registry write, every DLL load, every named-pipe connection, every
image load — *from the kernel*, not from polling user-space APIs. Cost
per event is nanoseconds; the driver can see tens of thousands of
events per second without the endpoint noticing.

**2. In-kernel pre-filter.** A tiny, fast first pass decides whether
the event is even interesting. Default: everything except
a Microsoft-signed list of "this binary and this path, this ETW
provider, this known-clean process ancestry." Events that don't pass
the pre-filter are dropped at the driver level — never sent up to
user-space.

**3. User-space agent (`CSFalconService.exe`).** Collects the events
the kernel let through, enriches them (hashes, reputation lookups,
ancestry), batches, compresses, and ships them to the Falcon cloud.

**4. Falcon cloud.** This is where the *real* detection happens.
Hundreds of TB/day of endpoint events cross-correlated across millions
of customer endpoints. The cloud decides what's malicious; the agent
is mostly a sensor. Cloud pushes:
- detection rules (Indicators of Attack)
- new hash blocklists
- **adaptive exclusions** — if a path/binary pair produces a million
  benign events across the fleet, the cloud tells every agent to stop
  forwarding it.

**5. Management console.** The operator writes policy once (per
"policy group") and it's distributed to thousands of endpoints:
"exclude `C:\Program Files\OurApp\**` for production-team policy",
"require human approval before killing lsass.exe on domain controllers",
etc.

### Why this inverts the "pick what to watch" model

Because the kernel driver is **cheap per event**, it's free to watch
everything. Cost is in the upload bandwidth and cloud storage, both of
which scale with the customer's subscription. The operator's cognitive
load is moved from *"what should we monitor?"* (hard; requires threat
modelling) to *"what should we ignore?"* (easy; you know which of your
own apps are safe).

### Hard truths about this model

- It **requires a kernel driver**. Everything hangs on that.
- It **requires a cloud**. The agent alone is not the product. The
  cloud's cross-customer intelligence is what makes it smarter every
  day.
- It **costs $60–150/endpoint/year**. Kernel engineering,
  certifications, and cloud ops are expensive.
- It **requires continuous ML ops and threat-intel content**. A
  competitor without a dedicated detection-content team cannot catch
  up.
- It's **opaque**. You trust CrowdStrike's cloud to make the right
  call. You don't see the rules, the model weights, or the raw
  telemetry from other customers that informed your detection.

## How DEEPSecurity can't copy this

Every technical prerequisite — kernel driver, signed certificate,
Microsoft partnership, cross-customer cloud, detection-content team —
is outside the scope of this project. The honest ceiling is in
[THREAT_MODEL.md](./THREAT_MODEL.md). Nothing we build should pretend
otherwise.

But we can copy the *shape* of the operating model. That's the bit
that actually makes CrowdStrike feel good to use: operators don't
spend their day tuning a list of watched paths, they spend it
reviewing detections.

## How DEEPSecurity inverts the model inside the user-space ceiling

The shape we're aiming for:

> **Default-deny at the directory level, default-allow via exclusions
> at the file / glob level, operator time spent on triage not
> configuration.**

Here's how each layer lands in DEEPSecurity today and what fills the
gap going forward.

### 1. Ingestion — watch-everything-by-default

**What we can't do:** kernel-level subscription to every file event on
the machine. User-space `watchdog` only sees paths we explicitly pass
to `Observer.schedule(...)`.

**What we do instead:** ship a first-class "user-risk" preset
(`docs/WEDGE.md`) that covers Downloads, Desktop, Documents, Outlook
cache, `%TEMP%` — the five or six folders where malware actually
lands on a typical workstation. Not all events, but the ones where the
detection value is highest per CPU cycle.

**What's coming:** an ETW process-creation subscriber (`pywintrace`)
that gets *near*-kernel visibility on process starts *without* a
driver. Windows exposes this event stream to user-space by design.
Same for 4688/4624/4672 event-log subscription for login and
privilege-escalation visibility. These are the closest we can get to
the CrowdStrike ingestion shape on the right side of the kernel
boundary.

### 2. Exclusions — the operator's control surface

**CrowdStrike's model:** policy groups in the console. Per-path,
per-binary, per-command-line patterns. Some adaptive (cloud-learned),
some manual.

**DEEPSecurity today:**
- `DEEPSEC_WATCH_EXCLUDE_GLOBS` (just added) — glob patterns always
  skipped, even inside a watched directory. Defaults cover
  `node_modules`, `.venv`, IDE caches, browser caches, `*.pyc`,
  `Thumbs.db`, etc. Operators can append their own.
- `safelist_dir` — per-file exclusions created by operator action
  ("safelist this file") with an audit trail.
- `DEEPSEC_USER_RISK_PATHS` — the "user risk" preset itself is now
  overridable if your shop has a different idea of where to watch.
- DEEPSecurity's own state directories are always excluded
  (`data/`, `logs/`, `quarantine/`, etc.) so the watcher can't chase
  its own tail.

**What's coming (shelved, roadmap):**
- **Adaptive exclusions.** After N days of running, report the top 20
  paths producing high event volume with zero detections. Prompt the
  operator: "exclude these?" One click adds them to
  `DEEPSEC_WATCH_EXCLUDE_GLOBS`. This is the manual-ML version of
  CrowdStrike's cloud-learned exclusions.
- **Per-agent policy push.** The SaaS + agent architecture is already
  in place (`deepsecurity/agent/`). Adding "exclusion policy" to the
  command stream means one central source pushes a consistent
  exclusion set to every enrolled agent, just like a Falcon policy
  group.

### 3. Triage — where operators spend their time

**CrowdStrike's model:** detections arrive in a console with full
process ancestry, command lines, file hashes, MITRE tags, network
connections. Operators click through, approve/dismiss, write
suppression rules from dismissals.

**DEEPSecurity today:**
- Every detection already has MITRE ATT&CK tags, parent chain, file
  hash, redacted preview, explainable reasons — no black box.
- Quarantine has reason-required delete and session-rollback.
- Audit log is structured JSON, ready for SIEM forwarding.
- As of this release: CEF-over-syslog sink for Splunk / Sentinel /
  Elastic / ArcSight / QRadar / Exabeam consumption, so detections
  land directly in whatever the security team already uses for
  triage.

**What's coming:**
- **One-click "suppress this pattern."** When an operator dismisses a
  detection, offer to add the file path / hash / parent command line
  to a suppression rule, written to disk as a named rule with a
  timestamp and a note. This turns triage into policy refinement,
  which is the flywheel that makes mature tools feel good.
- **Noise report.** Weekly rollup: top 10 noisiest paths, top 10
  noisiest file types, detections per 1K events. The operator's job
  becomes "read the noise report once a week" rather than "tune paths
  daily."

### 4. Response — keep it conservative

**CrowdStrike's model:** high-confidence detections autonomously kill
processes, isolate the endpoint from the network, quarantine files,
and alert the SOC. Low-confidence items raise a ticket.

**DEEPSecurity today:**
- Auto-quarantine on signature hit (high confidence).
- Optional auto-kill for known-bad process names
  (`DEEPSEC_AUTO_KILL_KNOWN_BAD`) — off by default.
- Audit/quarantine on DLP / entropy / suspicious parent chain.
- No network isolation (needs kernel).
- No credential revocation (needs IdP integration).

**What we won't add:** autonomous response we can't back with kernel
confidence. A user-space tool that auto-kills processes on heuristic
confidence will eventually take out `lsass.exe` or `explorer.exe` on
someone's machine and get uninstalled. Our auto-response surface is
deliberately narrow.

### 5. Fleet policy

This is where DEEPSecurity's SaaS architecture is actually most
CrowdStrike-shaped and most under-exploited.

The agent enrolment + command-queue path (`deepsecurity/agent/`,
`deepsecurity/api/agents.py`) is the same pattern Falcon uses for
policy distribution. We already have:
- Enrolment tokens
- Per-agent API keys
- A `commands` queue the agent polls
- Heartbeats
- Per-agent labels

What's missing is a **policy document** — a signed JSON blob
containing watch scopes, exclusion globs, DLP pattern set,
signature-file URL, auto-kill posture. Every agent fetches the
policy on heartbeat, applies diffs. Operators edit policy centrally,
the fleet converges.

This is the biggest single lever for making DEEPSecurity feel like
CrowdStrike in a multi-endpoint deployment. It's a half-day's work
and a meaningful feature separator from the many "single-machine
scanner" tools in our space.

## Side-by-side

| Dimension | CrowdStrike | DEEPSecurity today | DEEPSecurity planned |
|---|---|---|---|
| Event source | Kernel driver + ETW-TI + WFP | `watchdog` + polling | ETW user-space + `watchdog` + polling |
| Event volume | Every file/process/network/registry op | Only watched paths | Same + ETW process stream |
| Coverage model | Watch-everything, exclude by policy | Watch scoped paths, default exclusion globs | Same + per-agent policy push |
| Latency | µs (kernel callback) | 10–100ms (user-space) | 10–100ms (no kernel path available) |
| Exclusions | Manual + cloud-learned adaptive | Manual (globs) + default-list | Manual + "suggest from noise report" |
| Response | Autonomous kill / isolate / revoke | Quarantine + optional kill | Same — conservative by design |
| Fleet policy | Falcon cloud policy groups | Agent enrolment + command queue | Policy document + agent diff apply |
| Self-protection | PPL + signed kernel driver | None (killable) | None — deliberate |
| Detection content | Dedicated threat-intel team | Curated MITRE rules + YARA | Same + community rule pack |
| Cost | $60–150/endpoint/year | Free / self-hosted | Free / self-hosted |
| Transparency | Closed cloud, opaque rules | ~8K lines of inspectable Python | Same |

## Our honest win

DEEPSecurity cannot win the "real-time kernel coverage" race. That
race was decided ten years ago and we're not funded to enter it.

DEEPSecurity *can* win:

- **Transparency.** Every rule, every match, every exclusion is
  readable Python. No cloud, no black box, no vendor lock-in. Small
  companies doing SOC2 love this because auditors can read the code.
- **DLP depth.** CrowdStrike has the light version of this; specialist
  DLP tools (Nightfall, Varonis) have the heavy version. We sit in the
  middle at a reasonable price and with MITRE-tagged output.
- **Operator UX for triage.** Reason-required delete, session
  rollback, explainable detections, per-finding safelist with notes.
  These are details enterprise EDR vendors never invested in because
  they were busy winning on kernel access.
- **Per-agent fleet policy without a SaaS subscription.** Once we
  ship the policy document, any operator can run a 10-endpoint
  deployment with central policy for $0/endpoint/year. That's a real
  wedge against the $60/endpoint floor.

## What ships next in this lane

In order of shipping effort and marginal value:

1. **Adaptive exclusion suggestions** — ~1 day. Report top-N noisy
   paths, let operator one-click add to `WATCH_EXCLUDE_GLOBS`.
2. **Agent policy document** — ~2 days. JSON schema, signed via
   existing API key, agent applies on heartbeat.
3. **ETW process-creation subscription** — ~2 days. `pywintrace` or
   `wtrace` consumer, dashboard "live process events" feed.
4. **Suppression rules from dismissals** — ~1 day. "This is a false
   positive" button in the DLP / detections panels, writes a named
   rule to disk.
5. **Weekly noise report** — ~0.5 day. Email/Slack/dashboard rollup
   of event volume vs detection count per path.

Each of these makes DEEPSecurity more CrowdStrike-shaped without
crossing the kernel boundary. None of them take more than two
engineer-days. Stack five of them up and the gap narrows materially —
not on kernel visibility, which is a lost battle, but on the
*operating model*, which is what operators actually experience.
