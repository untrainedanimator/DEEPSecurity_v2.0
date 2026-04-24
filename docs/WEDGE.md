# DEEPSecurity Wedge — who we're for and what we're not

This document is the **decision filter** for every feature, every piece of
copy, every commit. Before adding something, check it against this file.
If it makes DEEPSecurity better at the wedge, ship it. If it doesn't, put
it in a separate product or don't build it at all.

> If you find yourself thinking "but this could maybe also serve
> <different-audience>" — stop. Having one buyer is a product. Having
> three buyers you're "maybe" serving is a backlog with no direction.

---

## The wedge (one sentence)

**DEEPSecurity is a DLP, policy, and compliance-audit overlay for
engineering laptops and small-team file servers — running alongside
Windows Defender, not replacing it.**

## The three audiences, ordered

### 1. Engineering teams at 10–100 person companies going through SOC2 / ISO 27001 / HIPAA

They have:

- laptops that handle customer data, API keys, and PII in local git repos
- Microsoft Defender (or similar) already installed and running
- an auditor asking "how do you prevent secrets from leaking to dev
  machines?" and "show me evidence that PII isn't in unencrypted local
  folders"
- nobody whose job title is "security engineer" — usually a founding eng
  wearing a compliance hat

They don't have:

- CrowdStrike / SentinelOne budget ($60–150/endpoint/yr × 50 laptops)
- a SOC
- time to read 400-page vendor manuals
- political appetite to force a new AV onto every dev's machine

**What they'll pay for:**

- "I ran DEEPSecurity's DLP sweep across every engineer's `~/code` folder
  and here's the CSV of findings, auditor. We remediated these 12, here's
  the evidence log."
- Policy enforcement they can explain to both engineers and auditors:
  regex + parent-chain + MITRE tag + redacted preview. No black box.
- An agent fleet they can install without involving IT: `pip install`,
  one env var, one enrolment token.

### 2. Shared file servers in small-to-mid companies

Think: the `//fileserver/finance` share, the `\\nas\hr` share, the
Sharepoint-alternative someone set up in 2019 and nobody owns. These
have:

- years of accumulated files that no AV has ever looked at for DLP content
- SSNs, tax docs, contracts with bank info, exported CRM dumps, all in cleartext
- turnover: the people who put the files there are long gone

**What they'll pay for:** a one-time and recurring DLP sweep with a CSV
report of exactly which files contain which secrets/PII, stored redacted
so they can share the report internally without re-leaking what they
just found. Plus a monthly recurring "this changed since last month"
diff.

### 3. Contractor / BYOD fleets where enterprise AV can't be installed

Legal, consulting, agencies. They hire contractors. Contractors use
their own laptops. The firm can't force CrowdStrike onto a contractor's
personal MacBook, but they *can* ask them to run a lightweight Python
agent during the engagement that proves no source code or client data is
being written to unencrypted Dropbox folders.

**What they'll pay for:** a time-bounded DLP + audit-log agent that can
be uninstalled cleanly at engagement end, with a report both sides sign
off on.

---

## What the wedge rules IN

Every one of these makes DEEPSecurity better at the wedge:

- **DLP patterns.** More patterns, better patterns, regional variants
  (UK NINO, India Aadhaar, EU VAT). This is our core competence.
- **Observe-before-enforce mode** for new DLP patterns. Ship a pattern
  as `observe`, let operators see false positives for a week, promote to
  `enforce` when confident.
- **Compliance report templates.** "SOC2 CC6.1 — access controls
  evidence pack", "ISO 27001 A.8.1 — asset inventory extract". Named
  and mapped, not just "here's some JSON."
- **SIEM forwarding.** Syslog/CEF to Splunk, Elastic, Sentinel.
  DEEPSecurity as a signal source.
- **Audit-friendly UX.** Reason-required delete. Session rollback.
  Safelist with notes and history. Everything Defender doesn't have.
- **Explainable detections.** Every finding shows: which pattern, the
  redacted match, the parent chain, the MITRE tag, the confidence. No
  "trust the ML model."
- **Per-path policy.** Watch `Downloads` strictly, watch `node_modules`
  loosely, don't scan `data/` at all — configured, not hardcoded.
- **Repository-aware scanning.** Recognize `.git/`, respect
  `.gitignore`, skip `node_modules/`, skip `venv/`. The tool should
  already understand the layout of a dev laptop.
- **Agent fleet management.** Enrolment tokens, heartbeats, remote
  commands — already built. Deepen: per-agent policy, drift alerts.
- **Tamper-evidence.** Integrity snapshot of the DEEPSecurity binaries
  so the operator can detect if someone edited them on disk. Already
  shipped; keep polishing.

## What the wedge rules OUT

Every one of these is out of scope — no matter how cool they sound:

- **Kernel driver.** Windows minifilter, ETW-TI, WFP callouts. That's
  Option C (see main README). Not this product.
- **Network packet capture.** Npcap, raw sockets, WFP. We can enumerate
  connections and match IPs against a reputation feed. That's the
  ceiling.
- **DNS / TLS interception.** Needs a local proxy + root CA
  installation. Hostile to the "runs alongside your AV without causing
  trouble" positioning.
- **Memory scanning.** Reading another process's memory is a kernel or
  debugger-level capability. No.
- **Self-protection (un-killable agent).** Requires signed kernel driver
  + Protected Process Light, which Microsoft only grants to AV vendors
  in their MAPP programme. We're deliberately killable.
- **Replacing Windows Defender / MS Defender for Endpoint.** Hard no.
  We complement.
- **Sandboxing / detonation.** That's a different product category
  (Cuckoo, ANY.RUN, Hatching Triage).
- **Competing with CrowdStrike / SentinelOne.** We will lose on every
  metric except price and inspectability. Don't play that game.

## The one-question filter

When considering a feature, ask:

> Does this help a SOC2-auditing engineering manager, a file-server
> owner, or a contractor-managing firm do their job? If yes, how?

If the answer is specific and honest, ship it. If the answer is "well,
security is good for everyone" — that's a red flag that the feature
belongs to someone else's product.

## What this means for the near-term roadmap

Inside the wedge:

1. **SIEM forwarder (Syslog/CEF)** — turns every detection into a
   signal other tools can consume. Ships this sprint.
2. **Watchdog scope presets** — "user-risk paths" (Downloads + Desktop +
   Documents + Outlook cache + %TEMP%). One click, realistic default.
3. **ETW process subscription** — near-real-time process events on
   Windows without a kernel driver. Big upgrade to the Process panel.
4. **Compliance report templates** — SOC2 / ISO 27001 / HIPAA named
   packs.
5. **DLP pattern library expansion** — source-code API keys
   (GitHub/Stripe/Azure/OpenAI/Anthropic), regional PII.
6. **Observe-mode for DLP rules** — ship new rules in shadow before
   enforcement.
7. **Repository-aware scanning** — respect `.gitignore`, skip
   `node_modules` / `venv` by default.

Outside the wedge (shelved):

- Kernel minifilter
- Packet capture
- DNS inspection
- Memory forensics
- Anti-tamper / un-killable

## How to use this doc

- **Before a new feature:** read the two lists above. Place your
  feature in one.
- **Before a marketing claim:** check it against "what it is NOT" in
  the README. If you can't back it, don't claim it.
- **When someone says "can DEEPSecurity also do X":** open this file,
  check the lists, answer yes or no. Say no a lot more than yes.

The wedge narrows over time, not widens. If in six months we're
confident our three audiences are happy, we consider extending. Not
before.
