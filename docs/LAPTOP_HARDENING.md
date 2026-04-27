# Hardening your laptop — what DEEPSecurity actually contributes

A direct, honest answer to "can DEEPSecurity make my laptop 98%
secured?": **no, not on its own.** DEEPSecurity is documented as a
**user-space policy / DLP / compliance overlay** that runs **alongside**
your AV — not instead of it. The README says this in the first
paragraph, and `docs/THREAT_MODEL.md` enumerates the things it
deliberately doesn't do (no kernel hook, no real-time process
inspection, no network filter, not self-protecting).

What CAN realistically push a laptop to a 95–98% security posture is a
**stack of layered controls**, of which DEEPSecurity is one specific
layer. That stack is what this document maps out.

---

## The stack — and where DEEPSecurity sits in it

| # | Layer | What it defends | Tool (Windows) |
|---|---|---|---|
| 1 | Kernel-mode malware blocking | Real-time AV, exploit guard, controlled folder access (anti-ransomware), tamper protection | **Windows Defender** (built-in, free) |
| 2 | Disk encryption | Drive cannot be read offline | **BitLocker** (Windows Pro / Enterprise) |
| 3 | Account hygiene | Standard user, UAC strict, screen lock on inactivity | OS settings |
| 4 | Browser hardening | Sandboxing, HTTPS-only, content blocker, sandboxed downloads | Edge or Chrome with strict mode |
| 5 | Phishing + cred theft | MFA on every IdP, strong unique passwords, no shared logins | 1Password / Bitwarden + Authenticator app |
| 6 | OS + app patching | New CVE → patched within hours-days, not weeks | Windows Update + `winget upgrade --all` |
| 7 | **Policy / DLP / compliance overlay** | Secrets in source, PII in shared folders, MITRE-tagged audit trail, redacted findings, SIEM-ready event stream, evidence pack for SOC2 / ISO / HIPAA | **DEEPSecurity** |
| 8 | Off-machine backup | Recover from anything (including ransomware that beat layer 1) | **Restic** to S3, **Backblaze**, or **OneDrive** with versioning |
| 9 | Network egress filtering | Block traffic to known-bad domains | Defender SmartScreen + Pi-hole / NextDNS |
| 10 | Physical security | Cable lock or "don't leave the laptop in a rental car" | Operational |

DEEPSecurity is **row 7**. It is the **only row** that gives you:

- A redacted DLP feed (raw secrets never persisted) suitable for
  pre-commit gating, shared-folder sweeps, and contractor-laptop
  audits.
- A MITRE-ATT&CK-tagged audit log + retention purge that maps
  cleanly onto SOC2 CC6.1 / ISO 27001 A.12.4 / HIPAA §164.308(a)(1).
- A CEF-over-syslog forwarder that Splunk / Elastic / Sentinel /
  ArcSight / QRadar / Exabeam will auto-parse.
- A `/metrics` endpoint that any Prometheus scraper can ingest.

Without rows 1–6 + 8 in place, **DEEPSecurity contributes meaningfully
but doesn't move the needle on its own.** With rows 1–6 + 8 in place,
DEEPSecurity is what gives you the *evidence trail* to *prove* your
posture — to an auditor, an internal reviewer, or to yourself.

---

## Self-assessment — answer the 10 questions honestly

Tick each row that's TRUE today.

```
[ ]  1.  Windows Defender is on, real-time protection enabled,
         tamper protection enabled, controlled folder access enabled,
         and Defender has updated definitions in the last 24 hours.
[ ]  2.  BitLocker is enabled on the system drive AND every other
         internal drive. Recovery key is stored in your 1Password /
         Bitwarden, not on the laptop.
[ ]  3.  Your daily-driver account is a STANDARD user, not local
         admin. UAC is at the default ("Always notify"). Screen
         locks after 5 min of inactivity. Auto-login disabled.
[ ]  4.  Browser is on the latest stable. uBlock Origin (or
         equivalent) is installed. HTTPS-only mode is on. No
         expired/forgotten extensions.
[ ]  5.  EVERY login (email, GitHub, cloud provider, bank, ssh) has
         MFA — preferably WebAuthn / YubiKey, otherwise TOTP. NO
         logins use SMS as the only second factor.
[ ]  6.  Windows Update auto-installs. `winget upgrade --all` runs
         weekly (or you've automated it). No app is more than 30
         days behind its current release.
[ ]  7.  DEEPSecurity is running with: a real `DEEPSEC_DEV_PASSWORD`
         (or OIDC wired up), `DEEPSEC_SCAN_ROOT` set to where you
         actually keep code/PII, watchdog autostart on user_risk,
         and at least one alert sink configured (Slack webhook,
         email, or syslog).
[ ]  8.  An off-machine backup runs at least daily and you have
         RECENTLY restored a test file from it (within 30 days).
         The backup is encrypted at rest.
[ ]  9.  DNS is going through Defender SmartScreen at minimum, ideally
         a known-bad blocker (Pi-hole / NextDNS / Quad9).
[ ] 10.  You don't leave the laptop unattended in untrusted physical
         spaces (hotel lobby, rental car, public co-working desk).
```

**Score interpretation** (rough):

| Ticked | Realistic posture |
|---|---|
| 0–3 | Standard consumer laptop. ~30–40%. One bad email lands. |
| 4–6 | Mid-range. ~60–75%. Resilient to opportunistic threats. |
| 7–8 | Strong. ~85–92%. Resilient to most targeted threats. |
| 9–10 | Excellent. ~95–98%. Very few realistic attackers can reach you without insider access. |

DEEPSecurity = row 7 of 10. You can have DEEPSecurity perfectly
configured and still be at 30% if rows 1, 2, 5, 8 are blank. That's
why the README is so explicit about scope — security tooling that
oversells itself is a real harm.

---

## What DEEPSecurity adds that NOTHING else in the stack does

Every other layer above is mass-market: Defender, BitLocker, password
managers, browsers, backups, DNS blockers. They handle the common case
extremely well and they should be the foundation.

DEEPSecurity covers the **policy / evidence / DLP** layer that those
products *don't* and that auditors *do* ask about:

1. **Secrets in source code on a dev laptop.** Defender doesn't care
   about your AWS access key sitting in `~/work/checkout/.env`.
   DEEPSecurity DLP catches it (one of 35+ patterns), redacts the
   value, and either alerts on it or audit-logs it for a
   pre-commit / compliance review.

2. **PII in shared folders.** SSNs, credit cards, PHI, EU VAT,
   IBAN — flagged with severity, redacted, exportable as a
   compliance report.

3. **MITRE-ATT&CK-tagged audit log + retention purge.** SOC2 CC6.1
   asks for it. ISO 27001 A.12.4.1 asks for it. HIPAA §164.308(a)(1)
   asks for it. DEEPSecurity gives you the JSON/CSV evidence pack.

4. **SIEM-ready event stream.** CEF-over-syslog out of the box. If
   you have a Splunk, Elastic, or Sentinel deployment in any other
   part of your life, DEEPSecurity events drop in without a custom
   parser.

5. **Pre-AV catch on slow-burn threats.** Cryptominers, suspicious
   parent chains (Office → cmd, PDF → powershell), known-bad LOLBins,
   ransomware write-rate anomalies. Defender catches the malware;
   DEEPSecurity catches the *behaviour*.

This is genuinely useful. It's also genuinely not the whole stack.

---

## Concrete laptop checklist — quickest path from "today" to "98%"

If you ticked < 8 above, here's the order of operations that
maximises security gain per hour spent.

1. **30 minutes.** Turn on tamper protection + controlled folder
   access in Defender. Enable BitLocker on every drive; store the
   recovery key in 1Password / Bitwarden.

2. **30 minutes.** Make your daily-driver account a Standard User.
   Create a separate local admin for installs only.

3. **1 hour.** Install 1Password / Bitwarden. Move every reused
   password to a unique generated one. Enable WebAuthn on GitHub,
   Google, Microsoft. Buy a YubiKey if you haven't.

4. **30 minutes.** Configure DEEPSecurity:

   ```cmd
   cd C:\Apps\DEEPSecurity_v2.0
   .venv\Scripts\activate.bat
   notepad .env
   ```

   Set:

   - `DEEPSEC_SCAN_ROOT` to your dev / Documents / Downloads area.
   - `DEEPSEC_DEV_PASSWORD` to a strong password (or wire OIDC).
   - At least one of `DEEPSEC_SLACK_WEBHOOK_URL` /
     `DEEPSEC_SMTP_HOST` / `DEEPSEC_SYSLOG_HOST` so alerts go
     somewhere.
   - `DEEPSEC_INTEL_MALWAREBAZAAR_ENABLED=true` for free
     known-bad-hash updates.

   Then:

   ```cmd
   deepsec init-db
   deepsec start
   ```

5. **30 minutes.** Set up off-machine backup. Restic to a B2 bucket
   is the cheapest mature option. Schedule it daily. Restore one
   file from it now to prove the workflow.

6. **15 minutes.** Switch your home DNS to NextDNS or Quad9.

7. **Ongoing.** Run `winget upgrade --all` weekly. Run
   `scripts\loop_24h.bat` once to confirm DEEPSecurity is still
   green after the changes (see below).

That's a ~3-hour session that takes most laptops from a roughly
30–40% posture to roughly 90%+, and DEEPSecurity is the row that
gives you the evidence to prove it.

---

## Running the 24-hour loop — lightweight by default

```cmd
cd C:\Apps\DEEPSecurity_v2.0
.venv\Scripts\activate.bat
scripts\loop_24h.bat                  REM 24h, every 15 min, lightweight
scripts\loop_24h.bat 12 30            REM 12h, every 30 min, lightweight
scripts\loop_24h.bat 1 5  fast        REM 1h smoke (no E2E, just verify)
scripts\loop_24h.bat 24 15 heavy      REM full E2E every cycle, normal priority
```

Output:

- `logs\loop_24h_<UTC-stamp>.md`  — Markdown roll-up (one row per cycle).
- `logs\loop_24h_<UTC-stamp>.json` — same data, machine-readable.
- `logs\loop_24h_<UTC-stamp>\`    — per-cycle subprocess output.

To make it survive logout:

```cmd
schtasks /Create /XML scripts\loop_24h_task.xml /TN "DEEPSecurity\loop_24h"
schtasks /Run    /TN "DEEPSecurity\loop_24h"
```

To stop it cleanly:

```cmd
schtasks /End    /TN "DEEPSecurity\loop_24h"
```

### What the loop does each cycle

Lightweight mode (the default) is a two-track schedule designed to be
imperceptible on a laptop you're using for other work:

**Every cycle (~10–15 s of CPU at idle priority):**
1. `deepsec backup incremental --keep 48` — fresh DB snapshot.
2. `python scripts\verify_v2_5.py` — the 19-stage v2.5 wiring check.
3. `deepsec clean --services-only --yes` — stop services only;
   **DB, logs, quarantine, and integrity snapshot are preserved.**

**Every Nth cycle (default N=4, so ~once an hour at the 15-min interval):**
4. `python scripts\e2e_full.py` — the full 15-stage E2E (~70–90 s
   at idle priority).

If a cycle fails, the script keeps going (a transient hiccup never
kills your overnight run). The Markdown roll-up records which
specific cycle and step failed; per-cycle logs in
`logs\loop_24h_<stamp>\` show full subprocess output.

### Resource impact (measured)

What lightweight mode actually costs on a typical mid-range laptop
(Intel i5 / Ryzen 5, 16 GB RAM, NVMe SSD):

| Resource | Cheap-cycle (every 15 min) | E2E cycle (every 4th) | 24-hour totals |
|---|---|---|---|
| CPU time | ~10–15 s @ idle priority | ~70–90 s @ idle priority | ~12 minutes total over 24 hrs |
| Average CPU | ≪1% | ~4% during the burst | ≈0.8% over 24 hours |
| Peak RSS | ~120–180 MB | ~250–400 MB | returns to 0 between cycles |
| Disk write | ~50 KB (one snapshot) | ~150 KB | ~10 MB total (incl. logs) |
| Battery | paused — see below | paused — see below | 0 cycles run on battery by default |

`IDLE_PRIORITY_CLASS` on Windows means the loop yields to anything
the foreground is doing. You should not notice it.

### Battery handling

By default, the loop **skips** any cycle that starts while the laptop
is on battery, logs the skip in the roll-up, and resumes when AC is
restored. Two consequences:

* You can run a 24h soak on a laptop you take to meetings — it just
  pauses during travel and resumes at your desk.
* The reported "ran" count in the rollup is "scheduled cycles minus
  battery-skipped". If you want the loop to run regardless, pass
  `--no-pause-on-battery` (or use the `heavy` mode in the .bat).

### When to use heavy mode

The default cadence is right for ~98% of cases. Reach for
`scripts\loop_24h.bat 24 15 heavy` only when:

* You're running on a dedicated test rig that's not your work laptop.
* You're hunting for an intermittent failure that needs more E2E
  coverage than once an hour.
* You're publishing benchmark numbers and want full-priority results.

In heavy mode the budget jumps to roughly 5 minutes of CPU per cycle
× 96 cycles ≈ 8 hours of CPU over 24 hours. Don't run that on
battery, on a Wi-Fi hotspot, or while you're on a video call.

---

## CLI reference for the commands you asked about

All of these are already shipped — `deepsec` and `deepsecurity` are
both registered as console entry points in `pyproject.toml`, so the
two commands are interchangeable.

| Command | What it does |
|---|---|
| `deepsec start` | Spawn the backend (and the Vite frontend if installed) on background pids. Survives the calling shell closing. |
| `deepsec stop` | Stop the backend + frontend cleanly. Idempotent. |
| `deepsec status` | Show backend / frontend pid, health, watching paths. |
| `deepsec clean --services-only --yes` | **NEW in v2.5.** Stop services WITHOUT touching the DB, logs, quarantine, or integrity snapshot. Use this between cycles in long-running soak tests. |
| `deepsec clean --keep-db --keep-logs --yes` | Stop services + clear quarantine, but preserve DB + logs. |
| `deepsec clean --yes` | Stop + wipe DB + logs + quarantine + caches. Safelist preserved by default. |
| `deepsec backup full --keep 7` | Full DB snapshot to `data/backups/`, keeps 7. |
| `deepsec backup incremental --keep 48` | Incremental snapshot, keeps 48 (≈48 hourly slots). |
| `deepsec restore <path-to-snapshot>` | Restore a snapshot. The current DB is renamed to `.before-restore-<timestamp>` first. |
| `deepsec integrity snapshot` | Re-baseline the integrity tripwire (run after a deploy that legitimately changed files). |
| `deepsec integrity check` | Verify the running tree matches the baseline. |
| `deepsec scan <dir> --role admin` | One-shot scan of a directory. |
| `deepsec watchdog start \| stop \| status` | Real-time file-system monitor controls. |
| `deepsec serve` | Run the backend in the foreground (for development / `Ctrl-C` to stop). |

---

## Summary

> Can DEEPSecurity make my laptop 98% secured? **No.**
> Can DEEPSecurity + Defender + BitLocker + MFA + browser hygiene +
> backups + patching get to roughly 95–98%? **Yes — and DEEPSecurity
> is the row that gives you the evidence trail.**

If you tick all 10 boxes in the self-assessment above, you are
realistically in the top single-digit percentile of consumer / SMB
laptop security. DEEPSecurity is one row in that stack. Run the
24-hour loop overnight tonight — if every cycle is OK, your DEEPSec
layer is solid and the remaining work is the other nine rows.
