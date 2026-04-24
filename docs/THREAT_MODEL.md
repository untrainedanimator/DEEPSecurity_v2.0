# Threat model

A small, honest threat model — what we defend, who we defend against, and
what we explicitly don't try to cover.

## Assets

1. **The user's filesystem.** The scanner reads bytes and can move files.
   A bug here has real blast radius.
2. **The audit trail.** Downstream accountability depends on it.
3. **The credentials** used to authenticate operators and downstream sinks.
4. **The scan results DB.** Contains file paths and hashes that are
   themselves sensitive (tells an attacker what you have and where).

## Actors

| Actor | Capability | Our stance |
|---|---|---|
| Unauthenticated network caller | Reach the HTTP port | 401 on every protected endpoint; rate-limited; security-headers applied |
| Authenticated analyst | Read status, results, audit | Allowed; still rate-limited; every action audit-logged |
| Authenticated security role | Start/cancel scans, restore quarantine | Allowed; path-checked against `scan_root` |
| Authenticated admin | Permanent-delete quarantine, purge retention, update feeds | Allowed; requires a `reason` string on destructive ops |
| Local host user | Read `.env`, the signature file, the quarantine copies | Out of scope — file-system-level access is assumed |
| Supply-chain attacker | Push a malicious wheel into our deps | Pinned versions; `pip-audit` in CI; gitleaks in CI |

## Attack surfaces and how we cover them

### HTTP API
- JWT required on everything except `/healthz`, `/readyz`, `/metrics`, `/api/auth/login`.
- Role check via `@require_role(...)`. No fallback identity.
- `resolve_under_root()` rejects any path that isn't inside `scan_root`.
- CORS limited to an explicit origin list; `*` is refused at config time.
- Security headers on every response (CSP, HSTS, X-Frame-Options, etc.).
- Sliding-window rate limit (per-user for authenticated, per-IP for anonymous).
- Request size capped at `DEEPSEC_MAX_REQUEST_BYTES`.

### Filesystem
- Scanner walks `scan_root` and skips symlinks that escape it.
- Quarantine is always a **copy**. Originals are never auto-deleted.
- Permanent delete requires admin + reason + audit entry.
- Watchdog ignores the quarantine, safelist, and deleted dirs to avoid loops.

### Credentials
- All secrets in env; validated at startup; placeholders rejected.
- JWTs short-lived (default 60 min).
- The dev-user password bootstrap is explicit and documented as a seam.

### Data
- DLP scans text-ish files for secrets/PII and alerts on critical hits.
- Findings are stored *redacted* — raw secrets never touch the DB.
- Retention purge deletes old rows on schedule.

## User-space vs kernel — what this tool can and cannot see

DEEPSecurity is a **user-space** scanner. That word matters. Here's what it
means concretely:

| Capability | User-space (us) | Kernel / EDR (CrowdStrike, SentinelOne, MDE, …) |
|---|---|---|
| Hash a file on disk | ✓ | ✓ |
| YARA rules on a file | ✓ | ✓ |
| Regex DLP on text content | ✓ | ✓ |
| Watch file create/modify (folders you can read) | ✓ | ✓ |
| Watch file create/modify (system-protected folders) | Only if run as admin/root | ✓ |
| Hook every file `open()` at the kernel | ✗ | ✓ |
| See process creation / termination system-wide | via `psutil` polling | ✓ (event-driven) |
| See DLL / shared-object loads | ✗ | ✓ |
| See network syscalls | ✗ | ✓ |
| Scan process memory | ✗ | ✓ |
| Detect in-memory-only (fileless) malware | ✗ | ✓ |
| Block a process at exec time | ✗ | ✓ |
| Survive tampering from a privileged attacker | ✗ | ✓ (tamper protection) |

We can do a lot of real work in user-space: signature + YARA + entropy + DLP
on any file we can read, real-time folder watching, running-process
inspection via `psutil`, open-port visibility, outbound alerting to your
SIEM. We don't fake the rest. If you need kernel-level EDR, buy an EDR —
this tool is meant to run alongside it, not replace it.

## Explicit non-goals

- **Not an EDR.** See the table above.
- **Not a network IDS.** We don't sniff traffic or inspect flows.
- **Not a SOAR.** Alerts fire outbound; remediation playbooks are your job.
- **Not an anti-sandboxing engine.** Known-bad hashes and YARA catch common
  payloads; they won't defeat a determined packer.
- **Not HIPAA/PCI certified by default.** The compliance module emits the
  evidence an auditor expects; the certification itself is a process.

## What the user's checklist requires that still lives outside this tool

| Checklist need | Where it lives |
|---|---|
| Network inspection | Firewall / NDR / Zeek |
| Cloud posture | CSPM (Prisma / Wiz / Orca) |
| User behaviour analytics | UEBA inside SIEM |
| SOAR playbooks | Tines / Palo Alto XSOAR / Torq |
| Identity provider | Okta / Entra / Keycloak (swap our dev-user path) |
| Full email gateway DLP | Proofpoint / Mimecast |
| Endpoint behavioural detection | CrowdStrike / SentinelOne / MDE |

DEEPSecurity plays alongside those via the hooks we already expose:
`/metrics` (Prometheus), syslog sink (SIEM), Slack / webhook (SOAR triggers),
`/api/intel/update` (feed-driven detection refresh).
