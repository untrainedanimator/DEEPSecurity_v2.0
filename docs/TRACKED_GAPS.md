# Tracked gaps and accepted risks

This document is the canonical home for **known limitations** that are
not bugs — they are deliberate ceilings of the user-space, no-kernel-
hook architecture, or items that are scheduled but not yet shipped. Each
entry has an ID, the residual risk, the rationale for accepting it now,
and (where applicable) a target version for closure.

If a redteam exercise marks a scenario `KNOWN-CEILING` or
`KNOWN-MISSING`, it should map back to one of these IDs. New ceilings
discovered in subsequent redteam runs are added here, not buried in an
E2E log.

---

## CEILING — fundamental architectural limits

These are properties of the "user-space overlay alongside AV" design.
Closing them would require a different product (signed kernel driver,
EDR-class behavioural engine). We accept them and document them.

### G-CEIL-01 — DEEPSecurity is not self-protecting

**Risk**: An admin or a process running with the same UID as the
DEEPSecurity service can `taskkill` it.
**Rationale**: We do not ship a signed kernel driver. The trade-off is
deliberate — see `docs/THREAT_MODEL.md` § "What this is NOT".
**Target**: not closing in v2.x. If self-protection is required, layer
a kernel-mode AV (Defender, CrowdStrike) underneath.

### G-CEIL-02 — Process & network telemetry is polled, not streamed

**Risk**: Sub-second behavioural events (process starts, connect()
events) can be missed if they live shorter than the polling interval.
**Rationale**: `psutil` is the cross-platform path; no kernel hook.
**Target**: not closing in v2.x.

### G-CEIL-03 — Base64 / encoded payloads in DLP

**Risk**: A secret base64-encoded inside an attachment is not detected
by the regex layer.
**Rationale**: Recursive base64 decoding is non-trivial to do safely
(exponential expansion, false positives). Covered separately by
filename heuristics; alerts on `*.b64`/`*.enc` files.
**Target**: v2.6 — add an opt-in base64 unwrap pass for files <16 KiB
(`DEEPSEC_DLP_DEEP_DECODE=true`).

### G-CEIL-04 — Watchdog exclude-globs can be dropped by attacker control

**Risk**: A malicious process that can write to the OS environment can
push `DEEPSEC_WATCH_EXCLUDE_GLOBS=**` and silence the realtime monitor.
**Rationale**: Anything with write access to the deployment env can
already break the agent.
**Target**: v2.6 — pin exclude-globs from the SaaS policy fetch
(`AgentPolicy.exclusion_globs`), refuse local override when fleet
policy is configured.

---

## MISSING — scheduled but not yet shipped

### G-MISS-05 — Database wipe detection

**Risk**: An attacker who deletes `data/deepscan.db` removes the
audit trail.
**Rationale**: Audit-log replication is on the SaaS roadmap; for
single-node deployments today we recommend backing the DB up to S3
or equivalent (see `docs/BACKUP_RESTORE.md`).
**Target**: v2.6 — replicate audit_log inserts to a CEF/syslog sink
with deduplication, so the source-of-truth is the receiver.

### G-MISS-06 — Browser-extension privacy-sensitive patterns

**Risk**: Browser session-cookie strings, OAuth refresh tokens stored
in browser local storage, are not specifically patterned.
**Rationale**: These are ephemeral and high-volume; would need
careful tuning to avoid noise.
**Target**: v2.6 (observe-tier patterns).

---

## RESOLVED in v2.5.0

Items previously listed as KNOWN-CEILING/MISSING and now closed:

- **DLP missing `credit_card` pattern** — added in v2.5.0
  (`deepsecurity.dlp.PATTERNS["credit_card"]`) with Luhn validation
  and brand-aware prefixes (Visa, MC, Amex, Discover, JCB, Diners).
  Severity: `high`.
- **No real IdP** — added generic OIDC blueprint
  (`deepsecurity/api/oidc.py`) in v2.5.0. Production deployments now
  refuse the env-driven dev login.
- **Single-instance assumptions** — added Redis-backed state backend
  (`deepsecurity/state_backend.py`) in v2.5.0. Multi-replica
  deployments share rate-limit budgets and the scan lease.
- **CI mypy & pip-audit advisory** — flipped to fail-fast in
  `.github/workflows/ci.yml` in v2.5.0.
- **No container scanning / SBOM** — Trivy + Syft (CycloneDX) wired
  into `ci.yml` and `release.yml` in v2.5.0.
- **No DB migrations** — Alembic wired in (see `migrations/` and
  `alembic.ini`) in v2.5.0.
- **Watchdog autostart-during-pytest race** — fixed in v2.5.0 by
  unconditionally skipping autostart when `DEEPSEC_ENV=test`.

---

## How to add an entry

1. Pick the next free ID (`G-CEIL-NN` or `G-MISS-NN`).
2. State the risk in one sentence.
3. State the rationale for accepting it now in one sentence.
4. Pin a target version, or write "not closing".
5. If a redteam scenario maps to it, reference the scenario ID.
