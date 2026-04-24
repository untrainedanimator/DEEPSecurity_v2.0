# Compliance

What DEEPSecurity gives you toward common audit asks, and what still
needs your organisation to wrap around it.

## GDPR (EU / UK)

| Requirement | What DEEPSecurity provides |
|---|---|
| Art. 5(1)(f) — integrity and confidentiality | Scanner detections + quarantine, audit trail on every action |
| Art. 25 — data protection by design | Redacted DLP previews (raw secrets never persisted), refuse-to-boot on wildcard CORS, path traversal blocked |
| Art. 30 — records of processing | `AuditLog` table + `/api/compliance/audit.csv` export |
| Art. 32 — security of processing | TLS-ready (behind your reverse proxy), JWT auth, role gating, rate limiting, request-size cap |
| Art. 33 — breach notification | Alerting bus → Slack / webhook / syslog / email on detection |
| Art. 17 / 21 — erasure / restriction | `/api/compliance/purge` enforces retention; manual purge of a file's scan history is straightforward via the `ScanResult` table |

## HIPAA (US)

| Safeguard | What DEEPSecurity provides |
|---|---|
| §164.312(a)(1) — Access control | JWT + role-based authorisation; default-deny |
| §164.312(b) — Audit controls | `AuditLog` on every state-changing action, searchable by actor / action / time |
| §164.312(c)(1) — Integrity | SHA-256 on every scanned artefact; hash stored with the scan result |
| §164.312(d) — Person or entity authentication | Short-lived JWT; IdP integration seam in `deepsecurity.api.auth.login` |
| §164.308(a)(1)(ii)(D) — Information system activity review | `/metrics` + `/api/compliance/report` |

## ISO/IEC 27001

| Control family | How we support it |
|---|---|
| A.5 — Info-sec policies | `docs/SECURITY.md` + `docs/THREAT_MODEL.md` |
| A.8 — Asset management | `ScanSession` + `ScanResult` inventory your scanned filesystems |
| A.9 — Access control | Role-gated API, audit log |
| A.12 — Operations security | Signature + YARA + ML detection; DLP; Prometheus metrics |
| A.16 — Incident management | Alert bus (Slack / webhook / syslog / email) + quarantine workflow |
| A.18 — Compliance | Retention policy (`purge_older_than`), compliance report API |

## Data classifications we recognise

DLP patterns are grouped by severity. The mapping can inform your data-classification policy:

| Severity | Patterns | Implies |
|---|---|---|
| Critical | AWS keys, GCP service accounts, PEM private keys, GitHub / Slack / HF / Stripe tokens | Immediate rotation required |
| High | JWTs, generic API-key-like values | Review required |
| Medium | US SSN, credit card numbers | Potential PII / PCI — review |
| Low | Email addresses | PII, often legitimate |

## What an auditor can do with what's in the box

```bash
# 1. Prove scanning happened.
curl -H "Authorization: Bearer $TOKEN" \
    "http://deepsec:5000/api/compliance/report?days=90" | jq

# 2. Export the audit trail for the window under review.
curl -H "Authorization: Bearer $TOKEN" -o audit.csv \
    "http://deepsec:5000/api/compliance/audit.csv?days=90"

# 3. Confirm retention is enforced.
curl -X POST -H "Authorization: Bearer $TOKEN" \
    "http://deepsec:5000/api/compliance/purge?days=90"

# 4. Verify an individual file's lifecycle.
curl -H "Authorization: Bearer $TOKEN" \
    "http://deepsec:5000/api/scanner/results?session_id=<id>" | jq

# 5. Dump scan metrics for the evidence pack.
curl http://deepsec:5000/metrics
```

## What still needs organisation-level work

- **Data-subject access requests.** The tool stores file paths and hashes,
  not personal records — but if a file path identifies a person (e.g. under
  `/users/alice/`), the organisation owns the SAR process.
- **Breach notification timing.** Alerts fire; the human decision to notify
  a regulator within 72 h (GDPR) or 60 days (HIPAA) is not automated.
- **Risk assessment documentation.** `docs/THREAT_MODEL.md` is a starting
  point, not a certified ISMS risk register.
- **Chain of custody for forensic evidence.** The quarantine copy + audit
  trail + hash are enough for a technical chain; a formal legal chain
  requires your incident-response process.
