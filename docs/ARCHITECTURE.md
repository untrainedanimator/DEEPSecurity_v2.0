# Architecture

## One-sentence summary

A Flask API around a pure-Python scanning engine that walks a directory, hashes
and entropy-fingerprints each file, optionally runs an ML classifier, and
copies detections into a quarantine folder — with every action audit-logged.

## Layers

```
          ┌────────────────────────────┐
          │  Frontend (Vite + React)   │   CORS-guarded to explicit origins
          └────────────┬───────────────┘
                       │ JSON over HTTPS
          ┌────────────▼───────────────┐
          │  deepsecurity.api (Flask)  │   JWT-gated blueprints
          │  auth / scanner / quar /   │   health, errors, role decorator
          │  audit / health            │
          └────────────┬───────────────┘
                       │
          ┌────────────▼───────────────┐
          │  deepsecurity.scanner      │   pure functions over FileFeatures
          │  + deepsecurity.ml         │   + MLClassifier (joblib)
          │  + deepsecurity.paths      │   + resolve_under_root()
          └────────────┬───────────────┘
                       │
          ┌────────────▼───────────────┐
          │  deepsecurity.db (SQLAlch) │   ScanSession / ScanResult / AuditLog /
          │  + deepsecurity.audit      │   SafeListEntry
          └────────────────────────────┘
```

## Request lifecycle — start scan

1. Client hits `POST /api/scanner/start` with `{path: "..."}` and a bearer token.
2. `@require_role("admin","security")` decodes the JWT. 401 / 403 short-circuits.
3. Route calls `resolve_under_root(path, settings.scan_root)`. Traversal → 400.
4. A daemon thread is dispatched. 202 returned immediately with the target path.
5. In-thread `scan_directory(...)` opens a DB session, records a `ScanSession`,
   walks files with `iter_files()`, and for each one:
   1. `extract_features()` — MIME, size, SHA-256, and (if not whitelisted) entropy.
   2. `classify()` — combines signature match, ML verdict, anomaly score.
   3. If malicious → `quarantine_copy()` — the **original is never deleted**.
   4. Persist `ScanResult` row (batched; commits every 50 files).
   5. Update `scan_state.state` so `/api/scanner/status` can report progress.
6. When done (or cancelled), a final `ScanSession` update records totals and status.

## Detection policy

| Evidence                                           | Outcome                             |
|---------------------------------------------------|-------------------------------------|
| SHA-256 matches the signature list                | `malicious` — quarantine           |
| ML layer enabled AND confidence ≥ threshold       | `malicious` — quarantine           |
| Anomaly score ≥ threshold (non-whitelisted MIME)  | `suspicious` — log, do nothing     |
| Everything else                                    | `clean`                             |

The confidence threshold is a per-deployment configuration (`DEEPSEC_ML_CONFIDENCE_THRESHOLD`, default 0.85).
The anomaly threshold defaults to 2.0 bits/byte above the MIME-specific baseline.

## MIME whitelist

`deepsecurity.scanner.MEDIA_MIMES` and `ARCHIVE_MIMES` contain common audio,
video, image, and archive MIME types. Files of these types skip the entropy
layer because their high entropy is structural (compression / encoding), not
suspicious. The signature layer still runs — a known-bad MP4 will still be
flagged. This is the fix for v1.0-working's false-positive disaster.

## ML layer

`deepsecurity.ml.MLClassifier` lazily loads a joblib-pickled sklearn model from
`DEEPSEC_ML_MODEL_PATH`. If no path is configured or the file is missing, the
classifier returns `MLVerdict(enabled=False, ...)` and the scanner continues
with signature + entropy only.

Feature vector for live scans: `[entropy, size_kb, anomaly_score]`.

A proper training pipeline is intentionally out of scope for the initial cut.
Recommended: fine-tune on a labelled dataset such as EMBER
(<https://github.com/elastic/ember>) and ship the resulting joblib as a
versioned artefact under `models/`.

## State and concurrency

- `deepsecurity.scan_state.state` is a single `ScanState` singleton with an
  internal `threading.Lock`. One active scan at a time; `/api/scanner/start`
  returns 409 if one is already running.
- Database writes go through a `session_scope()` context manager that commits
  on success, rolls back on exception, and always closes the session.
- Each inbound request is a thread; long-running scans are dispatched onto a
  daemon thread so the HTTP response returns immediately.

## Observability

- Structured logging via `structlog`. JSON in production, pretty console in dev.
- Every audit event writes both to the `audit_log` table (for API querying)
  and to stdout (for log-aggregator ingestion).
- `GET /healthz` always 200 if the process is serving.
- `GET /readyz` checks DB connectivity and scan-root presence; 503 if degraded.

## Future work (tracked, not implemented)

- Alembic migrations (the schema is stable enough that `create_all` is fine
  for now; migrations go in when the first non-trivial change lands).
- WebSocket progress push (currently polling `/api/scanner/status`).
- Proper identity provider integration; the built-in `DEEPSEC_DEV_USER`
  auth is a placeholder for local development.
- Real ML training pipeline (see `ml.py` comment).
