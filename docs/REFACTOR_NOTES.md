# Refactor notes — from v2.0 to v2.1

The previous v2.0 had a sound architectural instinct (streaming I/O,
MIME-aware baseline, conservative quarantine) with a fragile implementation.
These notes capture what changed and why. Paired with `_legacy/` (the old
source, kept for reference) you can diff any claim here.

## Bugs that would have crashed a running instance

1. **`log_scan_event` signature mismatch.** The function was defined as
   `log_scan_event(actor, file_path, label, confidence, reason, timestamp=None)`
   but called as `log_scan_event(scan_path, False, {...dict...})` throughout
   `routes/scanner.py` and `core/outlook_scanner.py`. Every call site would
   have raised `TypeError` the moment a request hit it.
   **Fix:** replaced with the keyword-only `audit_log()` in `deepsecurity.audit`.

2. **`scan_status` dictionary key mismatch.** `core/global_state.py` defined
   keys `{"active", "session_id", "progress", ...}`, but
   `routes/scanner.py` read `scan_status["running"]`, `["scanned_count"]`,
   `["total_files"]`, `["output"]`, `["current_file"]`, `["start_time"]`.
   **Fix:** `deepsecurity.scan_state` now uses a dataclass with a typed
   `snapshot()` method; keys are schema-checked at use.

3. **`scan_dispatcher.start_scan` wrong signature.** Routes called it as
   `start_scan(scan_type=..., path=..., actor=..., user_role=..., detection_config=...)`
   but the function was `start_scan(directory, actor, role)`.
   **Fix:** removed the wrapper entirely. Routes call
   `deepsecurity.scanner.scan_directory()` directly.

4. **Duplicate function definitions in `core/scanner.py`.** `generate_preview`
   and `move_to_safe_list` were each defined twice; the second (stub)
   definition overrode the first (real) one. So `move_to_safe_list` always
   returned `True` without doing anything.
   **Fix:** single definition per function in `deepsecurity/scanner.py`.

5. **Module-level model loading in `core/scanner.py`.** The model was
   loaded as a side effect of `import`, which made the module unusable in
   tests and CLI contexts without a model file.
   **Fix:** `MLClassifier` lazy-loads on first classify() call.

6. **`/ml_explain` imported `core.ml_explainer` — a module that did not exist.**
   First request → 500.
   **Fix:** route removed pending a real explainability implementation
   against a real model.

## Security fixes

- **JWT fallback removed.** `routes/scanner.py:67-70` had a `try/except` that
  assigned `user = {"username": "debug", "role": "analyst"}` on any auth
  failure. Every unauthenticated request was silently promoted to an analyst.
  **Fix:** `deepsecurity.api.auth.require_role` returns 401 or 403; there is
  no fallback identity anywhere.

- **`cors_allowed_origins="*"` removed.** SocketIO accepted any origin. The
  new config layer refuses to start with `*` or a list containing `*`.

- **Outlook permanent-delete removed.** The `outlook_scanner.py` path
  `delete_file(save_path, soft_delete=False)` at ML confidence > 0.85 has
  been deleted. Every detection is quarantined; attachments and mailboxes are
  never modified.

- **Path traversal guard.** Every API endpoint that takes a filesystem path
  now resolves it under `settings.scan_root`. Traversal → 400.

- **Placeholder-secret refusal.** Settings validation rejects the
  `change-me-*` strings from `.env.example`, along with "changeme", "secret",
  "password", and "admin".

## Layout changes

| Before                            | After                                           |
|-----------------------------------|-------------------------------------------------|
| `core/scanner.py` (661 lines)     | `deepsecurity/scanner.py` (focused, dedup'd)   |
| `core/ml_model.py` (random API names) | `deepsecurity/ml.py` (honest `MLVerdict`)    |
| `core/outlook_scanner.py`         | `deepsecurity/outlook.py` (quarantine-only)    |
| `core/audit_logger.py`            | `deepsecurity/audit.py` (single entrypoint)    |
| `core/global_config.py`           | `deepsecurity/config.py` (pydantic-settings)   |
| `core/global_state.py`            | `deepsecurity/scan_state.py` (typed snapshot)  |
| `core/database.py`                | `deepsecurity/db.py` + `deepsecurity/models.py`|
| `routes/scanner.py`               | `deepsecurity/api/scanner.py` (split)          |
| `core/scan_dispatcher.py`         | deleted — was a 21-line wrapper                 |
| `core/core.scanner.txt`           | deleted — stray .py-as-.txt copy                |
| `core/routes.scanner.txt`         | deleted                                         |
| `My Documents/`                   | moved to `_legacy/My_Documents/`                |
| `ceremony/`                       | moved to `_legacy/ceremony/`                    |
| `src/` (React)                    | moved to `frontend/src/`                        |

## New infrastructure

- `requirements.txt` + `requirements-dev.txt` — pinned dependencies.
- `pyproject.toml` — package metadata, ruff + mypy + pytest config.
- `.env.example` — every config variable documented with comment.
- `Makefile` — `install`, `dev-install`, `lint`, `format`, `test`, `run`, `docker-*`.
- `deploy/Dockerfile` + `deploy/docker-compose.yml` — non-root, healthcheck, gunicorn.
- `.github/workflows/ci.yml` — lint + test (matrix over 3.11 / 3.12) + docker build + pip-audit.
- `.github/workflows/release.yml` — publish to GHCR on tag.
- `.pre-commit-config.yaml` — ruff, mypy, detect-private-key, trailing-whitespace.
- `docs/ARCHITECTURE.md`, `docs/SECURITY.md` — the story and the hardening checklist.

## Tests added (22 test cases across 7 files)

- `test_config.py` — placeholder-secret refusal, wildcard-CORS refusal, JWT bound check.
- `test_paths.py` — traversal (parent, double-dot, symlink) all return `PathOutsideRootError`.
- `test_entropy.py` — entropy range on zeros / random / text; MIME baseline adaptation;
  MIME whitelist coverage.
- `test_scanner.py` — **the regression test for v1.0-working's bug**: a
  high-entropy JPEG is not quarantined; signature match quarantines but
  leaves original in place; quarantine/restore round-trip; directory-level
  scan rejects out-of-root paths.
- `test_api_auth.py` — login issues a token; bad password → 401; protected
  route with no token → 401 (not 200 with a fallback identity).
- `test_api_scanner.py` — start rejects out-of-root paths; status shape;
  sessions/cancel/results require auth.
- `test_outlook_policy.py` — disabled by default raises; non-Windows raises;
  delete-on-detect invariant is False.

## Honest limitations

- The ML layer is structurally sound but ships without a trained model. The
  README and `ARCHITECTURE.md` are explicit: wire in an EMBER-trained
  classifier when you're ready.
- No database migrations yet. The schema is created by `create_all()`.
  Alembic goes in when the first non-trivial schema change lands.
- The frontend is a minimal dashboard; it demonstrates the three real pages
  (live scan, quarantine, audit) but doesn't rebuild v1.0's twenty-one panels.
