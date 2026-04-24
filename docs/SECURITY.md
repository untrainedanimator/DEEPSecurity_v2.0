# Security

This is a scanner. It reads untrusted bytes from disk and exposes a web API
that can act on them. We take its security posture seriously.

## Threat model

The assets we protect:

1. **The user's filesystem.** A bug that mis-quarantines user files is the
   most likely harm. We defend against it with the MIME whitelist, the
   quarantine-only (never-auto-delete) policy, and an explicit `suspicious`
   label that never triggers file movement.
2. **Leaked credentials.** Secrets live in `.env` (gitignored) and are
   validated at startup. Placeholders from `.env.example` are refused. CORS
   wildcards are refused.
3. **Unauthorised API access.** Auth is a short-lived JWT, not a session
   cookie. There is no "dev fallback" user — failing auth returns 401, full
   stop. Role-gated routes require the claim, not a request body.
4. **Path traversal.** Every user-supplied path goes through
   `deepsecurity.paths.resolve_under_root()` before the scanner touches it.
   Paths that escape `DEEPSEC_SCAN_ROOT` are rejected with 400.
5. **Supply-chain risk.** Dependencies are pinned. CI runs `pip-audit`.
   `pre-commit` includes `detect-private-key`.

## Non-goals

- This tool is not an IDS, EDR, or antivirus replacement. It is a local
  scanner useful for analysts, labs, and research rigs.
- No network-based threat detection. No behavioural analysis.
- No real-time kernel or filesystem hooks. Scans are triggered by the user.

## Reporting a vulnerability

Open a private issue or email the maintainer. Please do not file a public
issue for anything that describes an exploitable bug.

## Hardening checklist for deployment

- [ ] `DEEPSEC_SECRET_KEY` and `DEEPSEC_JWT_SECRET` are 32+ random chars
      (generated with `python -c "import secrets; print(secrets.token_hex(32))"`).
- [ ] `DEEPSEC_CORS_ORIGINS` lists only production origins. No `*`.
- [ ] `DEEPSEC_SCAN_ROOT` points only at the directory you actually want
      scanned, not `/` or `C:\`.
- [ ] `DEEPSEC_DEV_PASSWORD` is rotated or the dev auth is swapped for a
      real IdP before exposure beyond localhost.
- [ ] The container runs as the `deepsec` user (it does, by default).
- [ ] The scanner mount in `docker-compose.yml` is read-only (`:ro`).
- [ ] `DEEPSEC_OUTLOOK_ENABLED` is false unless you explicitly want Outlook
      scanning and have acknowledged that attachments are written to disk
      under `$TMP` during the scan.
- [ ] Database backups exist. The audit log is the forensic trail — losing
      it is losing accountability.

## What this project will not do

- Automatically delete files. The closest thing we do is `quarantine_copy`,
  which copies a detected file into a separate directory. The original is
  never touched.
- Trust entropy alone. A high-entropy file becomes `suspicious`, not
  `malicious`, and is never quarantined on that basis.
- Run the ML layer if no model is configured. The layer reports honestly
  that it is disabled, and the scanner continues with signature + entropy.

## Change log (security-relevant)

- 2026-04-23 — Removed the JWT exception fallback in `routes/scanner.py` that
  auto-logged any caller in as a "debug" analyst.
- 2026-04-23 — Removed `cors_allowed_origins="*"` from SocketIO; CORS is now
  a pinned list and `*` is rejected by config validation.
- 2026-04-23 — Outlook auto-delete (`delete_file(..., soft_delete=False)` at
  confidence > 0.85) replaced with quarantine-only.
- 2026-04-23 — Added `resolve_under_root()` on every API route that accepts
  a path.
- 2026-04-23 — Refused to boot with placeholder secrets.
