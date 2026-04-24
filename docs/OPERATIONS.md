# Operations Runbook

## Start / stop

```bash
# Dev
make run

# Prod
gunicorn --bind=0.0.0.0:5000 --workers=1 --threads=4 \
  'deepsecurity.api:create_app()'

# Container
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml down
```

## Switching to PostgreSQL

See `docs/POSTGRES.md`. Short version: `docker compose up --build` with a
`POSTGRES_PASSWORD` in `.env` gives you a ready postgres service the API
uses by default.

## Daily operator tasks

| Task | Command |
|---|---|
| Pull fresh threat-intel feeds | `deepsec intel-update` or `POST /api/intel/update` |
| Generate a 30-day compliance report | `deepsec report --days 30` |
| Export audit trail for the last 30 days | `GET /api/compliance/audit.csv?days=30` |
| Enforce retention policy | `deepsec purge` or `POST /api/compliance/purge` |
| Start real-time watchdog | `deepsec watchdog start` or `POST /api/watchdog/start` |
| Check system health | `GET /healthz` (always-on), `GET /readyz` (deps) |

## Monitoring

Scrape `http://host:5000/metrics` every 15–30 s. Example Prometheus job:

```yaml
- job_name: deepsecurity
  static_configs:
    - targets: ['deepsec:5000']
  metrics_path: /metrics
```

Key metrics:

- `deepsec_scans_started_total` / `deepsec_scans_completed_total` — throughput
- `deepsec_detections_total` — trigger for an alert if non-zero in last 5 min
- `deepsec_dlp_findings_total` — trigger for any critical-severity pattern
- `deepsec_quarantine_actions_total` — confirm the app is acting
- `deepsec_scan_duration_seconds_bucket` — latency histogram
- `deepsec_auth_denied_total` — brute-force signal
- `deepsec_active_scans` — should be 0 or 1 in single-replica mode

## Alert routing

`deepsecurity.alerts` has a process-wide `AlertBus`. Default rules:

1. `critical` or `high` → every configured sink (console + slack + webhook + syslog + email)
2. `medium` → every sink except email
3. everything else → console only

Configure sinks via `.env`:

- `DEEPSEC_SLACK_WEBHOOK_URL`
- `DEEPSEC_ALERT_WEBHOOK_URL`
- `DEEPSEC_SYSLOG_HOST` + `DEEPSEC_SYSLOG_PORT`
- SMTP block (`DEEPSEC_SMTP_*`, `DEEPSEC_ALERT_EMAIL_TO`)

## Incident response — initial triage

1. **Detection alert fires.** Click the file path in the alert — or hit
   `GET /api/scanner/results?session_id=<id>&label=malicious` for the session.
2. **Confirm the quarantine.** `GET /api/quarantine/list` shows the copy.
   The **original is still in place** — this is by design. The quarantine is
   a safety copy, not a move.
3. **Decide.** Options:
   - Leave quarantined for analysis. No action needed.
   - Restore to another location: `POST /api/quarantine/restore`.
   - Permanently delete the quarantine copy:
     `POST /api/quarantine/delete` with `{"name": "...", "reason": "..."}`.
     Reason is required; it ends up in the audit log.
   - Add to safelist (so future scans don't re-detect):
     `POST /api/quarantine/safelist` with `{"sha256": "...", "file_path": "..."}`.
4. **Audit.** `GET /api/audit?actor=<user>&limit=200` shows who did what.

## Retention

Default retention is 90 days for audit / scan-result / scan-session rows. Run
`deepsec purge` weekly (or a scheduled task) to enforce. DLP findings follow
the same retention when you add the purge to them — currently they stay until
you drop the table (short-term: add `DLPFinding` to `purge_older_than()` when
you wire a scheduler).

## Common failures

| Symptom | Likely cause | Fix |
|---|---|---|
| `/readyz` returns 503 | DB down or `scan_root` missing | Check `DEEPSEC_DATABASE_URL`, mkdir the root |
| Every scan returns 400 | Path isn't under `DEEPSEC_SCAN_ROOT` | Move target into scan_root or reconfigure |
| Watchdog stays unavailable | `watchdog` not installed | `pip install 'deepsecurity[watchdog]'` |
| YARA never matches | No rules directory | Set `DEEPSEC_YARA_RULES_DIR`, drop .yar files in |
| Alerts not firing | Check `deepsec_alerts_sent_total` in /metrics | Verify sink config in .env |
| Login returns 503 | `DEEPSEC_DEV_PASSWORD` empty | Set a password or wire an IdP |
