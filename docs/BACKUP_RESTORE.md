# Backup & Restore Runbook

DEEPSecurity ships an online-snapshot backup CLI suitable for compliance
evidence (SOC2 CC9.1, ISO27001 A.8.13, HIPAA §164.308(a)(7)) and disaster
recovery. This document is the operator runbook.

## At a glance

```
deepsec backup full           # rotated daily snapshots, keeps 7
deepsec backup incremental    # rotated hourly snapshots, keeps 24
deepsec backup list           # show what's on disk
deepsec restore --latest --confirm
deepsec restore --from <path> --confirm
```

Default destination: `data/backups/` under the repo root. Override
with `--to <dir>` (or `--in <dir>` for `list`/`restore --latest`).

## What "incremental" means here

`full` and `incremental` both produce **complete snapshots**. The only
difference is the default rotation policy:

| command       | default `--keep` | typical cron     |
| ------------- | ---------------- | ---------------- |
| `full`        | 7                | `@daily`         |
| `incremental` | 24               | `0 * * * *` (hourly) |

This is deliberate. At our DB scale (50–200 MB), real WAL-shipping
deltas are over-engineering: the snapshot is fast, the disk cost is
trivial, and "restore the most recent snapshot" is unambiguous in a
way that "restore the base + N deltas in order" is not. If your deploy
ever outgrows this, the CLI shape (`backup full` / `backup incremental`)
is forward-compatible with real differential backups.

## How it works under the hood

**SQLite.** We use the built-in `Connection.backup()` API, which pumps
pages from the live DB into a fresh file while the server is still
writing. No flock contention, no service downtime. The output is a
plain `.db` file you can open directly with `sqlite3 backup.db`.

**Postgres.** We shell out to `pg_dump --format=plain`. The output is
SQL text, which means you can `less` it during incident response.
Replay with `psql -f`. Requires `pg_dump` on `PATH`.

**Filename schema.** `deepsec_<UTC ts>_full.<ext>` — e.g.
`deepsec_20260425T143015Z_full.db`. Rotation parses the timestamp out
of the filename, so do not rename files in the backup directory if you
want them to be eligible for rotation. (Renamed files are always safe
from rotation — we only delete files that match our schema.)

## Cron / Task Scheduler examples

### Linux cron

```cron
# Daily full at 02:15 — keeps 7 days
15 2 * * * cd /opt/deepsecurity && /opt/deepsecurity/.venv/bin/deepsec backup full --keep 7

# Hourly snapshot at :05 — keeps 24 hours
5 * * * *  cd /opt/deepsecurity && /opt/deepsecurity/.venv/bin/deepsec backup incremental --keep 24
```

### Windows Task Scheduler (PowerShell)

```powershell
# Run as the same user that owns the DEEPSecurity install.
$action = New-ScheduledTaskAction `
    -Execute "C:\Apps\DEEPSecurity_v2.0\.venv\Scripts\deepsec.exe" `
    -Argument "backup full --keep 7" `
    -WorkingDirectory "C:\Apps\DEEPSecurity_v2.0"
$trigger = New-ScheduledTaskTrigger -Daily -At 2:15am
Register-ScheduledTask -TaskName "DEEPSecurity backup full" `
    -Action $action -Trigger $trigger
```

## Restoring

Restore is destructive. The CLI enforces three guards:

1. **`--confirm` is mandatory.** No prompt-driven restore — if you're
   not sure enough to type `--confirm`, you're not sure enough to
   destroy the live DB.
2. **Server must be stopped.** `deepsec restore` queries the local
   pidfile; if the server is up it refuses. Override with `--force`
   only if you are restoring on a fresh host where the local pidfile
   doesn't reflect reality.
3. **Safety copy is automatic.** Before overwriting, the current DB is
   copied to `<dbpath>.pre_restore_<UTC ts>`. If the restore turns out
   to have been the wrong file, you can swap that back into place.

### Procedure

```bash
# Verify what's available
deepsec backup list

# Stop the server cleanly
deepsec stop

# Restore the most-recent snapshot
deepsec restore --latest --confirm

# Or restore a specific file
deepsec restore --from data/backups/deepsec_20260425T143015Z_full.db --confirm

# Bring the server back up
deepsec start

# Once you've verified the restore is correct, delete the safety copy
# (the CLI tells you the path).
rm data/deepscan.db.pre_restore_*
```

### Postgres-specific notes

`deepsec restore` for postgres assumes:

- The target database exists and is empty (or willing to be
  overwritten in place).
- For a true point-in-time rebuild, do
  `DROP DATABASE deepsec; CREATE DATABASE deepsec OWNER deepsec;`
  before invoking restore.
- `psql` must be on `PATH` and able to read your `DEEPSEC_DATABASE_URL`
  credentials. Test with a no-op query first:
  `psql "$DEEPSEC_DATABASE_URL" -c "SELECT 1;"`.

## What's in the snapshot

Everything that lives in the database:

- `audit_log` (every action ever taken, redacted DLP previews)
- `scan_session` / `scan_result` (scan history)
- `agent` / `agent_policy` (fleet inventory + per-agent policy)
- `quarantine_record` (provenance for files in `quarantine/`)
- `safelist` / `dismissals`

What is **not** in the snapshot:

- The `quarantine/` directory itself (binary files; back up separately)
- The `safelist/` directory (operator-curated, version-controlled)
- `logs/` (rotated separately — these are not authoritative state)
- `models/` (ML artifacts; pinned-version, ship-controlled)

For a complete DR recovery, also tar `quarantine/` and `safelist/`.
The DB references them by path, so restoring just the DB will leave
dangling pointers.

## Compliance evidence

For SOC2 CC9.1 / ISO27001 A.8.13 audits, the auditor wants to see:

1. **A documented backup schedule.** This file + your cron entries.
2. **Evidence backups actually happen.** `audit_log` rows with
   `action='backup.full'` / `action='backup.incremental'`.
3. **Evidence restores have been tested.** Restore quarterly into a
   non-production environment and record an `audit_log` entry; the
   compliance API surface exposes these via
   `GET /api/compliance/template/iso27001_a_8_9?days=90`.

The audit row written by `deepsec backup full` includes the destination
path, the byte size, the rotation outcome, and the keep value — every
field an auditor will ask for.

## Failure modes

| Symptom                                            | Cause                                        | Fix                                                |
| -------------------------------------------------- | -------------------------------------------- | -------------------------------------------------- |
| `cannot back up an in-memory or empty SQLite URL`  | `DEEPSEC_DATABASE_URL=sqlite:///:memory:`    | Configure a file-based URL                         |
| `pg_dump not on PATH`                              | postgresql-client missing                    | `apt install postgresql-client` or set `PGBIN`     |
| `unsupported database URL scheme`                  | `mysql://` or another DB                     | Currently only sqlite:// and postgresql:// supported |
| `refusing to restore: DEEPSecurity is currently running` | server up                              | `deepsec stop`, then re-run                        |
| Restore appears to succeed but server fails to start | DB schema older than the package version   | `deepsec init-db` after restore (idempotent)       |

## Smoke test

After any change to your backup setup, run this in a non-prod env:

```bash
# 1. Take a backup
deepsec backup full --to /tmp/dr_test --keep 3

# 2. Cause a known mutation
deepsec scan ./samples

# 3. Stop, restore, start
deepsec stop
deepsec restore --latest --in /tmp/dr_test --confirm
deepsec start

# 4. Verify the mutation is gone (the scan session from step 2 should
#    be absent).
deepsec report --days 1 | jq '.totals'
```

If step 4 doesn't show the pre-mutation state, your backup or restore
is broken. Investigate before relying on it for DR.
