# Switching to PostgreSQL

SQLite is the default — it's the right choice for a personal, single-node,
single-writer install. If any of these are true, switch to PostgreSQL:

- More than one client writing at the same time (concurrent scans).
- You want remote read access for reporting or analytics.
- You're deploying this as a shared service.
- The audit log is your forensic record of truth and you want native replication.

## Fastest path — docker-compose

The shipped `deploy/docker-compose.yml` already contains a `db` service
using `postgres:16-alpine`, and the `api` service defaults to pointing at
it. You just need one extra variable in `.env`:

```
POSTGRES_PASSWORD=<a long random password>
```

Generate one:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Then:

```bash
cd deploy
docker compose up --build
```

That brings up both containers. The API waits for postgres to pass its
healthcheck before it starts. Data lives in the `deepsec-pgdata` named
volume — it survives container rebuilds.

## Local (no Docker)

```bash
# Install the driver
pip install "deepsecurity[postgres]"

# Start a local postgres (or use an existing one). Example:
sudo -u postgres createuser --pwprompt deepsec
sudo -u postgres createdb -O deepsec deepsec

# Point DEEPSecurity at it
export DEEPSEC_DATABASE_URL='postgresql+psycopg://deepsec:YOUR_PASSWORD@localhost:5432/deepsec'

deepsec init-db
deepsec serve
```

## Migrating from SQLite

We don't ship an automated data migrator yet — the schema is simple enough
that a one-liner via `pgloader` or manual `sqlite3 … .dump` → `psql` works
fine. Typical path:

```bash
# 1. Export from SQLite
sqlite3 data/deepscan.db .dump > /tmp/deepsec.sql

# 2. Strip SQLite-isms (BEGIN TRANSACTION; PRAGMA …) that postgres doesn't
#    understand — a sed pass usually suffices for this schema.
grep -v "^PRAGMA" /tmp/deepsec.sql \
  | grep -v "^BEGIN TRANSACTION" \
  | grep -v "^COMMIT" > /tmp/deepsec.pg.sql

# 3. Load into postgres
psql 'postgresql://deepsec:password@localhost/deepsec' < /tmp/deepsec.pg.sql
```

If the tables already exist on the postgres side (from `deepsec init-db`),
drop them first or use `\i /tmp/deepsec.pg.sql` after `deepsec reset-db
--yes`.

## Ongoing operations

- **Connection pooling.** SQLAlchemy's default pool size is 5. For busy
  deployments, set `?pool_size=20` in the URL or override in code.
- **Backups.** `pg_dump -U deepsec deepsec > daily.sql` on cron.
- **Retention.** `deepsec purge --days 90` still works identically on
  postgres — it goes through the same SQLAlchemy delete.
- **Replication / HA.** Standard PostgreSQL streaming replication or a
  managed service (RDS, Cloud SQL, Neon, Supabase). DEEPSecurity has no
  hard ties to a specific postgres feature.

## When SQLite is still right

- Single laptop / workstation.
- Air-gapped environments where you don't want another daemon.
- Embedded / appliance deployments where the scanner is one component on
  one box.

For those, leave `DEEPSEC_DATABASE_URL=sqlite:///data/deepscan.db` and
skip this doc entirely.
