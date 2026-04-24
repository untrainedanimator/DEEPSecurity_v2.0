# DEEPSecurity

**A user-space policy, DLP, and compliance overlay for endpoints.**
Runs **alongside** your AV (Windows Defender / SentinelOne / CrowdStrike) —
not as a replacement for it. Where your AV answers *"is this malware?"*,
DEEPSecurity handles what it punts on: explainable policy detections,
data-loss prevention for secrets and PII, MITRE ATT&CK-tagged audit trails,
compliance reporting, and a SIEM-ready event stream.

**What it is:**

- A user-space scanner for **policy violations** on files and processes —
  secrets in source code, PII in shared folders, suspicious parent chains
  (Office → shell, PDF → shell), known-bad LOLBins, cryptominers, and
  ransomware write-rate anomalies.
- A **DLP engine** with regex patterns for AWS / GCP / Azure keys,
  GitHub / Slack / Stripe tokens, SSNs, credit-card numbers, PHI, email
  addresses. Every finding is stored *redacted*, not raw.
- A **compliance overlay** — MITRE-tagged detections, retained audit log,
  retention-purge enforcement, CSV/JSON exports that map onto SOC2 / ISO
  27001 / HIPAA evidence requirements.
- A **signal source** for existing security stacks — Prometheus metrics on
  `/metrics`, pluggable alert sinks (Slack, generic webhook, RFC-5424
  syslog, SMTP email). Drop it into Splunk / Elastic / Sentinel.
- **Transparent and auditable** — ~8K lines of Python you can read
  end-to-end. No kernel driver, no binary blobs, no telemetry home, no
  cloud dependency to run it.

**What it is NOT:**

- **Not an AV replacement.** Keep Defender on. DEEPSecurity catches
  different things.
- **Not an EDR.** We don't hook the kernel. File events are near-real-time
  via `watchdog`; process and network visibility are *polled*, not streamed.
- **Not a network security product.** We can't drop packets, intercept
  DNS, or inspect TLS. We can enumerate connections (via `psutil`) and
  alert on IPs matching a reputation feed.
- **Not self-protecting.** Task Manager can kill DEEPSecurity. That's a
  deliberate trade-off — no signed kernel driver means no
  undisableability. See `docs/THREAT_MODEL.md` for the full ceiling.

**Who it's for:** small security teams running SOC2 / ISO 27001 / HIPAA
audits, engineering shops that need DLP on dev laptops, contractor/BYOD
fleets where you can't install enterprise AV, file-server owners who want
explainable policy enforcement and a real audit trail.

> **Status.** Refactored from the v2.0 prototype into a reproducible,
> testable, deployable shape. See `docs/ARCHITECTURE.md` for the design,
> `docs/WEDGE.md` for the target use case, and `docs/REFACTOR_NOTES.md`
> for what changed and why.

## What it does

**On-demand scan** of a directory you control. For each file:

1. Hash the content (SHA-256) and compare against a list of known-bad hashes.
   Threat-intel feeds (MalwareBazaar, AlienVault OTX) append to this list.
2. If a YARA rules directory is configured, run rules against the file.
3. If an ML model is configured, score `(entropy, size_kb, anomaly)` and
   flag high-confidence detections.
4. Flag anomalous-entropy files for review — but never act on entropy alone.
5. In parallel, run a **DLP sweep** over text-ish files for secrets
   (AWS/GCP keys, private keys, GitHub/Slack/HF/Stripe tokens) and PII
   (SSNs, credit cards, emails). Findings are stored redacted.

On a detection, the file is **copied** to a quarantine directory. The
original is left in place. Permanent deletion is a separate, audit-logged,
admin-only action that requires a reason string.

**Real-time** file-system monitoring is available via the `watchdog`
optional dep — any new or modified file under `scan_root` gets scanned
automatically.

MIME whitelist: MP3s, MP4s, JPEGs, ZIPs, and other common media/archive
formats skip the entropy layer entirely, because their high entropy is
structural rather than suspicious. This is the single design decision that
prevents the v1.0-working failure mode of quarantining the user's music
library.

**Alerts** go out on every high/critical detection via any combination of:
Slack webhook, generic HTTPS webhook, RFC-5424 syslog (for SIEM ingestion),
or SMTP email. Rules are configurable and failing sinks never break the
caller.

**Metrics** are exposed on `/metrics` in Prometheus text format — scan
throughput, detection counts, DLP findings, rate-limit denials, scan
duration histograms.

**Compliance** reports via `/api/compliance/report?days=30` give auditors a
GDPR/HIPAA/ISO-friendly JSON pack; `audit.csv` exports the access log;
`purge` enforces retention.

## Quick start

Supported Python: **3.11** or **3.12** recommended. 3.13 works with core deps.
3.14 works for core deps but **not** for the optional `[ml]` extra on Windows
(no prebuilt numpy/scipy wheels yet — use 3.12 if you want the ML layer).

### Windows (cmd.exe)

```cmd
cd C:\Apps\DEEPSecurity_v2.0
py -3.12 -m venv .venv
.venv\Scripts\activate.bat
pip install --upgrade pip
pip install -r requirements-dev.txt

copy .env.example .env
REM Edit .env — at minimum set DEEPSEC_SECRET_KEY, DEEPSEC_JWT_SECRET,
REM DEEPSEC_DEV_PASSWORD, and DEEPSEC_SCAN_ROOT to a real folder.

deepsec init-db
pytest
deepsec serve
```

### PowerShell

```powershell
cd C:\Apps\DEEPSecurity_v2.0
py -3.12 -m venv .venv
.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements-dev.txt
copy .env.example .env      # edit the file
deepsec init-db
pytest
deepsec serve
```

### macOS / Linux

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements-dev.txt
cp .env.example .env        # edit the file
deepsec init-db
pytest
deepsec serve
```

### If you don't have Python 3.12 and are stuck on 3.14

Core still installs fine — you just can't use the ML layer:

```cmd
py -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
REM Leave DEEPSEC_ML_MODEL_PATH empty. The scanner runs without it.
```

### Optional capability extras

```bash
pip install "deepsecurity[watchdog]"   # real-time file monitoring
pip install "deepsecurity[yara]"       # YARA rule engine
pip install "deepsecurity[ml]"         # sklearn-based ML detection
pip install "deepsecurity[windows]"    # Outlook (Windows only)
pip install "deepsecurity[all]"        # everything available on your platform
```

Login:

```bash
curl -s -X POST http://127.0.0.1:5000/api/auth/login \
    -H 'content-type: application/json' \
    -d '{"username":"admin","password":"your-password-from-env"}'
```

Kick off a scan (replace TOKEN):

```bash
curl -s -X POST http://127.0.0.1:5000/api/scanner/start \
    -H 'content-type: application/json' \
    -H "Authorization: Bearer TOKEN" \
    -d '{"path":"/absolute/path/inside/scan_root"}'
```

Watch progress:

```bash
curl -s http://127.0.0.1:5000/api/scanner/status
```

## One-shot CLI

```bash
deepsec scan /path/to/folder --role admin
deepsec signature-hash /suspicious/file   # compute SHA-256 for signature list
deepsec intel-update                      # pull MalwareBazaar + configured OTX pulses
deepsec watchdog start|stop|status        # real-time file monitor
deepsec report --days 30                  # compliance report as JSON
deepsec purge --days 90                   # enforce retention
```

## Docker

```bash
cp .env.example .env     # fill it in
docker compose -f deploy/docker-compose.yml up --build
```

The container runs as a non-root user, listens on `:5000`, and mounts
`./samples` read-only as the scan target. Adjust the bind mount in
`deploy/docker-compose.yml` to point at what you actually want to scan.

## Development

```bash
make dev-install   # installs deps + pre-commit hooks
make lint          # ruff
make format        # ruff format + fix
make typecheck     # mypy
make test          # pytest
make test-cov      # pytest with coverage (htmlcov/ report)
```

## Layout

```
deepsecurity/              Python package
  api/                     Flask blueprints
    auth / scanner /       operator-facing
    quarantine / audit /
    dlp / watchdog /       admin-facing
    intel / compliance /
    metrics / health       machine-facing (Prometheus + k8s probes)
  config.py                Settings (pydantic-settings, env-driven, validated)
  scanner.py               Signature + YARA + ML + entropy pipeline, DLP hook
  ml.py                    Joblib/sklearn wrapper, honest when disabled
  yara_engine.py           YARA rule compiler + matcher (optional dep)
  dlp.py                   Secret / PII regex engine with redaction
  watchdog_monitor.py      Real-time filesystem monitor (optional dep)
  outlook.py               Windows-only Outlook attachment scanner (opt-in)
  threat_intel.py          MalwareBazaar + OTX feed ingestion
  alerts.py                AlertBus + sinks (console/webhook/Slack/syslog/email)
  metrics.py               Prometheus counters / gauges / histograms
  compliance.py            Report generation + retention purge
  paths.py                 Path-traversal-safe resolution
  security_headers.py      CSP / HSTS / X-Frame-Options
  rate_limit.py            In-process sliding window + request-size cap
  db.py + models.py        SQLAlchemy setup + ORM (+ DLPFinding)
  audit.py                 Single audit-log entry point
  scan_state.py            Thread-safe in-process scan state
  logging_config.py        structlog (JSON or console)
  cli.py                   Click-based CLI entry point
tests/                     pytest suite (16 test files, 50+ cases)
deploy/                    Dockerfile + docker-compose.yml
.github/workflows/         CI (lint, test, build, pip-audit, gitleaks)
docs/                      ARCHITECTURE, SECURITY, THREAT_MODEL, OPERATIONS,
                           COMPLIANCE, REFACTOR_NOTES
frontend/                  Minimal React dashboard (Vite)
_legacy/                   Pre-refactor v2.0 code, kept for reference
```

## Security posture

- Authentication via short-lived JWTs. No dev fallback — a missing or invalid
  token returns 401. Full stop.
- Role-based authorisation at the route level (`admin`, `security`, `analyst`).
- Every user-supplied path is resolved under a configured `DEEPSEC_SCAN_ROOT`.
  Traversal attempts are rejected with 400.
- CORS is a pinned list of origins. `*` is explicitly forbidden by the config
  layer — the app refuses to start with a wildcard.
- Never automatic delete. The quarantine is a copy, the original stays.
  Permanent deletion requires an admin, a reason string, and is audit-logged.
- Secrets live in `.env` (gitignored) and are validated at startup (length,
  not-a-placeholder). No secret ever goes to the repo.
- Pinned dependency versions; pip-audit runs in CI.

## Licence

MIT — see `LICENSE`.
