# DEEPSecurity v2.2 — Test Operations Runbook

Hands-on test plan. Eight phases, ~2.5 hours end-to-end for a complete
pass. Each section is self-contained and says what to run, what to expect,
and what to check if it fails.

Every assertion in here is backed by code in the repo. When a test goes
red, the failure message + the audit log tell you which module broke.

> **Do every test in a disposable VM or on a machine you don't mind
> rebooting.** The watchdog, process-kill, and ransomware-rate tests all
> touch real system resources. None of these are destructive by default
> but it's easier to test fearlessly on a throwaway machine.

## Table of contents

1. [Prerequisites](#phase-0--prerequisites)
2. [Boot the server](#phase-1--boot-the-server-10-min)
3. [Auth + smoke test](#phase-2--authentication--smoke-test-5-min)
4. [Detection layer tests](#phase-3--detection-layer-tests-45-min)
5. [Response actions](#phase-4--response-actions-15-min)
6. [Self-integrity](#phase-5--self-integrity-10-min)
7. [SaaS + agent loop](#phase-6--saas--agent-loop-30-min)
8. [Failure injection](#phase-7--failure-injection-20-min)
9. [Cleanup + teardown](#phase-8--cleanup--teardown)
10. [Troubleshooting](#troubleshooting-cheat-sheet)

---

## Phase 0 — Prerequisites

Before any testing:

- **Python 3.11 or 3.12** (3.14 works for core but blocks the `[ml]` extra
  on Windows — check `python --version`).
- **A venv activated**, `.env` populated with real secrets, `deepsec init-db`
  has been run once on this machine.
- **Sample folder** — create one you're willing to throw detections at:
  ```cmd
  mkdir C:\Apps\DEEPSecurity_v2.0\samples
  ```
  Keep nothing valuable in here.
- **Second terminal** ready — one for the server, one for tests.

If you haven't done the bootstrap yet, run through `docs/SAAS_DEPLOY.md`
sections 1.1–2 first, then come back here.

---

## Phase 1 — Boot the server (10 min)

### Goal

Flask is up, database is healthy, every blueprint registered, the integrity
tripwire has a snapshot.

### Steps

```cmd
deepsec init-db
deepsec serve
```

You should see JSON log lines ending with:

```json
{"env": "development", "cors": [...], "event": "api.ready", ...}
{"host": "127.0.0.1", "port": 5000, "event": "serve.start", ...}
```

Server is listening on http://127.0.0.1:5000. Leave this running.

### Verify in a second terminal

```cmd
curl http://127.0.0.1:5000/
curl http://127.0.0.1:5000/healthz
curl http://127.0.0.1:5000/readyz
curl http://127.0.0.1:5000/metrics | findstr deepsec_
```

Expected:
- `/` returns the endpoint directory (JSON).
- `/healthz` → `{"status":"ok"}`.
- `/readyz` → `{"status":"ok","checks":{"database":"ok","scan_root":...}}`.
- `/metrics` prints lines starting with `deepsec_`.

If any of these fail, stop and fix Phase 1 before moving on.

### Take the integrity baseline

```cmd
deepsec serve  # already running; the boot_check ran at startup
```

Confirm in the server log you see:

```json
{"event": "integrity.boot_check", "status": "no_snapshot", ...}
```

That's expected on first boot. Take a snapshot now so subsequent tests
have a baseline:

```cmd
curl -s -X POST http://127.0.0.1:5000/api/system/integrity/snapshot ^
  -H "Authorization: Bearer %TOKEN%"
```

(You'll get `%TOKEN%` in Phase 2.)

---

## Phase 2 — Authentication + smoke test (5 min)

### Goal

Prove login works, the smoke test suite is all green, you have an
operator JWT to use for the rest of the tests.

### Steps

```cmd
deepsec self-test
```

Expected: `ALL GREEN   17 passed  0 failed  0 skipped`.

If you see any FAIL, read the detail column — it'll name the endpoint
and HTTP code. Stop and fix before proceeding.

### Grab a JWT for the rest of the tests

```cmd
> login.json echo {"username":"admin","password":"YOUR_PASSWORD"}
curl -s -X POST http://127.0.0.1:5000/api/auth/login ^
  -H "content-type: application/json" ^
  -d @login.json
```

Response:

```json
{"access_token": "eyJ...","role":"admin"}
```

Copy the token:

```cmd
set TOKEN=eyJ...paste_whole_thing...
```

All curl commands below use `%TOKEN%`.

### Sanity-check whoami

```cmd
curl -s -H "Authorization: Bearer %TOKEN%" http://127.0.0.1:5000/api/auth/whoami
```

Expected: `{"username":"admin","role":"admin"}`. If this fails, your token
or password is wrong — re-login.

---

## Phase 3 — Detection layer tests (45 min)

Nine detection surfaces, tested individually. For each one you'll write a
test artefact, scan it, and verify the expected label + MITRE tag. Each
sub-test takes ~5 minutes.

### 3.1 Signature — EICAR test file

EICAR is the industry-standard benign file that AVs flag as malicious for
testing. Known SHA-256:
`275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`.

```cmd
REM add the EICAR hash to your signature list
echo 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f >> data\signatures.txt

REM write the EICAR file itself
>samples\eicar.com.txt echo X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*

REM scan
curl -s -X POST http://127.0.0.1:5000/api/scanner/start ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "content-type: application/json" ^
  -d "{\"path\":\"C:/Apps/DEEPSecurity_v2.0/samples\"}"

REM wait ~5s, then check the most recent session
curl -s -H "Authorization: Bearer %TOKEN%" ^
  "http://127.0.0.1:5000/api/scanner/sessions?limit=1"
```

Grab the session id, then:

```cmd
curl -s -H "Authorization: Bearer %TOKEN%" ^
  "http://127.0.0.1:5000/api/scanner/results?session_id=1&label=malicious"
```

Expected: at least one row for `eicar.com.txt` with:
- `label: "malicious"`
- `reason` includes `signature_match`
- `file_status: "quarantined"`
- `quarantine_path` populated
- MITRE tag **T1588.001** in the detection reasons (via the server audit log)

Also check that the original is still at `samples/eicar.com.txt` (we copy,
never move) and a copy exists in `quarantine/`.

### 3.2 YARA — optional layer

Only works if you installed `yara-python`:

```cmd
pip install "yara-python>=4.5"
```

Create a trivial rule file:

```cmd
mkdir rules
>rules\test_eicar.yar echo rule eicar_pattern { strings: $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" condition: $a }
set DEEPSEC_YARA_RULES_DIR=C:\Apps\DEEPSecurity_v2.0\rules
```

Restart the server (env-var change). Re-scan the same path. Expected:
`reason` now includes `yara:eicar_pattern` on the EICAR file, T1027 in
tags.

### 3.3 Entropy + MIME whitelist

This is the test for the v1.0-working regression you must not reintroduce.

```cmd
REM high-entropy text → should be suspicious
python -c "import os; open('samples/weird.bin','wb').write(os.urandom(8192))"

REM high-entropy JPEG → should be clean (MIME whitelist skips entropy)
python -c "import os; open('samples/photo.jpg','wb').write(os.urandom(8192))"

REM scan
curl -s -X POST http://127.0.0.1:5000/api/scanner/start ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "content-type: application/json" ^
  -d "{\"path\":\"C:/Apps/DEEPSecurity_v2.0/samples\"}"
```

Expected (check results):
- `weird.bin` → `label: "suspicious"`, reason includes `entropy_spike(…)`,
  **not** quarantined.
- `photo.jpg` → `label: "clean"`, reason does **not** contain
  `entropy_spike`, because the MIME whitelist skipped entropy.

If `photo.jpg` got flagged as suspicious, you have the v1.0-working
regression. Stop and fix.

### 3.4 DLP — secrets in text files

```cmd
>samples\secrets.env echo DB_URL=postgresql://db.example.com/prod
>>samples\secrets.env echo AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
>>samples\secrets.env echo PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----
>>samples\secrets.env echo SSN=123-45-6789
>>samples\secrets.env echo support@example.com

REM scan
curl -s -X POST http://127.0.0.1:5000/api/scanner/start ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "content-type: application/json" ^
  -d "{\"path\":\"C:/Apps/DEEPSecurity_v2.0/samples\"}"

REM check DLP findings
curl -s -H "Authorization: Bearer %TOKEN%" ^
  "http://127.0.0.1:5000/api/dlp/findings?limit=50"
```

Expected: at least five findings:
- `aws_access_key_id` — severity `critical`, MITRE `T1552.001`
- `private_key_pem` — severity `critical`, MITRE `T1552.004`
- `us_ssn` — severity `medium`, MITRE `T1005`
- `email_address` — severity `low`, MITRE `T1005`

Every finding's `preview` field must contain `****` (redacted) and must
not contain the raw secret. If the raw `AKIAIOSFODNN7EXAMPLE` string leaks
through, DLP redaction is broken.

### 3.5 Process heuristics — CPU anomaly

```cmd
REM in a separate terminal, start a CPU-hog
python -c "while True: pass"
```

Leave it running. Back in the test terminal:

```cmd
curl -s -X POST http://127.0.0.1:5000/api/processes/scan ^
  -H "Authorization: Bearer %TOKEN%"
```

Expected: a row in the response with `label: "suspicious"`, name `python.exe`,
`cpu_percent` ≥ 80, reasons includes `high_cpu:…`, MITRE tag **T1496**.

Kill the CPU-hog Python (Ctrl+C) before continuing.

### 3.6 Process heuristics — LOLBin name

```cmd
REM copy cmd.exe to our samples with a flagged name
copy C:\Windows\System32\cmd.exe samples\mimikatz.exe

REM scan
curl -s -X POST http://127.0.0.1:5000/api/scanner/start ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "content-type: application/json" ^
  -d "{\"path\":\"C:/Apps/DEEPSecurity_v2.0/samples\"}"
```

Check the results — `mimikatz.exe` gets a signature check (probably clean
unless cmd.exe is in your sig list), BUT when it's *running* it triggers
the process scanner:

```cmd
samples\mimikatz.exe /c "timeout 30 >nul"
REM immediately, in the test terminal:
curl -s -X POST http://127.0.0.1:5000/api/processes/scan ^
  -H "Authorization: Bearer %TOKEN%"
```

Expected: a row for `mimikatz.exe` with `label: "suspicious"`, reason
`lolbin:mimikatz.exe`, tags **T1218** + **T1059**.

### 3.7 Ransomware rate detector

This is the noisy test. Make sure the watchdog is watching:

```cmd
curl -s -X POST http://127.0.0.1:5000/api/watchdog/start ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "content-type: application/json" ^
  -d "{\"path\":\"C:/Apps/DEEPSecurity_v2.0/samples\"}"
```

Now write files faster than the threshold (default 50/sec):

```cmd
python -c "import os,time; [open(f'samples/ransom_{i}.txt','w').write('x') for i in range(100)]; time.sleep(0.1)"
```

Within a few seconds check:

```cmd
curl -s -H "Authorization: Bearer %TOKEN%" ^
  "http://127.0.0.1:5000/api/audit?limit=5&action=ransomware.suspected"
```

Expected: one audit entry with action `ransomware.suspected`, severity
critical, details including `rate_per_second` > 50 and a candidate
`suspect` PID/name.

Also check your alert sinks — if you configured any in `.env` (Slack,
syslog, email), the test event should have landed there.

Stop the watchdog:

```cmd
curl -s -X POST http://127.0.0.1:5000/api/watchdog/stop ^
  -H "Authorization: Bearer %TOKEN%"
```

Clean up the ransom_* test files.

### 3.8 Network / IP reputation

This requires the abuse.ch feed to be loaded. First, update it:

```cmd
deepsec intel-update
```

Expected output: `abuse.ch/feodotracker: fetched=N  added=N` where N > 0.

Now list current connections and look for any remote IP that matches the
feed. Most test machines won't have any known-bad remotes, so this test
usually shows clean — which is the correct outcome.

```cmd
curl -s -H "Authorization: Bearer %TOKEN%" ^
  "http://127.0.0.1:5000/api/network/connections?state=ESTABLISHED"
```

Expected: a JSON object with:
- `total` ≥ 1 (you have connections)
- `known_bad_remotes` probably 0
- `reputation_size` > 0 (feed loaded)
- Every connection has a `reputation` field

To positively verify the lookup works, add a fake entry to the local cache
and confirm it matches:

```cmd
REM add one fake known-bad IP
echo 8.8.8.8 >> data\ip_reputation.txt
REM restart the server so the cache reloads
REM then ping 8.8.8.8 to open a connection
ping 8.8.8.8

curl -s -H "Authorization: Bearer %TOKEN%" ^
  "http://127.0.0.1:5000/api/network/connections?state=ESTABLISHED" | findstr 8.8.8.8
```

You should see the connection to 8.8.8.8 with `"reputation":{"known_bad":true,...}`.

**Remove the 8.8.8.8 entry afterward** — it's Google DNS, not actually malicious.

### 3.9 Detection summary — what you've just proved

Eight out of nine detection surfaces tested with controlled, reproducible
artefacts. The ninth (ML) is honestly disabled unless you've trained and
configured a model. Every result has a MITRE tag, every action is
audit-logged.

Now run:

```cmd
curl -s -H "Authorization: Bearer %TOKEN%" "http://127.0.0.1:5000/api/audit?limit=30"
```

You should see a walk through the last 30 minutes of tests: scan.start,
scan.finish, process.flagged, ransomware.suspected, etc.

---

## Phase 4 — Response actions (15 min)

### 4.1 Quarantine round-trip

From Phase 3.1 you have `eicar.com.txt` in quarantine. Confirm:

```cmd
curl -s -H "Authorization: Bearer %TOKEN%" http://127.0.0.1:5000/api/quarantine/list
```

Pick one `name`, then restore it:

```cmd
curl -s -X POST http://127.0.0.1:5000/api/quarantine/restore ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "content-type: application/json" ^
  -d "{\"name\":\"<paste>\",\"original_path\":\"C:/Apps/DEEPSecurity_v2.0/samples/restored_eicar.com.txt\"}"
```

Expected: `{"restored":true,"path":"..."}`. Check `samples/` — the
restored file is there. Check `quarantine/` — the copy is gone (restore
moves, not copies).

### 4.2 Permanent delete (with required reason)

Re-scan to get a fresh quarantine entry. Then:

```cmd
REM without reason — should 400
curl -s -X POST http://127.0.0.1:5000/api/quarantine/delete ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "content-type: application/json" ^
  -d "{\"name\":\"<paste>\"}"
```

Expected: HTTP 400 `{"error":"reason_required"}`. Good — we refuse
destructive action without explanation.

```cmd
REM with reason — should succeed
curl -s -X POST http://127.0.0.1:5000/api/quarantine/delete ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "content-type: application/json" ^
  -d "{\"name\":\"<paste>\",\"reason\":\"verified malicious by analyst\"}"
```

Expected: `{"deleted":true,"sha256":"..."}`. Check the audit log — an
entry with action `quarantine.delete`, your reason, your actor name.

### 4.3 Process kill

Start a harmless long-running process:

```cmd
start /B python -c "import time; time.sleep(120)"
REM note the PID from Task Manager or:
tasklist /FI "IMAGENAME eq python.exe"
```

Then terminate it via the API:

```cmd
curl -s -X POST http://127.0.0.1:5000/api/processes/kill ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "content-type: application/json" ^
  -d "{\"pid\":<PID>,\"reason\":\"test run\"}"
```

Expected: `{"killed":true,"pid":<PID>,"name":"python.exe","force":false}`.

`tasklist` confirms the process is gone. Audit log shows
`process.kill` with your reason.

If you get `access_denied`, you need to run the server as admin — that's
an honest limit, not a bug.

### 4.4 Session rollback

Run a fresh scan that quarantines multiple files. Then bulk-restore:

```cmd
curl -s -X POST http://127.0.0.1:5000/api/quarantine/restore-session ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "content-type: application/json" ^
  -d "{\"session_id\":<id>}"
```

Expected: `{"session_id":<id>,"restored":N,"missing":0,"failed":0,"items":[...]}`.
Every quarantined file from that scan is back in place.

---

## Phase 5 — Self-integrity (10 min)

### 5.1 Baseline

```cmd
curl -s -H "Authorization: Bearer %TOKEN%" http://127.0.0.1:5000/api/system/integrity
```

Expected: `status: "ok"` (if you took the snapshot in Phase 1).

### 5.2 Simulate tampering

Open any file under `deepsecurity\` and add a comment:

```cmd
echo # test tamper >> deepsecurity\scanner.py
```

Re-check:

```cmd
curl -s -H "Authorization: Bearer %TOKEN%" http://127.0.0.1:5000/api/system/integrity
```

Expected: `status: "tampered"`, `mismatched` contains
`"deepsecurity/scanner.py"`.

### 5.3 Simulate boot-time alert

Restart the server:

```cmd
REM Ctrl+C the server, then
deepsec serve
```

In the log you should see a critical alert:

```json
{
  "event": "integrity.boot_check",
  "status": "tampered",
  "mismatched": 1,
  ...
}
```

And if you have an alert sink configured, a `integrity.tampered` event
should have fired.

### 5.4 Recover

Undo the comment you added (`git checkout deepsecurity/scanner.py` or
delete the line). Re-snapshot:

```cmd
curl -s -X POST http://127.0.0.1:5000/api/system/integrity/snapshot ^
  -H "Authorization: Bearer %TOKEN%"
```

Recheck — should be `ok` again.

---

## Phase 6 — SaaS + agent loop (30 min)

Skip this phase if you're only testing the single-node deployment.

### 6.1 Enrol an agent

```cmd
curl -s -X POST http://127.0.0.1:5000/api/agents/enrol ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "content-type: application/json" ^
  -d "{\"label\":\"local-test\",\"ttl_hours\":1}"
```

Copy the `enrolment_token`.

### 6.2 Register the agent against the same server

In a **second** terminal (venv activated):

```cmd
deepsec-agent register --server http://127.0.0.1:5000 --token <paste>
deepsec-agent status
```

Expected: `heartbeat: ok`. A `~/.deepsec-agent/config.json` appears.

### 6.3 Run the agent loop

```cmd
deepsec-agent run
```

Agent heartbeats every 30s. In the server log you'll see
`agent.registered` once, then periodic requests against
`/api/agents/heartbeat` and `/api/agents/commands`.

### 6.4 Queue a command for it

List agents first:

```cmd
curl -s -H "Authorization: Bearer %TOKEN%" http://127.0.0.1:5000/api/agents
```

Copy the `id`. Then queue a self-test:

```cmd
curl -s -X POST http://127.0.0.1:5000/api/agents/<AGENT_ID>/commands ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "content-type: application/json" ^
  -d "{\"kind\":\"self_test\",\"payload\":{}}"
```

Within 30 seconds the agent terminal shows it picked up the command and
posted a result. In the audit log:

```cmd
curl -s -H "Authorization: Bearer %TOKEN%" ^
  "http://127.0.0.1:5000/api/audit?actor=agent:<AGENT_ID>&limit=10"
```

Expected: rows showing `agent.registered`, `agent.command_ok`.

### 6.5 Queue a scan command

```cmd
curl -s -X POST http://127.0.0.1:5000/api/agents/<AGENT_ID>/commands ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "content-type: application/json" ^
  -d "{\"kind\":\"scan\",\"payload\":{\"path\":\"C:/Apps/DEEPSecurity_v2.0/samples\"}}"
```

Agent runs the scan locally, quarantines locally, reports summary back.
Confirm:
- Quarantine files are on the agent's machine (same machine here, but
  in production they'd be on a laptop somewhere else)
- Scan results in the server's `scan_sessions` / `scan_results` tables
- Audit trail of the whole lifecycle

### 6.6 Revoke the agent

```cmd
curl -s -X DELETE http://127.0.0.1:5000/api/agents/<AGENT_ID> ^
  -H "Authorization: Bearer %TOKEN%"
```

Expected: `{"revoked":true,...}`. Next agent heartbeat returns 401,
agent gets kicked out cleanly.

---

## Phase 7 — Failure injection (20 min)

Stress-test what happens when things go wrong.

### 7.1 Unauthenticated → 401

```cmd
curl -s -o nul -w "%%{http_code}\n" http://127.0.0.1:5000/api/scanner/start
```

Expected: `401`. If this returns anything else, auth is broken.

### 7.2 Bad JWT → 401

```cmd
curl -s -o nul -w "%%{http_code}\n" -H "Authorization: Bearer not_a_real_token" ^
  http://127.0.0.1:5000/api/scanner/sessions
```

Expected: `401`.

### 7.3 Path traversal → 400

```cmd
curl -s -X POST http://127.0.0.1:5000/api/scanner/start ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "content-type: application/json" ^
  -d "{\"path\":\"../../etc/passwd\"}"
```

Expected: HTTP 400, `{"error":"path_outside_scan_root",...}`.

(If you've set `DEEPSEC_SCAN_ROOT` = empty, you're in permissive mode and
only RELATIVE paths are rejected. Test with a relative path like
`"../foo"` in that case.)

### 7.4 Rate limit → 429

Fire 50 anonymous requests rapidly:

```cmd
for /L %i in (1,1,50) do @curl -s -o nul -w "%%{http_code} " http://127.0.0.1:5000/api/scanner/status
```

Expected: first ~30 responses are 200, then 429. The `Retry-After`
header appears in the 429 responses.

### 7.5 Request too large → 413

```cmd
python -c "print('{\"path\":\"' + 'x'*20000000 + '\"}')" > big.json
curl -s -o nul -w "%%{http_code}\n" -X POST http://127.0.0.1:5000/api/scanner/start ^
  -H "Authorization: Bearer %TOKEN%" ^
  -H "content-type: application/json" ^
  -d @big.json
del big.json
```

Expected: HTTP 413. `DEEPSEC_MAX_REQUEST_BYTES` (default 10 MiB) protects
the server from unbounded uploads.

### 7.6 DB disappears → graceful 5xx

While the server is running:

```cmd
REM on Windows this usually fails because SQLite locks the file —
REM on Linux you can rename it. This test is only meaningful on Linux.
mv data/deepscan.db data/deepscan.db.testmove
curl -s http://127.0.0.1:5000/readyz
mv data/deepscan.db.testmove data/deepscan.db
```

Expected: `/readyz` returns 503 with
`"database":"error: OperationalError"`. `/healthz` still 200 (liveness
separate from readiness). After the file is back, `/readyz` is 200 again
within a second.

### 7.7 Agent network loss → backoff + reconnect

With the agent running (`deepsec-agent run`), stop the server:

```cmd
REM Ctrl+C the server
```

Agent log shows:

```
{"event": "agent.heartbeat_failed", ..., "backoff": 1.0}
{"event": "agent.heartbeat_failed", ..., "backoff": 2.0}
{"event": "agent.heartbeat_failed", ..., "backoff": 4.0}
```

Start the server again. Within the next backoff window the agent
reconnects transparently:

```
{"event": "agent.heartbeat", "status": "ok"}
```

No crash, no manual restart needed.

---

## Phase 8 — Cleanup + teardown

Reset the test environment to a known state.

### 8.1 Drop all test data

```cmd
deepsec reset-db --yes
```

Confirms dropped + recreated. Every Phase 1-7 artefact is gone.

### 8.2 Clear quarantine

```cmd
del /Q quarantine\*
```

### 8.3 Clear test artefacts from samples

```cmd
del /Q samples\eicar*
del /Q samples\ransom_*
del /Q samples\weird.bin
del /Q samples\photo.jpg
del /Q samples\secrets.env
del /Q samples\mimikatz.exe
del /Q samples\restored_*
```

### 8.4 Remove EICAR hash from signatures

```cmd
REM edit data\signatures.txt, remove the 275a021b... line
notepad data\signatures.txt
```

### 8.5 Unregister any test agents

```cmd
curl -s -H "Authorization: Bearer %TOKEN%" http://127.0.0.1:5000/api/agents
REM for each id with label "local-test":
curl -s -X DELETE http://127.0.0.1:5000/api/agents/<id> ^
  -H "Authorization: Bearer %TOKEN%"
```

### 8.6 Reset integrity snapshot

```cmd
curl -s -X POST http://127.0.0.1:5000/api/system/integrity/snapshot ^
  -H "Authorization: Bearer %TOKEN%"
```

### 8.7 Stop services

Server: Ctrl+C in its terminal.
Agent:  Ctrl+C in its terminal.

You're back to a clean slate.

---

## Pass criteria — what "tested" means

A complete green pass of this runbook means you've verified:

- [ ] Server boots clean, all probes green
- [ ] Operator JWT auth works; no fallback identity exists
- [ ] Signature detection fires on a known hash
- [ ] YARA fires on a rule match (if the extra is installed)
- [ ] Entropy flags non-media high-entropy files; **does not** flag media
- [ ] DLP catches every pattern severity with redacted previews
- [ ] Process heuristics flag CPU-anomaly and LOLBin names
- [ ] Ransomware rate detector fires + alerts on >50 writes/sec
- [ ] Network panel shows reputation against the abuse.ch feed
- [ ] Quarantine round-trip (restore) works
- [ ] Permanent delete requires a reason
- [ ] Process kill succeeds with admin, fails honestly without
- [ ] Session rollback restores every file in a scan
- [ ] Self-integrity detects tampering and alerts on boot
- [ ] Agent can register, heartbeat, pull commands, execute, report
- [ ] Agent survives server outage and reconnects with backoff
- [ ] 401 / 403 / 400 / 429 / 413 all return their correct codes
- [ ] Audit log contains every state-changing action with actor, action,
      status, reason, MITRE tag

Any unchecked box is a regression to fix before calling this version
shippable.

---

## Troubleshooting cheat sheet

| Symptom | Likely cause | Fix |
|---|---|---|
| `deepsec: not found` | venv not activated | `.venv\Scripts\activate.bat` |
| Server crashes on boot with `ValidationError` | placeholder secret in `.env` | `deepsec init-env --force` |
| `/api/auth/login` returns 503 | `DEEPSEC_DEV_PASSWORD` empty | set it in `.env` and restart |
| All protected routes 401 with valid token | token from a pre-rotation session | re-login |
| Scanner returns 400 `path_outside_scan_root` | `DEEPSEC_SCAN_ROOT` set but target outside it | clear the var or widen it |
| Self-test `OperationalError: no such column` | DB is from pre-upgrade schema | `deepsec reset-db --yes` |
| Watchdog says "not available" | `watchdog` extra not installed | `pip install "deepsecurity[watchdog]"` |
| YARA says "disabled" | no rule files, or `yara-python` missing | drop `.yar` into `DEEPSEC_YARA_RULES_DIR` |
| Process kill returns `access_denied` | server not running as admin | run as admin or accept the limit |
| Ransomware test doesn't fire | watchdog not running or threshold too high | start watchdog, check `DEEPSEC_RANSOMWARE_RATE_THRESHOLD` |
| Agent won't register | enrolment token expired or reused | issue a fresh one via `/api/agents/enrol` |

If something breaks that isn't on this list, paste the server log + the
curl command that triggered it, and I'll fix the code.
