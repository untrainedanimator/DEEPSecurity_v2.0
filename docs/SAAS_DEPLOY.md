# Deploying DEEPSecurity as a SaaS

The SaaS build puts the DEEPSecurity control plane in the cloud and runs a
lightweight **agent** on each laptop. The agent does the scanning locally
(file / process / network) and reports results up; the cloud server holds
the dashboard, audit history, and command queue.

## Architecture

```
           ┌────────────────────────────────────────┐
           │          SaaS control plane            │
           │                                        │
 laptop A  │   Caddy ──► Flask API ──► PostgreSQL   │
 laptop B  │                ▲                       │
 laptop C  │                │ agent commands        │
           │                │ heartbeats / events   │
           └────────────────┴───────────────────────┘
                           ▲
                           │ HTTPS
     ┌─────────────────────┴─────────────────────┐
     │                                           │
     ▼                                           ▼
┌──────────┐                              ┌──────────┐
│ agent A  │                              │ agent B  │
│ scans    │   ... up to N laptops ...    │ scans    │
│ kills    │                              │ watchdog │
│ reports  │                              │ reports  │
└──────────┘                              └──────────┘
```

- Server = your VPS.
- Each agent = one `deepsec-agent run` loop on one laptop.
- Transport = HTTPS with two auth paths: operator JWT for the dashboard,
  long-lived API key for each agent.
- Enrolment = one-time token issued by the operator, burned on first use.

## Part 1 — Stand up the cloud server

You need:
- A VPS with ≥ 2 GB RAM, Docker and docker-compose installed.
- A domain (or subdomain) pointed at the VPS's public IP.
- Port 80 and 443 open.

### 1.1  Generate secrets locally

```bash
python -c "import secrets; print('DEEPSEC_SECRET_KEY=' + secrets.token_hex(32))"
python -c "import secrets; print('DEEPSEC_JWT_SECRET=' + secrets.token_hex(32))"
python -c "import secrets; print('POSTGRES_PASSWORD=' + secrets.token_urlsafe(32))"
python -c "import secrets; print('DEEPSEC_DEV_PASSWORD=' + secrets.token_urlsafe(18))"
```

### 1.2  On the VPS

```bash
git clone https://github.com/your-account/deepsecurity.git
cd deepsecurity
cp deploy/saas/.env.saas.example deploy/saas/.env

# Edit deploy/saas/.env with everything you generated + your domain + email.
# Then:
docker compose -f deploy/saas/docker-compose.yml --env-file deploy/saas/.env up -d
```

Caddy will obtain a Let's Encrypt cert on first request. Wait ~30 s, then:

```bash
curl https://deepsec.example.com/healthz   # → {"status":"ok"}
curl https://deepsec.example.com/readyz    # → checks DB + scan_root (permissive in SaaS)
```

Log in to the dashboard at `https://deepsec.example.com/` with
`DEEPSEC_DEV_USER` + `DEEPSEC_DEV_PASSWORD` from your env file.

## Part 2 — Enrol each laptop

### 2.1  Issue an enrolment token (operator, once per laptop)

From the dashboard (Agents tab → **New enrolment token**) or via API:

```bash
TOKEN_RESP=$(curl -s -X POST https://deepsec.example.com/api/agents/enrol \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"label": "dino-thinkpad", "ttl_hours": 24}')
echo "$TOKEN_RESP" | jq -r .enrolment_token
# → prints the token exactly once. Copy it securely to the laptop.
```

### 2.2  Install the agent on each laptop

Pip-install the package on the laptop:

```bash
pip install "deepsecurity"                # once published to PyPI
# or, in the interim:
pip install git+https://github.com/your-account/deepsecurity.git
```

### 2.3  Register

```bash
deepsec-agent register \
  --server https://deepsec.example.com \
  --token  <paste-the-enrolment-token>
```

The agent phones home, exchanges the token for a permanent API key, and
writes `~/.deepsec-agent/config.json`.

### 2.4  Run the loop

For a quick test:

```bash
deepsec-agent run
```

For production on the laptop, install as a service so it starts on boot:

**Windows (as Administrator):**

```cmd
nssm install deepsec-agent "C:\Path\to\deepsec-agent.exe" run
nssm start  deepsec-agent
```

**Linux (systemd):**

```bash
sudo tee /etc/systemd/system/deepsec-agent.service > /dev/null <<'EOF'
[Unit]
Description=DEEPSecurity endpoint agent
After=network-online.target
[Service]
Type=simple
User=deepsec
ExecStart=/usr/local/bin/deepsec-agent run
Restart=on-failure
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now deepsec-agent
```

**macOS (launchd):** see `deploy/agent/com.deepsecurity.agent.plist`
(next turn — simple plist, similar shape).

### 2.5  Verify

```bash
deepsec-agent status
# → heartbeat: ok
```

In the dashboard, the laptop appears in the **Agents** tab with its last
heartbeat timestamp, OS, hostname, and labels.

## Part 3 — Drive an agent from the dashboard

Queue a scan on a specific agent:

```bash
curl -X POST https://deepsec.example.com/api/agents/<AGENT_ID>/commands \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"kind":"scan","payload":{"path":"C:\\Apps\\Imgs2"}}'
```

Supported `kind` values:

| kind | payload | what it does |
|---|---|---|
| `scan` | `{path, quarantine?}` | full directory scan on the agent |
| `kill` | `{pid, force?}` | terminate a process on the agent |
| `watchdog_start` | `{scope?, paths?}` | start the real-time watcher |
| `watchdog_stop` | `{}` | stop the watcher |
| `processes_scan` | `{}` | scan every visible process, report verdicts |
| `self_test` | `{}` | alive-check |
| `intel_update` | `{}` | refresh signature / IP reputation feeds on that agent |

The agent picks up the command on its next poll (≤ 30 s by default),
executes it locally, and POSTs the result back. You see it in the command
history tied to that agent.

## Security notes

- Agent API keys are long-lived. Rotate by revoking the agent (operator)
  and re-registering. Roadmap: automatic periodic rotation.
- Enrolment tokens are one-time, short-lived, and audit-logged.
- All agent ↔ server traffic is HTTPS. Caddy terminates TLS; the Flask
  app itself only listens internally.
- The SaaS server has `DEEPSEC_SCAN_ROOT=""` — it never scans its own
  disk. All scanning happens on agents, on files operators cannot read
  directly from the server.
- Tighter rate limits in production (`10/min` anon, `300/min` auth) defend
  the public endpoint against enrolment-token brute force.

## What's still user-space

Everything in `docs/THREAT_MODEL.md` applies per agent. The agent sees
what `psutil` and the OS file-system API show. It is not an EDR even
when deployed as SaaS.
