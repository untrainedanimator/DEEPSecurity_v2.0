# Deploying DEEPSecurity SaaS on Render.com

Simpler than a VPS, one-click from a `render.yaml` blueprint, costs
~$7.25/month. Good fit for a 1-month trial or an MVP.

## What you get

- HTTPS out of the box (Render provisions the cert).
- Custom domain (`app.deepsjvb.net`) after one CNAME.
- Git-push deploys with zero downtime.
- A 1 GB persistent disk that survives redeploys.
- `/healthz` wired up as the platform's liveness check.

## Step-by-step

### 1. Get your repo on GitHub

```bash
git init
git add .
git commit -m "initial"
git branch -M main
git remote add origin https://github.com/your-account/deepsecurity.git
git push -u origin main
```

### 2. Connect Render

1. Sign up / log in at **render.com**.
2. Click **New → Blueprint**.
3. Authorise Render to read your GitHub.
4. Pick the `deepsecurity` repo. Render will read `render.yaml` and show
   you the service plan + disk + env vars it's about to create.
5. Fill in the two env vars marked "sync: false":
   - `DEEPSEC_DEV_PASSWORD`: the admin login password (generate with
     `python -c "import secrets; print(secrets.token_urlsafe(18))"`)
   - `DEEPSEC_CORS_ORIGINS`: leave blank for now, we fill it after step 3.
6. Click **Apply**. Render builds `deploy/Dockerfile`, provisions the
   disk, and boots. Takes 3–5 minutes.

### 3. First smoke test

Render gives you a URL like `https://deepsecurity.onrender.com`. Hit:

```bash
curl https://deepsecurity.onrender.com/healthz
curl https://deepsecurity.onrender.com/readyz
```

Both should be 200 OK. `/readyz` tells you DB and scan-root state.

Now go back to the service in Render's UI and set:

```
DEEPSEC_CORS_ORIGINS=https://deepsecurity.onrender.com
```

Save → service redeploys (~30 s).

### 4. Wire your custom domain

In **Settings → Custom Domains** on Render:

```
app.deepsjvb.net
```

Render shows a CNAME target like `deepsecurity.onrender.com`. Go to
Hostinger → your DNS panel for `deepsjvb.net`:

```
Type   Name   Value                          TTL
CNAME  app    deepsecurity.onrender.com      300
```

Within 5 minutes `https://app.deepsjvb.net` is live and Render has
auto-issued a Let's Encrypt cert for it.

Update `DEEPSEC_CORS_ORIGINS` in Render to include both origins:

```
https://deepsecurity.onrender.com,https://app.deepsjvb.net
```

Save → service redeploys.

### 5. Initialise the database

Render's shell (under **Shell** in the service's sidebar):

```bash
deepsec init-db
```

This creates every table including the agent ones. One-time.

### 6. Log in as operator

```bash
curl -s -X POST https://app.deepsjvb.net/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"YOUR_PASSWORD"}'
```

Copy the `access_token`.

### 7. Enrol your first laptop

```bash
# Issue an enrolment token (operator-side, uses your JWT)
curl -s -X POST https://app.deepsjvb.net/api/agents/enrol \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"label":"laptop-1","ttl_hours":24}'
# → {"enrolment_token":"...","ttl_hours":24}
```

On that laptop:

```powershell
pip install git+https://github.com/your-account/deepsecurity.git
deepsec-agent register --server https://app.deepsjvb.net --token <TOKEN>
deepsec-agent status    # heartbeat: ok
deepsec-agent run       # main loop; run as service for production
```

### 8. Drive a scan remotely

```bash
curl -X POST https://app.deepsjvb.net/api/agents/<AGENT_ID>/commands \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"kind":"self_test","payload":{}}'
```

Within 30 seconds the agent picks up the command, executes it locally,
and posts the result back. Verify via the dashboard → Audit tab.

## Cost dashboard

- Starter web service: **$7.00/mo**
- 1 GB persistent disk: **$0.25/mo**
- **Total: ~$7.25/mo** for a single-region, single-replica SaaS.

Upgrade paths if you decide to keep going:
- Web service Standard (2 GB RAM): +$18/mo
- Managed Postgres Starter: +$7/mo (replaces SQLite)
- Second region for redundancy: 2x the web-service cost
- Render's $20/month Pro plan: unnecessary for this workload

## Tearing down after the trial

If you decide not to continue:

1. **Settings → Delete Service** in Render. Confirms twice.
2. Remove the `CNAME app` record from Hostinger DNS.
3. Billing stops at the end of the current period (Render prorates nothing).

Nothing left on a box, no services left running, clean finish.

## Migrating to a VPS later

If you decide to keep the tool and want the cost savings:

1. Spin up Hetzner CX22 (€3.79/mo) or similar.
2. Follow `docs/SAAS_DEPLOY.md` — it's the same Dockerfile.
3. In Hostinger DNS, flip the `app` record from CNAME→Render to A→VPS-IP.
4. Once DNS propagates (5 min), delete the Render service.

Your agents keep working through the DNS flip — they reconnect to the
new IP transparently, assuming the old URL (`app.deepsjvb.net`) stays
constant.
