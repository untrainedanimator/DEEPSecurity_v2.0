import { useEffect, useState } from 'react'

// ---------------------------------------------------------------------------
// SinksPanel — two distinct sink families on one screen.
//
// 1. Alert sinks (existing) — where critical + high-severity DETECTIONS
//    fan out: Slack, email, webhook, syslog, console. Test button fires a
//    synthetic info-level event through every enabled channel.
//
// 2. Audit-log replication (v3.0) — every audit event copies to an external
//    WORM-style sink so the trail survives a local DB wipe. Required for
//    SOC2 Type II evidence retention. Configured via DEEPSEC_AUDIT_SINK_*
//    env vars.
//
// Both share a tab because operators usually configure them in the same
// .env edit. The data sources are different though: /api/sinks/status for
// alerts, /api/v3/status (audit_sinks key) for audit replication.
// ---------------------------------------------------------------------------

export default function SinksPanel({ token }) {
  const [alertSinks, setAlertSinks] = useState([])
  const [auditSinks, setAuditSinks] = useState(null)
  const [msg, setMsg] = useState('')

  const refresh = async () => {
    try {
      const r = await fetch('/api/sinks/status', {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (r.ok) setAlertSinks((await r.json()).sinks || [])
    } catch (e) {
      // leave alertSinks unchanged on transient failure
    }
    try {
      const r = await fetch('/api/v3/status', {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (r.ok) {
        const data = await r.json()
        setAuditSinks(data.audit_sinks || null)
      }
    } catch (e) {
      // audit-sink read is best-effort — keep showing the previous state
    }
  }

  useEffect(() => {
    refresh()
    // Light auto-refresh so queue depth + drop count stay live.
    const id = setInterval(refresh, 5000)
    return () => clearInterval(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const testFire = async () => {
    setMsg('')
    const r = await fetch('/api/sinks/test', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    })
    const body = await r.json()
    setMsg(
      body.dispatched
        ? 'test event dispatched — check your Slack / webhook / syslog / email'
        : JSON.stringify(body)
    )
  }

  const queueWarn =
    auditSinks?.configured &&
    typeof auditSinks.queue_size === 'number' &&
    typeof auditSinks.queue_max === 'number' &&
    auditSinks.queue_size > auditSinks.queue_max * 0.5

  return (
    <div className="sinks-panel">
      {/* ===== Alert sinks ===== */}
      <h2>Alert sinks</h2>
      <div className="scan-hint">
        Where critical + high-severity <strong>detections</strong> get
        forwarded. Configure each via <code>.env</code>; the{' '}
        <strong>test</strong> button fires a synthetic info-level event
        through every enabled sink so you can verify the plumbing without
        waiting for a real detection.
      </div>

      <table className="dlp-table">
        <thead>
          <tr>
            <th>sink</th>
            <th>enabled</th>
            <th>detail</th>
          </tr>
        </thead>
        <tbody>
          {alertSinks.map((s) => (
            <tr key={s.name}>
              <td>
                <code>{s.name}</code>
              </td>
              <td>
                <span className={`pill ${s.enabled ? 'pill-ok' : 'pill-sev-low'}`}>
                  {s.enabled ? 'enabled' : 'not configured'}
                </span>
              </td>
              <td className="dim">{s.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div style={{ marginTop: 14 }}>
        <button className="btn-refresh" onClick={testFire}>
          send test event
        </button>
        <button className="btn-refresh" onClick={refresh} style={{ marginLeft: 8 }}>
          refresh
        </button>
      </div>
      {msg && (
        <div className="scan-message" style={{ marginTop: 10 }}>
          {msg}
        </div>
      )}

      {/* ===== Audit-log replication (v3.0) ===== */}
      <h2 style={{ marginTop: 36 }}>Audit-log replication</h2>
      <div className="scan-hint">
        v3.0 — every <strong>audit event</strong> (every action, by every
        actor) is also streamed to one or more external sinks for tamper-
        evident retention. Required for SOC2 Type II evidence preservation.
        This stream is independent of the alert sinks above and uses
        separate <code>DEEPSEC_AUDIT_SINK_*</code> env vars.
      </div>

      {!auditSinks ? (
        <div className="scan-message" style={{ marginTop: 12 }}>
          /api/v3/status not reachable — the v3 endpoint may not be up yet.
        </div>
      ) : !auditSinks.configured ? (
        <div
          style={{
            marginTop: 14,
            padding: '12px 14px',
            background: 'var(--surface)',
            border: '1px solid var(--border)',
            borderLeft: '3px solid var(--warn)',
            borderRadius: 6,
          }}
        >
          <div style={{ marginBottom: 6 }}>
            <span className="pill pill-sev-low">not configured</span>
          </div>
          <div className="dim" style={{ fontSize: 13, lineHeight: 1.6 }}>
            Audit events are persisting locally (DB + stdout) but not
            replicating externally. To enable, set any combination of:
            <ul style={{ marginTop: 6, marginBottom: 0, paddingLeft: 20 }}>
              <li>
                <code>DEEPSEC_AUDIT_SINK_WEBHOOK_URL</code> — HTTPS POST to
                a SIEM/collector
              </li>
              <li>
                <code>DEEPSEC_AUDIT_SINK_SYSLOG_HOST</code> +{' '}
                <code>_SYSLOG_PORT</code> +{' '}
                <code>_SYSLOG_PROTOCOL</code> (default UDP/514)
              </li>
              <li>
                <code>DEEPSEC_AUDIT_SINK_FILE_PATH</code> — append-only
                JSONL with daily rotation, ideal for a separate volume
              </li>
            </ul>
            <div style={{ marginTop: 8 }}>
              Then restart: <code>deepsecurity stop &amp;&amp; deepsecurity start</code>.
            </div>
          </div>
        </div>
      ) : (
        <table className="dlp-table" style={{ marginTop: 8 }}>
          <thead>
            <tr>
              <th>property</th>
              <th>value</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>
                <code>configured sinks</code>
              </td>
              <td>
                {(auditSinks.sinks || []).map((s) => (
                  <span
                    key={s}
                    className="pill pill-ok"
                    style={{ marginRight: 6 }}
                  >
                    {s}
                  </span>
                ))}
              </td>
            </tr>
            <tr>
              <td>
                <code>queue depth</code>
              </td>
              <td className={queueWarn ? '' : 'dim'} style={queueWarn ? { color: 'var(--warn)' } : undefined}>
                {auditSinks.queue_size} / {auditSinks.queue_max}
              </td>
            </tr>
            <tr>
              <td>
                <code>batch size</code>
              </td>
              <td className="dim">{auditSinks.batch_size}</td>
            </tr>
            <tr>
              <td>
                <code>flush interval</code>
              </td>
              <td className="dim">{auditSinks.flush_interval_s}s</td>
            </tr>
            <tr>
              <td>
                <code>dropped (lifetime)</code>
              </td>
              <td
                style={{
                  color:
                    auditSinks.dropped > 0 ? 'var(--bad)' : 'var(--good)',
                }}
              >
                {auditSinks.dropped}
              </td>
            </tr>
          </tbody>
        </table>
      )}
    </div>
  )
}
