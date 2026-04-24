import { useEffect, useState } from 'react'

const fmt = (n) => {
  if (!n && n !== 0) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(1)} ${units[i]}`
}

const integrityPill = (status) =>
  status === 'ok'
    ? 'pill-ok'
    : status === 'tampered'
    ? 'pill-sev-critical'
    : status === 'no_snapshot'
    ? 'pill-sev-low'
    : 'pill-sev-medium'

export default function SystemPanel({ token }) {
  const [data, setData] = useState(null)
  const [top, setTop] = useState([])
  const [integrity, setIntegrity] = useState(null)
  const [snapMsg, setSnapMsg] = useState('')

  const refresh = async () => {
    try {
      const [s, t, i] = await Promise.all([
        fetch('/api/system/summary', { headers: { Authorization: `Bearer ${token}` } }),
        fetch('/api/system/top', { headers: { Authorization: `Bearer ${token}` } }),
        fetch('/api/system/integrity', { headers: { Authorization: `Bearer ${token}` } }),
      ])
      if (s.ok) setData(await s.json())
      if (t.ok) setTop((await t.json()).processes)
      if (i.ok) setIntegrity(await i.json())
    } catch {
      /* noop */
    }
  }

  useEffect(() => {
    refresh()
    const id = setInterval(refresh, 3000)
    return () => clearInterval(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const takeSnapshot = async () => {
    setSnapMsg('')
    const r = await fetch('/api/system/integrity/snapshot', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    })
    const body = await r.json()
    if (r.ok) {
      setSnapMsg(
        `snapshot saved: ${body.total_files} files fingerprinted at ${body.snapshot_at}`
      )
      setIntegrity(body)
    } else {
      setSnapMsg(body.error || `HTTP ${r.status}`)
    }
  }

  if (!data) return <div>loading…</div>

  const p = data.process
  const s = data.system

  return (
    <div className="system-panel">
      <h2>System</h2>
      <div className="scan-hint">
        Process column = DEEPSecurity only. System column = whole OS. A high
        system CPU that isn&apos;t ours means the load is elsewhere.
      </div>

      <div className="sys-grid">
        <div className="sys-card">
          <h3>DEEPSecurity process</h3>
          <dl className="sys-kv">
            <dt>PID</dt><dd>{p.pid}</dd>
            <dt>CPU</dt><dd>{p.cpu_percent}%</dd>
            <dt>RSS</dt><dd>{fmt(p.rss_bytes)}</dd>
            <dt>Threads</dt><dd>{p.threads}</dd>
            <dt>Open files</dt><dd>{p.open_files}</dd>
            <dt>Open sockets</dt><dd>{p.open_sockets}</dd>
          </dl>
        </div>
        <div className="sys-card">
          <h3>System</h3>
          <dl className="sys-kv">
            <dt>CPU</dt><dd>{s.cpu_percent}% across {s.cpu_count} cores</dd>
            <dt>RAM</dt><dd>{fmt(s.ram_used_bytes)} / {fmt(s.ram_total_bytes)} ({s.ram_percent}%)</dd>
            <dt>Swap</dt><dd>{s.swap_percent}%</dd>
            <dt>Disk /</dt><dd>{fmt(s.disk_used_bytes)} / {fmt(s.disk_total_bytes)} ({s.disk_percent}%)</dd>
          </dl>
        </div>
      </div>

      {integrity && (
        <div
          className="sys-card"
          style={{
            marginTop: 14,
            borderColor:
              integrity.status === 'tampered'
                ? 'var(--bad)'
                : integrity.status === 'ok'
                ? 'var(--good)'
                : 'var(--border)',
          }}
        >
          <h3>Self-integrity (tamper-aware, not tamper-proof)</h3>
          <dl className="sys-kv">
            <dt>Status</dt>
            <dd>
              <span className={`pill ${integrityPill(integrity.status)}`}>
                {integrity.status}
              </span>
            </dd>
            <dt>Files fingerprinted</dt>
            <dd>{integrity.total_files}</dd>
            <dt>Last snapshot</dt>
            <dd className="dim">{integrity.snapshot_at || '— never taken —'}</dd>
            <dt>Mismatched</dt>
            <dd>{integrity.mismatched?.length || 0}</dd>
            <dt>Missing</dt>
            <dd>{integrity.missing?.length || 0}</dd>
            <dt>Added</dt>
            <dd>{integrity.added?.length || 0}</dd>
          </dl>
          {integrity.status === 'tampered' &&
            (integrity.mismatched?.length > 0 || integrity.added?.length > 0) && (
              <div style={{ marginTop: 10, fontFamily: 'var(--mono)', fontSize: 12 }}>
                {integrity.mismatched?.slice(0, 10).map((f) => (
                  <div key={`m-${f}`} style={{ color: 'var(--bad)' }}>
                    ≠ {f}
                  </div>
                ))}
                {integrity.added?.slice(0, 10).map((f) => (
                  <div key={`a-${f}`} style={{ color: 'var(--warn)' }}>
                    + {f}
                  </div>
                ))}
              </div>
            )}
          <div style={{ marginTop: 12 }}>
            <button className="btn-refresh" onClick={takeSnapshot}>
              {integrity.status === 'no_snapshot' ? 'take snapshot' : 're-snapshot'}
            </button>
            <button className="btn-refresh" onClick={refresh} style={{ marginLeft: 8 }}>
              re-check
            </button>
          </div>
          {snapMsg && <div className="scan-message" style={{ marginTop: 8 }}>{snapMsg}</div>}
        </div>
      )}

      <h3 style={{ marginTop: 20, color: 'var(--accent)' }}>Top 20 processes</h3>
      <table className="dlp-table">
        <thead>
          <tr>
            <th>pid</th>
            <th>name</th>
            <th>user</th>
            <th>cpu%</th>
            <th>rss</th>
          </tr>
        </thead>
        <tbody>
          {top.map((r) => (
            <tr
              key={r.pid}
              style={{
                fontWeight: r.pid === p.pid ? 700 : 'normal',
                color: r.pid === p.pid ? 'var(--accent)' : undefined,
              }}
            >
              <td>{r.pid}</td>
              <td><code>{r.name}</code></td>
              <td className="dim">{r.user || '—'}</td>
              <td>{r.cpu_percent?.toFixed(1)}</td>
              <td>{fmt(r.rss_bytes)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
