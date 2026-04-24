import { useState } from 'react'

const fmt = (n) => {
  if (!n && n !== 0) return '—'
  const units = ['B', 'KB', 'MB', 'GB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(1)} ${units[i]}`
}

const labelPill = (label) =>
  label === 'known_bad'
    ? 'pill-sev-critical'
    : label === 'suspicious'
    ? 'pill-sev-medium'
    : 'pill-ok'

export default function ProcessPanel({ token }) {
  const [data, setData] = useState(null)
  const [filter, setFilter] = useState('all')
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')
  const [msg, setMsg] = useState('')
  const [expanded, setExpanded] = useState(null) // PID currently showing its parent chain

  const scan = async () => {
    setErr('')
    setMsg('')
    setLoading(true)
    try {
      const r = await fetch('/api/processes/scan', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      })
      const body = await r.json()
      if (!r.ok) {
        setErr(body.error || `HTTP ${r.status}`)
        return
      }
      setData(body)
    } catch (e) {
      setErr(String(e))
    } finally {
      setLoading(false)
    }
  }

  const killPid = async (pid, name) => {
    const reason = prompt(
      `Terminate PID ${pid} (${name})?\n\nType a reason (min 3 chars, it lands in the audit log):`
    )
    if (!reason) return
    setMsg('')
    const r = await fetch('/api/processes/kill', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ pid, reason, force: false }),
    })
    const body = await r.json()
    setMsg(
      body.killed
        ? `killed pid ${pid} (${body.name || name})`
        : `kill failed: ${body.reason || body.error || 'unknown'}`
    )
    // Refresh to pick up the post-kill state.
    scan()
  }

  const rows = (data?.processes || []).filter(
    (r) => filter === 'all' || r.label === filter
  )
  const counts = {
    known_bad: (data?.processes || []).filter((r) => r.label === 'known_bad').length,
    suspicious: (data?.processes || []).filter((r) => r.label === 'suspicious').length,
    clean: (data?.processes || []).filter((r) => r.label === 'clean').length,
  }

  return (
    <div className="process-panel">
      <h2>Running processes</h2>
      <div className="scan-hint">
        User-space inspection via <code>psutil</code>. We flag known
        cryptominers, LOLBins, suspicious parent chains (Office → shell, PDF
        reader → shell, etc.), sustained-CPU offenders, and executables whose
        hash matches your signature file. Every flag is tagged against
        MITRE ATT&amp;CK. This is NOT an EDR — we don&apos;t hook the
        kernel.
      </div>

      {data?.auto_kill_enabled && (
        <div
          className="scan-message"
          style={{ borderLeft: '3px solid var(--bad)', paddingLeft: 10 }}
        >
          <strong>auto-kill is ON</strong> (
          <code>DEEPSEC_AUTO_KILL_KNOWN_BAD=true</code>). Every known_bad
          process is terminated the moment it&apos;s detected.
          {data?.auto_killed > 0 && ` ${data.auto_killed} killed this scan.`}
        </div>
      )}

      <div className="dlp-toolbar">
        <div className="dlp-filters">
          <button
            className={`chip ${filter === 'all' ? 'chip-active' : ''}`}
            onClick={() => setFilter('all')}
          >
            all ({data?.total || 0})
          </button>
          <button
            className={`chip chip-sev-critical ${filter === 'known_bad' ? 'chip-active' : ''}`}
            onClick={() => setFilter('known_bad')}
          >
            known bad ({counts.known_bad})
          </button>
          <button
            className={`chip chip-sev-medium ${filter === 'suspicious' ? 'chip-active' : ''}`}
            onClick={() => setFilter('suspicious')}
          >
            suspicious ({counts.suspicious})
          </button>
          <button
            className={`chip ${filter === 'clean' ? 'chip-active' : ''}`}
            onClick={() => setFilter('clean')}
          >
            clean ({counts.clean})
          </button>
        </div>
        <button className="btn-refresh" onClick={scan} disabled={loading}>
          {loading ? 'scanning…' : 'scan processes'}
        </button>
      </div>

      {err && <div className="scan-message" style={{ borderLeft: '3px solid var(--bad)', paddingLeft: 10 }}>{err}</div>}
      {msg && <div className="scan-message">{msg}</div>}

      {!data && !loading && (
        <div className="scan-message">
          no scan yet. click <strong>scan processes</strong>.
        </div>
      )}

      {data && (
        <table className="dlp-table">
          <thead>
            <tr>
              <th>label</th>
              <th>pid</th>
              <th>name</th>
              <th>user</th>
              <th>cpu%</th>
              <th>rss</th>
              <th>reasons</th>
              <th>ATT&amp;CK</th>
              <th>actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <>
                <tr key={r.pid}>
                  <td>
                    <span className={`pill ${labelPill(r.label)}`}>{r.label}</span>
                  </td>
                  <td>{r.pid}</td>
                  <td>
                    <code>{r.name}</code>
                    {r.parent_chain?.length > 1 && (
                      <button
                        onClick={() => setExpanded(expanded === r.pid ? null : r.pid)}
                        style={{
                          marginLeft: 6,
                          background: 'transparent',
                          border: '1px solid var(--border)',
                          color: 'var(--ink-muted)',
                          borderRadius: 4,
                          fontSize: 10,
                          padding: '1px 6px',
                          cursor: 'pointer',
                        }}
                      >
                        {expanded === r.pid ? '−' : '▸'} chain
                      </button>
                    )}
                  </td>
                  <td className="dim">{r.user || '—'}</td>
                  <td>{r.cpu_percent}</td>
                  <td>{fmt(r.rss_bytes)}</td>
                  <td className="dim" style={{ maxWidth: 280, wordBreak: 'break-word' }}>
                    {r.reasons?.join(', ')}
                  </td>
                  <td>
                    {(r.mitre_tags || []).map((t) => (
                      <span
                        key={t}
                        className="pill pill-sev-low"
                        style={{ marginRight: 4, fontFamily: 'var(--mono)' }}
                      >
                        {t}
                      </span>
                    ))}
                  </td>
                  <td>
                    {r.label !== 'clean' ? (
                      <button
                        onClick={() => killPid(r.pid, r.name)}
                        style={{
                          background: 'var(--surface-2)',
                          border: '1px solid var(--bad)',
                          color: 'var(--bad)',
                          borderRadius: 4,
                          padding: '2px 8px',
                          fontSize: 11,
                          cursor: 'pointer',
                        }}
                      >
                        kill
                      </button>
                    ) : (
                      <span className="dim">—</span>
                    )}
                    {r.auto_kill_result && (
                      <span
                        className="dim"
                        style={{ marginLeft: 6, fontSize: 10 }}
                        title={JSON.stringify(r.auto_kill_result)}
                      >
                        {r.auto_kill_result.killed ? '✓ auto-killed' : '✕ kill failed'}
                      </span>
                    )}
                  </td>
                </tr>
                {expanded === r.pid && r.parent_chain?.length > 1 && (
                  <tr key={`${r.pid}-chain`}>
                    <td colSpan="9" style={{ background: 'var(--bg)', padding: '10px 20px' }}>
                      <div className="kv-label" style={{ marginBottom: 6 }}>
                        Parent chain (child → parent)
                      </div>
                      <div style={{ fontFamily: 'var(--mono)', fontSize: 12 }}>
                        {r.parent_chain.map((n, i) => (
                          <span key={n.pid}>
                            {i > 0 && <span className="dim"> ← </span>}
                            <span style={{ color: 'var(--accent)' }}>{n.name}</span>
                            <span className="dim">({n.pid})</span>
                          </span>
                        ))}
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan="9" style={{ textAlign: 'center', opacity: 0.6 }}>
                  no rows match the filter
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}
    </div>
  )
}
