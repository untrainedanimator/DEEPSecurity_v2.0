import { useEffect, useState } from 'react'

export default function NetworkPanel({ token }) {
  const [rows, setRows] = useState([])
  const [listen, setListen] = useState(0)
  const [knownBad, setKnownBad] = useState(0)
  const [repSize, setRepSize] = useState(0)
  const [filter, setFilter] = useState('any')
  const [err, setErr] = useState('')

  const refresh = async () => {
    setErr('')
    const state = filter === 'listen' ? 'LISTEN' : filter === 'est' ? 'ESTABLISHED' : 'any'
    try {
      const r = await fetch(`/api/network/connections?state=${state}`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      const j = await r.json()
      if (!r.ok) {
        setErr(j.error || `HTTP ${r.status}`)
        setRows([])
        return
      }
      setRows(j.connections || [])
      setListen(j.listening || 0)
      setKnownBad(j.known_bad_remotes || 0)
      setRepSize(j.reputation_size || 0)
    } catch (e) {
      setErr(String(e))
    }
  }

  useEffect(() => {
    refresh()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter])

  return (
    <div className="network-panel">
      <h2>Network connections</h2>
      <div className="scan-hint">
        Every socket visible to this process. Not a firewall — a view of what&apos;s
        listening and what&apos;s talking. Remote addresses are cross-checked against
        the local IP-reputation cache ({repSize.toLocaleString()} entries). Elevated
        privileges on some platforms give pid/process attribution; without them you
        see the socket tuples.
      </div>

      <div className="dlp-toolbar">
        <div className="dlp-filters">
          <button
            className={`chip ${filter === 'any' ? 'chip-active' : ''}`}
            onClick={() => setFilter('any')}
          >
            all ({rows.length})
          </button>
          <button
            className={`chip ${filter === 'listen' ? 'chip-active' : ''}`}
            onClick={() => setFilter('listen')}
          >
            listening ({listen})
          </button>
          <button
            className={`chip ${filter === 'est' ? 'chip-active' : ''}`}
            onClick={() => setFilter('est')}
          >
            established
          </button>
          {knownBad > 0 && (
            <span
              className="pill pill-sev-critical"
              style={{ marginLeft: 8 }}
              title="remote IPs matching the local reputation cache"
            >
              {knownBad} known-bad remote{knownBad === 1 ? '' : 's'}
            </span>
          )}
        </div>
        <button className="btn-refresh" onClick={refresh}>
          refresh
        </button>
      </div>

      {err && <div className="scan-message">{err}</div>}

      <table className="dlp-table">
        <thead>
          <tr>
            <th>proto</th>
            <th>local</th>
            <th>remote</th>
            <th>reputation</th>
            <th>state</th>
            <th>pid</th>
            <th>process</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((c, i) => {
            const bad = c.reputation?.known_bad
            return (
              <tr
                key={`${c.local?.ip}-${c.local?.port}-${c.remote?.ip}-${c.remote?.port}-${i}`}
                style={bad ? { background: 'rgba(248,113,113,0.08)' } : undefined}
              >
                <td>
                  <span className="pill pill-sev-low">
                    {c.family}/{c.kind}
                  </span>
                </td>
                <td>
                  <code>
                    {c.local?.ip || '—'}:{c.local?.port ?? '—'}
                  </code>
                </td>
                <td>
                  <code>
                    {c.remote?.ip || '—'}:{c.remote?.port ?? '—'}
                  </code>
                </td>
                <td>
                  {bad ? (
                    <span
                      className="pill pill-sev-critical"
                      title={`source: ${c.reputation.source}`}
                    >
                      known bad
                    </span>
                  ) : c.remote?.ip ? (
                    <span className="dim">clean</span>
                  ) : (
                    <span className="dim">—</span>
                  )}
                </td>
                <td>
                  <span
                    className={`pill ${
                      c.status === 'LISTEN'
                        ? 'pill-ok'
                        : c.status === 'ESTABLISHED'
                        ? 'pill-sev-medium'
                        : 'pill-sev-low'
                    }`}
                  >
                    {c.status}
                  </span>
                </td>
                <td>{c.pid ?? '—'}</td>
                <td>
                  <code>{c.process || '—'}</code>
                </td>
              </tr>
            )
          })}
          {rows.length === 0 && (
            <tr>
              <td colSpan="7" style={{ textAlign: 'center', opacity: 0.6 }}>
                no connections
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
