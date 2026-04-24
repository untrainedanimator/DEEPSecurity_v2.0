import { useEffect, useState } from 'react'

export default function SinksPanel({ token }) {
  const [sinks, setSinks] = useState([])
  const [msg, setMsg] = useState('')

  const refresh = async () => {
    const r = await fetch('/api/sinks/status', {
      headers: { Authorization: `Bearer ${token}` },
    })
    if (r.ok) setSinks((await r.json()).sinks)
  }

  useEffect(() => {
    refresh()
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

  return (
    <div className="sinks-panel">
      <h2>Alert sinks</h2>
      <div className="scan-hint">
        Where critical + high-severity alerts get forwarded. Configure each
        via <code>.env</code>; the <strong>test</strong> button fires a
        synthetic info-level event through every enabled sink so you can
        verify the plumbing without waiting for a real detection.
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
          {sinks.map((s) => (
            <tr key={s.name}>
              <td><code>{s.name}</code></td>
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
      {msg && <div className="scan-message" style={{ marginTop: 10 }}>{msg}</div>}
    </div>
  )
}
