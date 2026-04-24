import { useEffect, useState } from 'react'

export default function QuarantinePanel({ token }) {
  const [entries, setEntries] = useState([])
  const [message, setMessage] = useState('')

  const refresh = async () => {
    const r = await fetch('/api/quarantine/list', {
      headers: { Authorization: `Bearer ${token}` },
    })
    if (r.ok) setEntries((await r.json()).entries)
  }

  useEffect(() => {
    refresh()
  }, [])

  const del = async (name) => {
    const reason = prompt(`permanently delete ${name}?  type a reason:`)
    if (!reason) return
    const r = await fetch('/api/quarantine/delete', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ name, reason }),
    })
    const body = await r.json()
    setMessage(r.ok ? `deleted ${name} (sha256 ${body.sha256})` : body.error || 'error')
    refresh()
  }

  return (
    <div className="quarantine-panel">
      <h2>Quarantine</h2>
      <button onClick={refresh}>refresh</button>
      {message && <div className="scan-message">{message}</div>}
      <table className="quarantine-table">
        <thead>
          <tr>
            <th>file</th>
            <th>size</th>
            <th>mtime</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {entries.map((e) => (
            <tr key={e.name}>
              <td>
                <code>{e.name}</code>
              </td>
              <td>{e.size_bytes}</td>
              <td>{new Date(e.mtime * 1000).toLocaleString()}</td>
              <td>
                <button onClick={() => del(e.name)}>delete</button>
              </td>
            </tr>
          ))}
          {entries.length === 0 && (
            <tr>
              <td colSpan="4" style={{ textAlign: 'center', opacity: 0.6 }}>
                no quarantined files
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
