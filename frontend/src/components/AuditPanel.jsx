import { useEffect, useState } from 'react'

export default function AuditPanel({ token }) {
  const [rows, setRows] = useState([])

  useEffect(() => {
    fetch('/api/audit?limit=200', {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => r.json())
      .then(setRows)
      .catch(() => setRows([]))
  }, [token])

  return (
    <div className="audit-panel">
      <h2>Audit log (last 200)</h2>
      <table className="audit-table">
        <thead>
          <tr>
            <th>time</th>
            <th>actor</th>
            <th>action</th>
            <th>status</th>
            <th>file</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td>{r.timestamp}</td>
              <td>{r.actor}</td>
              <td>{r.action}</td>
              <td>
                <span className={`pill pill-${r.status}`}>{r.status}</span>
              </td>
              <td>
                <code>{r.file_path}</code>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
