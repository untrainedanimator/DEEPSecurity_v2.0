import { useEffect, useState } from 'react'

const SEV_ORDER = ['critical', 'high', 'medium', 'low']

export default function DLPPanel({ token }) {
  const [rows, setRows] = useState([])
  const [severity, setSeverity] = useState('')
  const [err, setErr] = useState('')

  const refresh = async () => {
    setErr('')
    const url =
      '/api/dlp/findings?limit=500' + (severity ? `&severity=${severity}` : '')
    try {
      const r = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!r.ok) {
        setErr(`HTTP ${r.status}`)
        setRows([])
        return
      }
      setRows(await r.json())
    } catch (e) {
      setErr(String(e))
    }
  }

  useEffect(() => {
    refresh()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [severity])

  const counts = SEV_ORDER.reduce((acc, s) => {
    acc[s] = rows.filter((r) => r.severity === s).length
    return acc
  }, {})

  return (
    <div className="dlp-panel">
      <h2>DLP findings</h2>
      <div className="scan-hint">
        Regex-based detection for secrets (AWS / GCP / Slack / GitHub / Stripe /
        private keys) and PII (SSN, credit card, email). Every hit is stored
        <strong> redacted</strong> — the raw secret never touches the database.
        Findings are tagged against MITRE ATT&amp;CK <code>T1552.*</code> (credential
        access) and <code>T1005</code> (local PII collection).
      </div>
      <div className="dlp-toolbar">
        <div className="dlp-filters">
          <button
            className={`chip ${severity === '' ? 'chip-active' : ''}`}
            onClick={() => setSeverity('')}
          >
            all ({rows.length})
          </button>
          {SEV_ORDER.map((s) => (
            <button
              key={s}
              className={`chip chip-sev-${s} ${severity === s ? 'chip-active' : ''}`}
              onClick={() => setSeverity(severity === s ? '' : s)}
            >
              {s} ({counts[s] || 0})
            </button>
          ))}
        </div>
        <button className="btn-refresh" onClick={refresh}>
          refresh
        </button>
      </div>
      {err && <div className="scan-message">{err}</div>}
      <table className="dlp-table">
        <thead>
          <tr>
            <th>severity</th>
            <th>pattern</th>
            <th>file</th>
            <th>line</th>
            <th>preview</th>
            <th>ATT&amp;CK</th>
            <th>time</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}>
              <td>
                <span className={`pill pill-sev-${r.severity}`}>{r.severity}</span>
              </td>
              <td>
                <code>{r.pattern}</code>
              </td>
              <td>
                <code className="file-cell">{r.file_path}</code>
              </td>
              <td>{r.line}</td>
              <td>
                <code className="preview-cell">{r.preview}</code>
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
              <td className="dim">{r.detected_at}</td>
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td colSpan="7" style={{ textAlign: 'center', opacity: 0.6 }}>
                {severity ? `no ${severity}-severity findings` : 'no DLP findings'}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
