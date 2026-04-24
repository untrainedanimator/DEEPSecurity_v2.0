import { useEffect, useState } from 'react'

export default function ScanPanel({ token }) {
  const [path, setPath] = useState('')
  const [status, setStatus] = useState(null)
  const [message, setMessage] = useState('')

  useEffect(() => {
    const id = setInterval(async () => {
      try {
        const r = await fetch('/api/scanner/status')
        if (r.ok) setStatus(await r.json())
      } catch {
        /* noop */
      }
    }, 2000)
    return () => clearInterval(id)
  }, [])

  const start = async () => {
    setMessage('')
    // Trim the input locally too — this way the user sees exactly what we
    // send and doesn't get bitten by a trailing space they can't see.
    const cleaned = path.trim()
    if (!cleaned) {
      setMessage('enter an absolute path')
      return
    }
    try {
      const r = await fetch('/api/scanner/start', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ path: cleaned, quarantine: true }),
      })
      const body = await r.json()
      if (!r.ok) {
        const parts = [body.error || 'error']
        if (body.message) parts.push(body.message)
        else if (body.path) parts.push(`tried: ${body.path}`)
        setMessage(parts.join(' — '))
        return
      }
      setMessage(`started against ${body.path}`)
    } catch (err) {
      setMessage(String(err))
    }
  }

  const cancel = async () => {
    await fetch('/api/scanner/cancel', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    })
  }

  return (
    <div className="scan-panel">
      <h2>Live scan</h2>
      <div className="scan-hint">
        Signature + YARA + entropy + DLP sweep of any absolute path — a drive
        (<code>C:\</code>, <code>/</code>), a folder, or a single file.
        DEEPSecurity <em>complements</em> your AV, it doesn't replace it;
        keep Defender/SentinelOne/CrowdStrike on for malware coverage.
      </div>
      <div className="scan-controls">
        <input
          type="text"
          placeholder="C:\path\to\scan   or   /path/to/scan   or   /path/to/file.exe"
          value={path}
          onChange={(e) => setPath(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && path && !status?.running) start()
          }}
        />
        <button onClick={start} disabled={!path || status?.running}>
          start scan
        </button>
        <button onClick={cancel} disabled={!status?.running}>
          cancel
        </button>
      </div>
      {message && <div className="scan-message">{message}</div>}
      {status && (
        <div className="scan-status">
          <div>
            <strong>running:</strong> {String(status.running)}
          </div>
          <div>
            <strong>files:</strong> {status.scanned_count}/{status.total_files || '?'}
            {' '}({status.progress_percent}%)
          </div>
          <div>
            <strong>detections:</strong> {status.total_detections}
          </div>
          <div>
            <strong>current:</strong> <code>{status.current_file}</code>
          </div>
          <div>
            <strong>deepsec:</strong> CPU {status.process?.cpu_percent ?? '—'}% · RSS{' '}
            {status.process?.rss_mb ?? '—'} MB
          </div>
          <div className="dim">
            <strong>system:</strong> CPU {status.system?.cpu_percent ?? status.cpu}% ·
            RAM {status.system?.ram_percent ?? status.ram}%
          </div>
          {status.output_tail?.length > 0 && (
            <pre className="scan-tail">{status.output_tail.join('\n')}</pre>
          )}
        </div>
      )}
    </div>
  )
}
