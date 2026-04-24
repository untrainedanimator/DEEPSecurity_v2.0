import { useEffect, useState } from 'react'

export default function RealtimePanel({ token }) {
  const [status, setStatus] = useState(null)
  const [msg, setMsg] = useState('')
  const [msgKind, setMsgKind] = useState('info') // 'info' | 'error' | 'ok'
  const [refreshing, setRefreshing] = useState(false)
  const [lastRefresh, setLastRefresh] = useState(null)
  const [refreshError, setRefreshError] = useState(null)

  // Manual controls live behind an "Advanced" toggle. The default view is
  // state + pause/resume, because the tool auto-starts on server boot.
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [customPath, setCustomPath] = useState('')

  const refresh = async () => {
    setRefreshing(true)
    setRefreshError(null)
    try {
      const r = await fetch('/api/watchdog/status', {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (r.ok) {
        setStatus(await r.json())
        setLastRefresh(new Date())
      } else {
        setRefreshError(`HTTP ${r.status}`)
      }
    } catch (e) {
      setRefreshError(String(e.message || e))
    } finally {
      setRefreshing(false)
    }
  }

  useEffect(() => {
    refresh()
    const id = setInterval(refresh, 5000)
    return () => clearInterval(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const refreshLabel = refreshing
    ? 'refreshing…'
    : refreshError
    ? `refresh (${refreshError})`
    : lastRefresh
    ? `refresh (${lastRefresh.toLocaleTimeString()})`
    : 'refresh'

  const callStart = async (body) => {
    setMsg('')
    try {
      const r = await fetch('/api/watchdog/start', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(body),
      })
      const data = await r.json()
      if (data.started) {
        setMsg(`watching: ${(data.paths || []).join(', ')}`)
        setMsgKind('ok')
      } else {
        setMsg(data.reason || `HTTP ${r.status}`)
        setMsgKind('error')
      }
    } catch (e) {
      setMsg(String(e.message || e))
      setMsgKind('error')
    }
    refresh()
  }

  const resumeUserRisk = () => callStart({ scope: 'user_risk' })
  const watchSystem = () => callStart({ scope: 'system' })
  const watchCustom = () => {
    const p = customPath.trim()
    if (!p) {
      setMsg('enter an absolute path')
      setMsgKind('error')
      return
    }
    callStart({ path: p })
  }

  const pause = async () => {
    setMsg('')
    try {
      const r = await fetch('/api/watchdog/stop', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      })
      const data = await r.json()
      setMsg(data.stopped ? 'watchdog paused' : data.reason || `HTTP ${r.status}`)
      setMsgKind(data.stopped ? 'info' : 'error')
    } catch (e) {
      setMsg(String(e.message || e))
      setMsgKind('error')
    }
    refresh()
  }

  const msgStyle =
    msgKind === 'error'
      ? { borderLeft: '3px solid var(--bad)', paddingLeft: 10 }
      : msgKind === 'ok'
      ? { borderLeft: '3px solid var(--good)', paddingLeft: 10 }
      : undefined

  const isRunning = !!status?.running
  const canStart = !!status?.available && !isRunning

  return (
    <div className="realtime-panel">
      <h2>Realtime scanning</h2>
      <div className="scan-hint">
        Near-real-time file monitoring via the <code>watchdog</code> library.
        DEEPSecurity <strong>auto-starts on the "user-risk" scope</strong>
        {' '}(Downloads, Desktop, Documents, Outlook cache, %TEMP%) when the
        server boots — no configuration required. Signature hit ⇒ quarantine,
        high-confidence heuristic ⇒ audit, otherwise silent. Latency is
        tens of ms, not microseconds: this is user-space and{' '}
        <strong>deliberately not</strong> a kernel hook, so it can't see
        what an EDR sees. See <code>docs/THREAT_MODEL.md</code> for the
        full ceiling.
      </div>

      {status && (
        <div className="realtime-grid">
          <div>
            <div className="kv-label">Dependency available</div>
            <div className="kv-value">
              <span className={`pill ${status.available ? 'pill-ok' : 'pill-denied'}`}>
                {status.available ? 'yes' : 'no — pip install "deepsecurity[watchdog]"'}
              </span>
            </div>
          </div>
          <div>
            <div className="kv-label">Status</div>
            <div className="kv-value">
              <span className={`pill ${isRunning ? 'pill-ok' : 'pill-suspicious'}`}>
                {isRunning ? 'active' : 'paused / stopped'}
              </span>
            </div>
          </div>
          {status.watching?.length > 0 && (
            <div style={{ gridColumn: '1 / -1' }}>
              <div className="kv-label">
                Currently watching ({status.watching.length}
                {status.watching.length === 1 ? ' path' : ' paths'})
              </div>
              <div className="kv-value">
                {status.watching.map((p) => (
                  <div key={p}>
                    <code>{p}</code>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Primary controls — one button, state-appropriate. */}
      <div className="scan-controls" style={{ marginTop: 14 }}>
        {isRunning ? (
          <button
            onClick={pause}
            style={{
              background: 'var(--surface-2)',
              border: '1px solid var(--warn)',
              color: 'var(--warn)',
              padding: '8px 14px',
              borderRadius: 6,
              cursor: 'pointer',
              fontWeight: 600,
            }}
          >
            pause watchdog
          </button>
        ) : (
          <button
            onClick={resumeUserRisk}
            disabled={!canStart}
            style={{
              background: 'var(--accent)',
              border: '1px solid var(--accent)',
              color: 'var(--bg)',
              padding: '8px 14px',
              borderRadius: 6,
              cursor: canStart ? 'pointer' : 'not-allowed',
              opacity: canStart ? 1 : 0.4,
              fontWeight: 700,
            }}
          >
            resume (user-risk scope)
          </button>
        )}
        <button
          onClick={refresh}
          className="btn-refresh"
          disabled={refreshing}
          title={
            refreshError
              ? `last refresh failed: ${refreshError}`
              : lastRefresh
              ? `last refreshed at ${lastRefresh.toLocaleTimeString()}`
              : 'refresh status'
          }
          style={{
            opacity: refreshing ? 0.6 : 1,
            borderColor: refreshError ? 'var(--bad)' : undefined,
            color: refreshError ? 'var(--bad)' : undefined,
          }}
        >
          {refreshLabel}
        </button>
      </div>

      {msg && (
        <div className="scan-message" style={{ ...msgStyle, marginTop: 12 }}>
          {msg}
        </div>
      )}

      {/* Advanced — hidden by default. Power-user overrides live here. */}
      <div style={{ marginTop: 18 }}>
        <button
          onClick={() => setShowAdvanced((v) => !v)}
          style={{
            background: 'transparent',
            border: 'none',
            color: 'var(--ink-muted)',
            cursor: 'pointer',
            padding: 0,
            fontSize: 12,
            textDecoration: 'underline dotted',
          }}
        >
          {showAdvanced ? '▾ hide advanced' : '▸ advanced (manual paths, system scope)'}
        </button>
      </div>

      {showAdvanced && (
        <div
          style={{
            marginTop: 10,
            padding: 12,
            border: '1px solid var(--border)',
            borderRadius: 6,
            background: 'var(--surface-2)',
          }}
        >
          <div className="scan-hint" style={{ marginBottom: 10, fontSize: 12 }}>
            The recommended posture is the auto-started "user-risk" scope.
            These overrides are here for diagnostics, narrow investigations,
            or full-drive coverage.
          </div>

          <div className="scan-controls">
            <input
              type="text"
              placeholder="absolute path to watch (narrow investigation)"
              value={customPath}
              onChange={(e) => setCustomPath(e.target.value)}
              disabled={isRunning}
            />
            <button onClick={watchCustom} disabled={!canStart}>
              watch this path
            </button>
          </div>

          <div style={{ marginTop: 10 }}>
            <button
              onClick={watchSystem}
              disabled={!canStart}
              style={{
                background: 'var(--surface)',
                border: '1px solid var(--border)',
                color: 'var(--ink-muted)',
                padding: '6px 12px',
                borderRadius: 6,
                cursor: canStart ? 'pointer' : 'not-allowed',
                opacity: canStart ? 1 : 0.4,
              }}
            >
              watch the whole system
            </button>
            <span className="dim" style={{ marginLeft: 10, fontSize: 12 }}>
              every drive — broad coverage but high event volume
            </span>
          </div>
        </div>
      )}
    </div>
  )
}
