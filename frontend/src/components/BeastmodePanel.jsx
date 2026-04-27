import { useEffect, useState } from 'react'

// ---------------------------------------------------------------------------
// BEASTMODE — v3.0 EDR / audit-sink / TLS / platform status panel.
//
// Polls /api/v3/status every 5s and renders one card per subsystem. Cards
// degrade gracefully when an extra is missing (dnslib not installed,
// running on Linux, etc.) — the backend already returns ``available:false``
// + a ``hint``, we just show that.
// ---------------------------------------------------------------------------

const Pill = ({ ok, warn, label }) => {
  const cls = ok ? 'pill-ok' : warn ? 'pill-suspicious' : 'pill-denied'
  return <span className={`pill ${cls}`}>{label}</span>
}

const Row = ({ label, value, mono = false }) => (
  <div className="bm-row">
    <div className="bm-row-label">{label}</div>
    <div className={`bm-row-value${mono ? ' bm-mono' : ''}`}>{value}</div>
  </div>
)

const Card = ({ title, accent, children, footer }) => (
  <div className="bm-card" style={accent ? { borderTopColor: accent } : undefined}>
    <div className="bm-card-title">{title}</div>
    <div className="bm-card-body">{children}</div>
    {footer && <div className="bm-card-footer">{footer}</div>}
  </div>
)

function RealtimeCards({ rt }) {
  if (!rt) return null
  return (
    <>
      <Card title="ETW" accent="var(--accent)">
        <Row
          label="Available"
          value={
            rt.etw?.available ? (
              <Pill ok label="yes" />
            ) : (
              <Pill label="no" />
            )
          }
        />
        {rt.etw?.providers && (
          <Row
            label="Providers"
            mono
            value={rt.etw.providers.join('\n')}
          />
        )}
        {rt.etw?.hint && <Row label="Hint" value={rt.etw.hint} />}
      </Card>

      <Card title="Sysmon" accent="var(--accent)">
        <Row
          label="Module"
          value={
            rt.sysmon?.available ? (
              <Pill ok label="loaded" />
            ) : (
              <Pill label="missing" />
            )
          }
        />
        <Row
          label="Channel installed"
          value={
            rt.sysmon?.installed ? (
              <Pill ok label="yes" />
            ) : (
              <Pill warn label="no — Sysmon not installed" />
            )
          }
        />
        {rt.sysmon?.channel && <Row label="Channel" mono value={rt.sysmon.channel} />}
        {rt.sysmon?.hint && <Row label="Hint" value={rt.sysmon.hint} />}
      </Card>

      <Card title="WinDivert" accent="var(--accent)">
        <Row
          label="Available"
          value={
            rt.windivert?.available ? (
              <Pill ok label="yes" />
            ) : (
              <Pill label="no" />
            )
          }
        />
        {rt.windivert?.version && <Row label="Version" mono value={rt.windivert.version} />}
        {rt.windivert?.hint && <Row label="Hint" value={rt.windivert.hint} />}
      </Card>

      <Card title="Defender Firewall" accent="var(--accent)">
        <Row
          label="COM dispatch"
          value={
            rt.defender_fw?.available ? (
              <Pill ok label="connected" />
            ) : (
              <Pill warn label="unavailable" />
            )
          }
        />
        {typeof rt.defender_fw?.rule_count === 'number' && (
          <Row label="FW rules" mono value={rt.defender_fw.rule_count.toLocaleString()} />
        )}
        {rt.defender_fw?.error && (
          <Row label="Error" mono value={rt.defender_fw.error} />
        )}
      </Card>

      <Card title="DNS sinkhole" accent="var(--accent)">
        <Row label="Bind" mono value={rt.dns_sinkhole?.configured_bind} />
        <Row label="Port" mono value={rt.dns_sinkhole?.configured_port} />
        <Row
          label="Blocklist"
          mono
          value={rt.dns_sinkhole?.blocklist_path || '(none)'}
        />
      </Card>

      <Card title="Memory scanner" accent="var(--accent)">
        <Row
          label="Module"
          value={
            rt.memory_scan?.available ? (
              <Pill ok label="loaded" />
            ) : (
              <Pill label="missing" />
            )
          }
        />
        {rt.memory_scan?.error && (
          <Row label="Error" mono value={rt.memory_scan.error} />
        )}
      </Card>
    </>
  )
}

function AuditSinksCard({ sinks }) {
  if (!sinks) return null
  if (!sinks.configured) {
    return (
      <Card title="Audit sinks" accent="var(--warn)">
        <Row label="Replication" value={<Pill label="not configured" />} />
        <Row
          label="Hint"
          value={
            <span className="bm-hint">
              Set <code>DEEPSEC_AUDIT_SINK_WEBHOOK_URL</code> /{' '}
              <code>_SYSLOG_HOST</code> / <code>_FILE_PATH</code> to
              replicate the audit trail to an external WORM-style sink.
            </span>
          }
        />
      </Card>
    )
  }
  const queueLabel = `${sinks.queue_size} / ${sinks.queue_max}`
  const queueWarn = sinks.queue_size > sinks.queue_max * 0.5
  return (
    <Card title="Audit sinks" accent="var(--good)">
      <Row label="Configured sinks" mono value={(sinks.sinks || []).join(', ')} />
      <Row
        label="Queue depth"
        value={
          <span style={{ color: queueWarn ? 'var(--warn)' : 'var(--good)' }}>
            {queueLabel}
          </span>
        }
      />
      <Row label="Batch size" mono value={sinks.batch_size} />
      <Row label="Flush interval" mono value={`${sinks.flush_interval_s}s`} />
      <Row
        label="Dropped"
        value={
          sinks.dropped > 0 ? (
            <span style={{ color: 'var(--bad)' }}>{sinks.dropped}</span>
          ) : (
            <span style={{ color: 'var(--good)' }}>0</span>
          )
        }
      />
    </Card>
  )
}

function TLSCard({ tls }) {
  if (!tls) return null
  const mode = tls.mode || 'off'
  const accent =
    mode === 'cert' ? 'var(--good)' : mode === 'self-signed' ? 'var(--warn)' : 'var(--ink-muted)'
  const expWarn = tls.cert_days_remaining !== undefined && tls.cert_days_remaining < 30
  return (
    <Card title="TLS" accent={accent}>
      <Row
        label="Mode"
        value={
          <Pill
            ok={mode === 'cert'}
            warn={mode === 'self-signed'}
            label={mode}
          />
        }
      />
      <Row label="HSTS max-age" mono value={`${tls.hsts_max_age}s`} />
      {tls.hint && <Row label="Hint" value={tls.hint} />}
      {tls.cert_path && <Row label="Cert path" mono value={tls.cert_path} />}
      {tls.cert_subject && <Row label="Cert subject" mono value={tls.cert_subject} />}
      {tls.cert_days_remaining !== undefined && (
        <Row
          label="Cert expires in"
          value={
            <span style={{ color: expWarn ? 'var(--warn)' : 'var(--good)' }}>
              {tls.cert_days_remaining} days
            </span>
          }
        />
      )}
      {tls.cert_parse_error && (
        <Row label="Parse error" mono value={tls.cert_parse_error} />
      )}
    </Card>
  )
}

function PlatformCard({ platform }) {
  if (!platform) return null
  const caps = platform.capabilities || {}
  return (
    <Card title="Platform" accent="var(--ink-muted)">
      <Row
        label="OS"
        mono
        value={`${platform.os_name} ${platform.os_release || ''}`.trim()}
      />
      <Row
        label="Realtime supported"
        value={
          platform.realtime_supported ? (
            <Pill ok label="yes" />
          ) : (
            <Pill warn label="no — see hints" />
          )
        }
      />
      <Row
        label="Capabilities"
        value={
          <div className="bm-caps">
            {Object.entries(caps).map(([k, v]) => (
              <span
                key={k}
                className="bm-cap-pill"
                style={{
                  color: v ? 'var(--good)' : 'var(--ink-muted)',
                  borderColor: v ? 'var(--good)' : 'var(--border)',
                }}
              >
                {k.replace(/_/g, ' ')}: {v ? 'yes' : 'no'}
              </span>
            ))}
          </div>
        }
      />
      {platform.notes && platform.notes.length > 0 && (
        <Row label="Notes" value={platform.notes.join(' · ')} />
      )}
    </Card>
  )
}

function MitigationsCard({ mitigations }) {
  if (!mitigations) return null
  if (!mitigations.available) {
    return (
      <Card title="Process mitigations" accent="var(--ink-muted)">
        <Row label="Module" value={<Pill label="unavailable" />} />
        {mitigations.error && <Row label="Error" mono value={mitigations.error} />}
      </Card>
    )
  }
  const layerOn = !!mitigations.layer_enabled
  const attempted = mitigations.attempted || {}
  return (
    <Card title="Process mitigations" accent={layerOn ? 'var(--good)' : 'var(--ink-muted)'}>
      <Row
        label="Layer"
        value={
          layerOn ? <Pill ok label="enabled" /> : <Pill label="disabled" />
        }
      />
      <Row
        label="Policies attempted"
        value={
          <div className="bm-caps">
            {Object.entries(attempted).map(([k, v]) => (
              <span
                key={k}
                className="bm-cap-pill"
                style={{
                  color: v ? 'var(--good)' : 'var(--ink-muted)',
                  borderColor: v ? 'var(--good)' : 'var(--border)',
                }}
              >
                {k.replace(/_/g, ' ')}: {v ? 'on' : 'off'}
              </span>
            ))}
          </div>
        }
      />
      {mitigations.ground_truth_hint && (
        <Row label="Ground truth" value={<span className="bm-hint">{mitigations.ground_truth_hint}</span>} />
      )}
    </Card>
  )
}

export default function BeastmodePanel({ token }) {
  const [data, setData] = useState(null)
  const [err, setErr] = useState(null)
  const [refreshing, setRefreshing] = useState(false)
  const [lastRefresh, setLastRefresh] = useState(null)

  const refresh = async () => {
    setRefreshing(true)
    setErr(null)
    try {
      const r = await fetch('/api/v3/status', {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!r.ok) {
        setErr(`HTTP ${r.status}`)
        return
      }
      setData(await r.json())
      setLastRefresh(new Date())
    } catch (e) {
      setErr(String(e.message || e))
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

  return (
    <div className="bm-panel">
      <style>{`
        .bm-panel { display: flex; flex-direction: column; gap: 16px; }
        .bm-header { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; }
        .bm-header h2 { margin: 0; }
        .bm-tagline { color: var(--ink-muted); font-size: 12px; }
        .bm-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; }
        .bm-card { background: var(--surface); border: 1px solid var(--border); border-top: 3px solid var(--border); border-radius: 8px; padding: 14px 16px; display: flex; flex-direction: column; gap: 6px; }
        .bm-card-title { font-weight: 600; font-size: 13px; color: var(--ink); letter-spacing: 0.3px; }
        .bm-card-body { display: flex; flex-direction: column; gap: 4px; }
        .bm-card-footer { font-size: 11px; color: var(--ink-muted); padding-top: 4px; border-top: 1px solid var(--border); }
        .bm-row { display: grid; grid-template-columns: 130px 1fr; gap: 8px; align-items: start; padding: 2px 0; font-size: 12px; }
        .bm-row-label { color: var(--ink-muted); }
        .bm-row-value { color: var(--ink); white-space: pre-wrap; word-break: break-word; }
        .bm-mono { font-family: var(--mono); font-size: 11.5px; }
        .bm-caps { display: flex; flex-wrap: wrap; gap: 4px; }
        .bm-cap-pill { display: inline-block; padding: 2px 8px; border-radius: 999px; border: 1px solid var(--border); font-size: 11px; font-family: var(--mono); }
        .bm-hint code { background: var(--surface-2); padding: 1px 4px; border-radius: 3px; font-size: 11px; }
        .bm-section-h { font-size: 11px; text-transform: uppercase; letter-spacing: 0.1em; color: var(--ink-muted); margin: 6px 0 0; }
      `}</style>

      <div className="bm-header">
        <div>
          <h2>v3.0 BEASTMODE</h2>
          <div className="bm-tagline">
            Real-time EDR surface, audit-log replication, TLS, and platform
            capability matrix. Polled from <code>/api/v3/status</code> every 5s.
          </div>
        </div>
        <button
          onClick={refresh}
          className="btn-refresh"
          disabled={refreshing}
          style={{ opacity: refreshing ? 0.6 : 1 }}
        >
          {refreshing
            ? 'refreshing…'
            : err
            ? `refresh (${err})`
            : lastRefresh
            ? `refresh (${lastRefresh.toLocaleTimeString()})`
            : 'refresh'}
        </button>
      </div>

      {err && !data && (
        <div className="scan-message" style={{ borderLeft: '3px solid var(--bad)', paddingLeft: 10 }}>
          /api/v3/status failed: {err}
        </div>
      )}

      {data && (
        <>
          <div className="bm-section-h">Realtime stack</div>
          <div className="bm-grid">
            <RealtimeCards rt={data.realtime} />
          </div>

          <div className="bm-section-h">Transport &amp; host</div>
          <div className="bm-grid">
            <TLSCard tls={data.tls} />
            <PlatformCard platform={data.platform} />
            <MitigationsCard mitigations={data.mitigations} />
          </div>

          <div
            className="bm-tagline"
            style={{ marginTop: 6, fontSize: 11.5 }}
          >
            Audit-log replication status moved to the{' '}
            <strong>Alert sinks</strong> tab so all sink configuration lives
            in one place.
          </div>
        </>
      )}
    </div>
  )
}
