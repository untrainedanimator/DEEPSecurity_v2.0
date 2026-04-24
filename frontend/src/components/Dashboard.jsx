import { useEffect, useState } from 'react'
import ScanPanel from './ScanPanel.jsx'
import RealtimePanel from './RealtimePanel.jsx'
import QuarantinePanel from './QuarantinePanel.jsx'
import DLPPanel from './DLPPanel.jsx'
import SystemPanel from './SystemPanel.jsx'
import NetworkPanel from './NetworkPanel.jsx'
import ProcessPanel from './ProcessPanel.jsx'
import SinksPanel from './SinksPanel.jsx'
import AuditPanel from './AuditPanel.jsx'

const TABS = [
  { id: 'scan', label: 'Live scan' },
  { id: 'realtime', label: 'Realtime' },
  { id: 'processes', label: 'Processes' },
  { id: 'quarantine', label: 'Quarantine' },
  { id: 'dlp', label: 'DLP findings' },
  { id: 'system', label: 'System' },
  { id: 'network', label: 'Network' },
  { id: 'sinks', label: 'Alert sinks' },
  { id: 'audit', label: 'Audit' },
]

export default function Dashboard({ token }) {
  const [tab, setTab] = useState('scan')
  const [me, setMe] = useState(null)

  useEffect(() => {
    fetch('/api/auth/whoami', { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then(setMe)
      .catch(() => setMe(null))
  }, [token])

  return (
    <div className="dashboard">
      <nav className="tabs">
        {TABS.map((t) => (
          <button
            key={t.id}
            className={`tab ${tab === t.id ? 'tab-active' : ''}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
        {me && (
          <div className="me">
            {me.username} · <em>{me.role}</em>
          </div>
        )}
      </nav>
      <section className="tab-body">
        {tab === 'scan' && <ScanPanel token={token} />}
        {tab === 'realtime' && <RealtimePanel token={token} />}
        {tab === 'processes' && <ProcessPanel token={token} />}
        {tab === 'quarantine' && <QuarantinePanel token={token} />}
        {tab === 'dlp' && <DLPPanel token={token} />}
        {tab === 'system' && <SystemPanel token={token} />}
        {tab === 'network' && <NetworkPanel token={token} />}
        {tab === 'sinks' && <SinksPanel token={token} />}
        {tab === 'audit' && <AuditPanel token={token} />}
      </section>
    </div>
  )
}
