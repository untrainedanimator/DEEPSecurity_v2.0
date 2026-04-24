import { useEffect, useState } from 'react'
import Login from './components/Login.jsx'
import Dashboard from './components/Dashboard.jsx'

const TOKEN_KEY = 'deepsec.token'

export default function App() {
  const [token, setToken] = useState(() => sessionStorage.getItem(TOKEN_KEY) || '')
  const [ready, setReady] = useState(null)

  useEffect(() => {
    fetch('/readyz')
      .then((r) => r.json())
      .then(setReady)
      .catch(() => setReady({ status: 'unreachable' }))
  }, [])

  const onLogin = (tok) => {
    sessionStorage.setItem(TOKEN_KEY, tok)
    setToken(tok)
  }
  const onLogout = () => {
    sessionStorage.removeItem(TOKEN_KEY)
    setToken('')
  }

  return (
    <div className="app">
      <header className="app-header">
        <div className="brand-wrap">
          <div className="brand">DEEPSecurity</div>
          <div className="tagline">
            Policy, DLP &amp; compliance overlay — runs alongside your AV
          </div>
        </div>
        <div className="ready">
          {ready ? (
            <span className={`ready-pill ready-${ready.status}`}>{ready.status}</span>
          ) : (
            <span className="ready-pill">checking…</span>
          )}
          {token && (
            <button className="logout" onClick={onLogout}>
              log out
            </button>
          )}
        </div>
      </header>
      <main className="app-main">
        {token ? <Dashboard token={token} /> : <Login onLogin={onLogin} />}
      </main>
    </div>
  )
}
