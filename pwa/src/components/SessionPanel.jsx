import { useState } from 'react'
import { isSessionValid } from '../lib/stellar.js'

export default function SessionPanel({ account, sessions }) {
  const [targetKey, setTargetKey] = useState('credit_score')
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  async function handleCheck(e) {
    e.preventDefault()
    if (!account) {
      setError('Connect a wallet first.')
      return
    }
    setBusy(true)
    setError(null)
    setResult(null)
    try {
      const valid = await isSessionValid({ account, targetKey })
      setResult(valid)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <article className="card">
      <h2>4. Session status</h2>
      <p>
        Query the contract to check whether an active session exists for your
        address and a target key.
      </p>

      <form onSubmit={handleCheck}>
        <label>
          Target key
          <input
            value={targetKey}
            onChange={(e) => setTargetKey(e.target.value)}
            placeholder="credit_score"
            required
          />
        </label>
        <div className="actions">
          <button type="submit" disabled={busy || !account} aria-busy={busy}>
            {busy ? 'Checking…' : 'Check session'}
          </button>
        </div>
      </form>

      {result !== null && (
        <p>
          Session: <span className={`status ${result ? 'status-ok' : 'status-pending'}`}>
            {result ? 'active' : 'none'}
          </span>
        </p>
      )}
      {error && <p className="error">{error}</p>}

      {sessions.length > 0 && (
        <>
          <h3>Local history</h3>
          <ul>
            {sessions.map((s) => (
              <li key={s.hash}>
                <span className="mono">{s.key}</span> with threshold {s.threshold}{' '}
                <span className="credential-meta">(tx {s.hash.slice(0, 12)}…)</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </article>
  )
}
