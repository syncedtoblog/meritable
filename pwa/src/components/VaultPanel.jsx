import { useState } from 'react'
import { requestCredential } from '../lib/issuer.js'
import { storeCredential, listCredentials, deleteCredential } from '../lib/vault.js'

export default function VaultPanel({ account, credentials, onCredentialsChange }) {
  const [key, setKey] = useState('credit_score')
  const [value, setValue] = useState(750)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  async function handleRefresh() {
    try {
      const stored = await listCredentials()
      onCredentialsChange(stored)
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleRequest(e) {
    e.preventDefault()
    if (!account) {
      setError('Connect a wallet first.')
      return
    }
    setBusy(true)
    setError(null)
    try {
      const credential = await requestCredential({
        userAddress: account,
        key,
        value: Number(value),
      })
      await storeCredential(credential)
      const stored = await listCredentials()
      onCredentialsChange(stored)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function handleDelete(id) {
    try {
      await deleteCredential(id)
      const stored = await listCredentials()
      onCredentialsChange(stored)
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <article className="card">
      <h2>2. Credential vault</h2>
      <p>
        Request a demo credential and store it locally. In the full build these
        entries are encrypted with a WebAuthn-derived key before being written to
        IndexedDB.
      </p>

      <form onSubmit={handleRequest}>
        <div className="grid">
          <label>
            Attribute key
            <input
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder="credit_score"
              required
            />
          </label>
          <label>
            Value
            <input
              type="number"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              required
            />
          </label>
        </div>
        <div className="actions">
          <button type="submit" disabled={busy || !account} aria-busy={busy}>
            {busy ? 'Requesting…' : 'Request demo credential'}
          </button>
          <button type="button" className="secondary" onClick={handleRefresh}>
            Refresh vault
          </button>
        </div>
      </form>

      {error && <p className="error">{error}</p>}

      <div>
        {credentials.length === 0 ? (
          <p className="empty">No credentials stored yet.</p>
        ) : (
          credentials.map((cred) => (
            <div className="credential-row" key={cred.id}>
              <div>
                <strong>{cred.key}</strong> = {cred.value}
                <div className="credential-meta">
                  commitment: <span className="mono">{cred.commitment}</span>
                </div>
              </div>
              <button
                className="secondary outline"
                onClick={() => handleDelete(cred.id)}
              >
                Remove
              </button>
            </div>
          ))
        )}
      </div>
    </article>
  )
}
