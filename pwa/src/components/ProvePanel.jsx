import { useState } from 'react'
import { generateProof } from '../lib/prover.js'
import { submitVerification } from '../lib/stellar.js'

const OPERATORS = [
  { value: 0, label: '>= (greater than or equal)' },
  { value: 1, label: '<= (less than or equal)' },
  { value: 2, label: '== (exactly equal)' },
  { value: 3, label: '> (strictly greater than)' },
  { value: 4, label: '< (strictly less than)' },
  { value: 5, label: '!= (not equal)' },
]

export default function ProvePanel({ account, credentials, onSessionCreated }) {
  const [credentialId, setCredentialId] = useState('')
  const [operator, setOperator] = useState(0)
  const [threshold, setThreshold] = useState(700)
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState(null)
  const [error, setError] = useState(null)

  async function handleProve(e) {
    e.preventDefault()
    if (!account) {
      setError('Connect a wallet first.')
      return
    }
    const credential = credentials.find((c) => c.id === credentialId)
    if (!credential) {
      setError('Select a credential from the vault.')
      return
    }

    setBusy(true)
    setError(null)
    setStatus('Generating proof…')
    try {
      const { proofBytes, publicInputs, nonce } = await generateProof({
        credential,
        operator,
        threshold: Number(threshold),
      })

      setStatus('Submitting transaction…')
      const result = await submitVerification({
        account,
        publicInputs,
        proofBytes,
        operator,
        threshold: Number(threshold),
        nonce,
      })

      setStatus(`Verified. Tx: ${result.hash}`)
      onSessionCreated({
        hash: result.hash,
        key: credential.key,
        threshold: Number(threshold),
        operator,
        at: Date.now(),
      })
    } catch (err) {
      setError(err.message)
      setStatus(null)
    } finally {
      setBusy(false)
    }
  }

  return (
    <article className="card">
      <h2>3. Prove a condition</h2>
      <p>
        Generate an UltraHonk proof in a Web Worker and submit it to the Soroban
        verifier. The credential value never leaves the browser.
      </p>

      <form onSubmit={handleProve}>
        <label>
          Credential
          <select
            value={credentialId}
            onChange={(e) => setCredentialId(e.target.value)}
            required
          >
            <option value="">Select a stored credential…</option>
            {credentials.map((cred) => (
              <option key={cred.id} value={cred.id}>
                {cred.key} = {cred.value}
              </option>
            ))}
          </select>
        </label>

        <div className="grid">
          <label>
            Operator
            <select
              value={operator}
              onChange={(e) => setOperator(Number(e.target.value))}
            >
              {OPERATORS.map((op) => (
                <option key={op.value} value={op.value}>
                  {op.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            Threshold
            <input
              type="number"
              value={threshold}
              onChange={(e) => setThreshold(e.target.value)}
              required
            />
          </label>
        </div>

        <div className="actions">
          <button type="submit" disabled={busy || !account} aria-busy={busy}>
            {busy ? 'Working…' : 'Generate proof & verify'}
          </button>
        </div>
      </form>

      {status && <p className="status status-ok">{status}</p>}
      {error && <p className="error">{error}</p>}
    </article>
  )
}
