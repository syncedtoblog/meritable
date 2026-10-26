import { useState } from 'react'
import { connectFreighter, getFreighterNetwork } from '../lib/stellar.js'

export default function WalletPanel({ account, onAccountChange }) {
  const [error, setError] = useState(null)
  const [network, setNetwork] = useState(null)
  const [busy, setBusy] = useState(false)

  async function handleConnect() {
    setBusy(true)
    setError(null)
    try {
      const addr = await connectFreighter()
      const net = await getFreighterNetwork()
      setNetwork(net)
      onAccountChange(addr)
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  function handleDisconnect() {
    setNetwork(null)
    onAccountChange(null)
  }

  return (
    <article className="card">
      <h2>1. Wallet</h2>
      <p>Connect the Stellar wallet that will authorize the verification transaction.</p>

      {account ? (
        <>
          <p>
            Connected: <span className="mono">{account}</span>
            {network ? <> on <strong>{network}</strong></> : null}
          </p>
          <div className="actions">
            <button className="secondary" onClick={handleDisconnect}>
              Disconnect
            </button>
          </div>
        </>
      ) : (
        <div className="actions">
          <button onClick={handleConnect} disabled={busy} aria-busy={busy}>
            {busy ? 'Connecting…' : 'Connect Freighter'}
          </button>
        </div>
      )}

      {error && <p className="error">{error}</p>}
    </article>
  )
}
