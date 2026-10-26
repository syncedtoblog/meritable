import { useState } from 'react'
import HowItWorks from './components/HowItWorks.jsx'
import WalletPanel from './components/WalletPanel.jsx'
import VaultPanel from './components/VaultPanel.jsx'
import ProvePanel from './components/ProvePanel.jsx'
import SessionPanel from './components/SessionPanel.jsx'

export default function App() {
  const [account, setAccount] = useState(null)
  const [credentials, setCredentials] = useState([])
  const [sessions, setSessions] = useState([])

  return (
    <main className="container">
      <header>
        <hgroup>
          <h1>Meritable</h1>
          <p>Prove a property of your private data without revealing the data.</p>
        </hgroup>
      </header>

      <HowItWorks />

      <div className="notice">
        <strong>Demo issuer.</strong> Credentials requested here are signed by a
        development key committed to the repository. No identity verification is
        performed. Do not use real personal data.
      </div>

      <WalletPanel account={account} onAccountChange={setAccount} />

      <VaultPanel
        account={account}
        credentials={credentials}
        onCredentialsChange={setCredentials}
      />

      <ProvePanel
        account={account}
        credentials={credentials}
        onSessionCreated={(session) => setSessions((prev) => [...prev, session])}
      />

      <SessionPanel account={account} sessions={sessions} />
    </main>
  )
}
