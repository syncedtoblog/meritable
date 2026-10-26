export default function HowItWorks() {
  return (
    <section className="card how" aria-labelledby="how-title">
      <header className="how-header">
        <p className="eyebrow">The idea</p>
        <h2 id="how-title">How it works</h2>
        <p className="story">
          <strong>Meet Alice.</strong> Her bank knows her credit score is 812.
          She wants a lender to know she qualifies for the Gold tier
          (score&nbsp;≥&nbsp;700) without handing over the score, her statement,
          or the bank's signature.
        </p>
      </header>

      <div
        className="flow"
        role="img"
        aria-label="Alice's issuer signs a credential, Alice generates a zero-knowledge proof on her device, and the verifier checks the proof on Soroban."
      >
        <div className="flow-card">
          <span className="flow-icon" aria-hidden="true">🏦</span>
          <h3>1. Issuer attests</h3>
          <p>
            The bank computes a commitment over Alice's private data and signs
            it. The data never leaves her device.
          </p>
          <span className="flow-tag">signed credential</span>
        </div>

        <div className="flow-arrow" aria-hidden="true">→</div>

        <div className="flow-card private">
          <span className="flow-icon" aria-hidden="true">🔐</span>
          <h3>2. Alice proves</h3>
          <p>
            Her browser generates a zero-knowledge proof that the signed data
            satisfies a condition, e.g. <strong>score ≥ 700</strong>.
          </p>
          <span className="flow-tag">proof only</span>
        </div>

        <div className="flow-arrow" aria-hidden="true">→</div>

        <div className="flow-card">
          <span className="flow-icon" aria-hidden="true">🛡️</span>
          <h3>3. Verifier checks</h3>
          <p>
            A Soroban contract verifies the proof and grants a short-lived
            session. It learns the claim is true, not the score.
          </p>
          <span className="flow-tag">true / false</span>
        </div>
      </div>

      <div className="compare">
        <div className="compare-card learns">
          <h3>What the verifier learns</h3>
          <ul>
            <li>The condition holds (e.g. “Gold tier”).</li>
            <li>Which issuer public key attested it.</li>
            <li>Alice's wallet address, for the session.</li>
            <li>That the proof is fresh (single-use nonce).</li>
          </ul>
        </div>
        <div className="compare-card private">
          <h3>What stays private</h3>
          <ul>
            <li>The exact score (812).</li>
            <li>The commitment salt and issuer signature.</li>
            <li>Every attribute not being proven.</li>
          </ul>
        </div>
      </div>

      <div className="use-cases">
        <h3>Same pattern, many uses</h3>
        <ul className="pill-list">
          <li>Age over 18 without a birthdate</li>
          <li>Credit tier without a score</li>
          <li>Income range without payslips</li>
          <li>Healthcare eligibility without a diagnosis</li>
          <li>Accredited investor status</li>
          <li>Employment or membership</li>
        </ul>
      </div>

      <p className="how-note">
        In this demo the issuer is a local development service, and the on-chain
        verifier currently uses a non-ZK proof flavor. The flow is real; the
        privacy guarantees are demo-grade. See the project README.
      </p>
    </section>
  )
}
