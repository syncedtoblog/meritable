# Meritable PWA

React + Vite + Pico.css frontend for the Meritable credential verifier.

No Tailwind. Plain JavaScript. Pico.css provides the base styles, with a small
custom layer in `src/styles.css`.

## Run locally

```bash
cd pwa
cp .env.example .env      # set VITE_CONTRACT_ID after deploying
npm install
npm run dev               # http://localhost:5173
```

Start the issuer service first:

```bash
cargo run -p issuer       # http://localhost:8080
```

## Build

```bash
npm run build             # dist/
npm run preview
```

## Modules

| File | Responsibility |
| --- | --- |
| `src/lib/config.js` | Env-driven configuration and operator labels |
| `src/lib/fields.js` | Stellar address / string → BN254 field conversion |
| `src/lib/issuer.js` | `POST /issue` client for the Rust issuer |
| `src/lib/vault.js` | WebAuthn PRF + AES-256-GCM + IndexedDB vault |
| `src/lib/prover.worker.js` | Noir witness + UltraHonk proof generation |
| `src/lib/prover.js` | Worker wrapper and circuit input construction |
| `src/lib/stellar.js` | Freighter connection and Soroban contract calls |

## Components

| Component | Purpose |
| --- | --- |
| `WalletPanel` | Connect Freighter and show network |
| `HowItWorks` | Explainer with the Alice / issuer / verifier flow diagram |
| `VaultPanel` | Request a demo credential and store it encrypted |
| `ProvePanel` | Generate a proof and submit the verification transaction |
| `SessionPanel` | Query `is_session_valid` and show local proof history |

## Vault behaviour

Credentials are encrypted with AES-256-GCM before being written to IndexedDB.

- **Preferred path:** the AES key is derived from a WebAuthn PRF output. The
  authenticator prompts for FaceID / TouchID / Windows Hello on the first vault
  operation of each session. The key is cached in memory for the rest of the
  session; reloading the page requires another biometric prompt.
- **Fallback path:** if the browser or authenticator does not support PRF, a
  random key is generated and stored in IndexedDB. This is labelled
  `dev-insecure` and **does not protect against local storage access**. Remove
  the fallback before handling real credentials.

## Proving

Proof generation runs in `prover.worker.js`, a module Web Worker. The worker
loads `/circuit/meritable_circuit.json`, runs `Noir.execute(inputs)`, then calls
`UltraHonkBackend.generateProof(witness, { keccak: true })`.

The worker returns the raw 14,592-byte proof and the seven public inputs as hex
strings. The main thread forwards them to the Soroban transaction builder.

### Multithreading

`@aztec/bb.js` can use multiple threads when `SharedArrayBuffer` is available.
That requires `Cross-Origin-Opener-Policy: same-origin` and
`Cross-Origin-Embedder-Policy: require-corp` headers. Without them, proving
falls back to single-threaded and takes longer.

Enabling COEP also requires the issuer API to send
`Cross-Origin-Resource-Policy: cross-origin`; the current Rust CORS layer does
not set that header. For local development we therefore leave COEP off.

## Contract calls

`submitVerification` builds a `verify_credential` call with:

```text
user | issuer_pubkey_x | issuer_pubkey_y | user_address | target_key
     | operator | threshold | nonce | proof_bytes
```

The seven public inputs come from the prover in exactly this order. Each is
converted back to 32 big-endian bytes before being passed as `Bytes`.

`isSessionValid` converts the target key string to its field representation
(`stringToField`) before querying `is_session_valid`.

## Deployment

`render.yaml` expects a Node service rooted at `pwa/`. Use:

```text
Build: npm install && npm run build
Start: npx vite preview --host 0.0.0.0 --port $PORT
```

Set `VITE_ISSUER_URL`, `VITE_CONTRACT_ID`, `VITE_NETWORK_PASSPHRASE`, and
`VITE_RPC_URL` in the Render dashboard.
