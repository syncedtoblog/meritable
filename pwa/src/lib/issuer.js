import { CONFIG } from './config.js'

/**
 * Request a demo credential from the issuer API.
 * The response contains the salt, commitment, issuer public key and signature
 * needed to build a Noir witness.
 */
export async function requestCredential({ userAddress, key, value }) {
  const res = await fetch(`${CONFIG.issuerUrl}/issue`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      user_address: userAddress,
      key,
      value: Number(value),
    }),
  })

  if (!res.ok) {
    const text = await res.text()
    throw new Error(`Issuer error ${res.status}: ${text}`)
  }

  return res.json()
}

export async function healthCheck() {
  const res = await fetch(`${CONFIG.issuerUrl}/health`)
  if (!res.ok) throw new Error(`Issuer health check failed: ${res.status}`)
  return res.json()
}
