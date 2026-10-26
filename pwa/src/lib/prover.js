import {
  addressToField,
  bigintToHex,
  stringToField,
  randomNonce,
} from './fields.js'

let worker = null
let nextId = 0
const pending = new Map()

function getWorker() {
  if (!worker) {
    worker = new Worker(new URL('./prover.worker.js', import.meta.url), {
      type: 'module',
    })
    worker.onmessage = (event) => {
      const { id, type, payload } = event.data
      const entry = pending.get(id)
      if (!entry) return
      pending.delete(id)
      if (type === 'result') {
        entry.resolve({
          proofBytes: new Uint8Array(payload.proof),
          publicInputs: payload.publicInputs,
        })
      } else {
        entry.reject(new Error(payload.message))
      }
    }
    worker.onerror = (event) => {
      const error = new Error(event.message || 'Prover worker crashed')
      for (const { reject } of pending.values()) reject(error)
      pending.clear()
    }
  }
  return worker
}

function callWorker(type, payload) {
  return new Promise((resolve, reject) => {
    const id = ++nextId
    pending.set(id, { resolve, reject })
    getWorker().postMessage({ id, type, payload })
  })
}

/**
 * Build the circuit input map from an issuer credential and generate an
 * UltraHonk proof inside the Web Worker.
 *
 * @param {object} args
 * @param {object} args.credential  Credential returned by the issuer API.
 * @param {number} args.operator    Operator code 0-5.
 * @param {number|string} args.threshold
 * @param {string} [args.nonce]     u64 nonce; generated when omitted.
 * @returns {Promise<{proofBytes: Uint8Array, publicInputs: string[], nonce: string}>}
 */
export async function generateProof({
  credential,
  operator,
  threshold,
  nonce = randomNonce(),
}) {
  const keyField = stringToField(credential.key)
  const valueField = BigInt(credential.value)
  const userAddressField = addressToField(credential.user_address)

  const inputs = {
    key: bigintToHex(keyField),
    value: bigintToHex(valueField),
    salt: credential.salt,
    sig_s_lo: credential.signature.sig_s_lo,
    sig_s_hi: credential.signature.sig_s_hi,
    sig_e_lo: credential.signature.sig_e_lo,
    sig_e_hi: credential.signature.sig_e_hi,
    issuer_pubkey_x: credential.issuer_pubkey.x,
    issuer_pubkey_y: credential.issuer_pubkey.y,
    user_address: bigintToHex(userAddressField),
    target_key: bigintToHex(keyField),
    operator: Number(operator),
    threshold: String(threshold),
    nonce: String(nonce),
  }

  const { proofBytes, publicInputs } = await callWorker('prove', { inputs })
  return { proofBytes, publicInputs, nonce: String(nonce) }
}

export { randomNonce }
