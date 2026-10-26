// Hardware-backed credential vault.
//
// Credentials are encrypted with AES-256-GCM. The AES key is derived from a
// WebAuthn PRF output (FaceID / TouchID / Windows Hello). If the authenticator
// or browser does not support PRF, we fall back to a randomly generated key
// stored in IndexedDB. The fallback is clearly labelled in the UI: it protects
// against casual inspection but NOT against an attacker with local storage
// access. Remove the fallback before handling real credentials.

const DB_NAME = 'meritable-vault'
const DB_VERSION = 1
const CRED_STORE = 'credentials'
const META_STORE = 'meta'

const PRF_SALT = new TextEncoder().encode('meritable-vault-prf-v1')
const PRF_INFO = new TextEncoder().encode('meritable-vault-aes-gcm-v1')

let cachedKey = null
let cachedMode = null

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION)
    req.onupgradeneeded = () => {
      const db = req.result
      if (!db.objectStoreNames.contains(CRED_STORE)) {
        db.createObjectStore(CRED_STORE, { keyPath: 'id' })
      }
      if (!db.objectStoreNames.contains(META_STORE)) {
        db.createObjectStore(META_STORE)
      }
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

async function withStore(storeName, mode, fn) {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, mode)
    const store = tx.objectStore(storeName)
    let result
    try {
      result = fn(store)
    } catch (err) {
      reject(err)
      return
    }
    tx.oncomplete = () => resolve(result)
    tx.onerror = () => reject(tx.error)
    tx.onabort = () => reject(tx.error)
  })
}

function reqToPromise(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

async function getMeta(key) {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(META_STORE, 'readonly')
    const req = tx.objectStore(META_STORE).get(key)
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

async function setMeta(key, value) {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(META_STORE, 'readwrite')
    tx.objectStore(META_STORE).put(value, key)
    tx.oncomplete = () => resolve()
    tx.onerror = () => reject(tx.error)
  })
}

async function putCredential(record) {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(CRED_STORE, 'readwrite')
    tx.objectStore(CRED_STORE).put(record)
    tx.oncomplete = () => resolve()
    tx.onerror = () => reject(tx.error)
  })
}

async function getAllCredentials() {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(CRED_STORE, 'readonly')
    const req = tx.objectStore(CRED_STORE).getAll()
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

async function deleteCredentialRecord(id) {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction(CRED_STORE, 'readwrite')
    tx.objectStore(CRED_STORE).delete(id)
    tx.oncomplete = () => resolve()
    tx.onerror = () => reject(tx.error)
  })
}

async function registerPasskey() {
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: 'Meritable', id: window.location.hostname },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: 'meritable-user',
        displayName: 'Meritable User',
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: {
        userVerification: 'required',
        residentKey: 'preferred',
      },
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  })
  if (!credential) throw new Error('Passkey creation was cancelled')
  const rawId = new Uint8Array(credential.rawId)
  await setMeta('credentialId', Array.from(rawId))
  const prf = credential.getClientExtensionResults().prf
  if (prf?.results?.first) return prf.results.first
  // Some browsers only return PRF results on assertion, not creation.
  return assertPrf(rawId)
}

async function assertPrf(credentialId) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: 'public-key', id: credentialId }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  })
  if (!assertion) throw new Error('Passkey assertion was cancelled')
  const prf = assertion.getClientExtensionResults().prf
  if (!prf?.results?.first) {
    throw new Error('Authenticator did not return a PRF result')
  }
  return prf.results.first
}

async function deriveAesKey(prfOutput) {
  const baseKey = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, [
    'deriveKey',
  ])
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32),
      info: PRF_INFO,
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

async function getDevKey() {
  let raw = await getMeta('devKey')
  if (!raw) {
    raw = Array.from(crypto.getRandomValues(new Uint8Array(32)))
    await setMeta('devKey', raw)
  }
  return crypto.subtle.importKey('raw', new Uint8Array(raw), 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ])
}

/**
 * Unlock the vault once per session. Prompts for biometrics when WebAuthn PRF
 * is available; otherwise falls back to a local dev key.
 *
 * @returns {Promise<{key: CryptoKey, mode: 'webauthn-prf'|'dev-insecure'}>}
 */
export async function unlockVault() {
  if (cachedKey) return { key: cachedKey, mode: cachedMode }

  try {
    const prfOutput = await registerOrAssert()
    const key = await deriveAesKey(prfOutput)
    cachedKey = key
    cachedMode = 'webauthn-prf'
  } catch (err) {
    console.warn(
      'WebAuthn PRF unavailable; using an insecure dev vault key. ' +
        'This is NOT suitable for real credentials.',
      err,
    )
    cachedKey = await getDevKey()
    cachedMode = 'dev-insecure'
  }

  return { key: cachedKey, mode: cachedMode }
}

async function registerOrAssert() {
  const credentialId = await getMeta('credentialId')
  if (!credentialId) return registerPasskey()
  return assertPrf(new Uint8Array(credentialId))
}

export async function storeCredential(credential) {
  const { key, mode } = await unlockVault()
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const data = new TextEncoder().encode(JSON.stringify(credential))
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data)

  const record = {
    id: crypto.randomUUID(),
    mode,
    iv: Array.from(iv),
    ciphertext: Array.from(new Uint8Array(ciphertext)),
    createdAt: Date.now(),
  }
  await putCredential(record)
  return { ...credential, id: record.id, mode, createdAt: record.createdAt }
}

export async function listCredentials() {
  const { key } = await unlockVault()
  const records = await getAllCredentials()
  const results = []

  for (const record of records) {
    try {
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(record.iv) },
        key,
        new Uint8Array(record.ciphertext),
      )
      const credential = JSON.parse(new TextDecoder().decode(plaintext))
      results.push({
        ...credential,
        id: record.id,
        mode: record.mode,
        createdAt: record.createdAt,
      })
    } catch (err) {
      console.warn(`Could not decrypt credential ${record.id}`, err)
    }
  }

  return results
}

export async function deleteCredential(id) {
  await deleteCredentialRecord(id)
}

/** Clear the cached key. The next vault operation will prompt for biometrics. */
export function lockVault() {
  cachedKey = null
  cachedMode = null
}
