import { StrKey } from '@stellar/stellar-sdk'

// BN254 scalar field modulus (Noir's `Field`).
const BN254_MODULUS =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n

function bytesToBigInt(bytes) {
  let value = 0n
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte)
  }
  return value
}

/** Decode a Stellar G... address into the BN254 field element used by the circuit. */
export function addressToField(address) {
  const raw = StrKey.decodeEd25519PublicKey(address)
  return bytesToBigInt(raw) % BN254_MODULUS
}

/** Mirror of issuer/src/crypto.rs::string_to_field (right-aligned ASCII in 32 bytes). */
export function stringToField(str) {
  const bytes = new TextEncoder().encode(str)
  const buf = new Uint8Array(32)
  const len = Math.min(bytes.length, 32)
  buf.set(bytes.subarray(0, len), 32 - len)
  return bytesToBigInt(buf) % BN254_MODULUS
}

/** Render a field element as a 0x-prefixed 64-hex-digit string. */
export function bigintToHex(value) {
  return '0x' + value.toString(16).padStart(64, '0')
}

/** Convert a hex field element (0x...) into a 32-byte big-endian Uint8Array. */
export function hexToBytes32(hex) {
  const sanitized = BigInt(hex).toString(16).padStart(64, '0')
  const bytes = new Uint8Array(32)
  for (let i = 0; i < 32; i += 1) {
    bytes[i] = parseInt(sanitized.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

/** Convert a Uint8Array into a 0x-prefixed hex string. */
export function bytesToHex(bytes) {
  return (
    '0x' +
    Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  )
}

/** Generate a random u64 nonce as a decimal string. */
export function randomNonce() {
  const bytes = crypto.getRandomValues(new Uint8Array(8))
  let value = 0n
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte)
  }
  // Avoid 0 so the contract's nonce storage key is unambiguous.
  return (value % (2n ** 63n - 1n) + 1n).toString()
}
