function normalizeHttpUrl(value, fallback) {
  const raw = (value || fallback || '').trim().replace(/\/+$/, '')
  if (!raw) return ''
  return /^https?:\/\//i.test(raw) ? raw : `https://${raw}`
}

export const CONFIG = {
  issuerUrl: normalizeHttpUrl(
    import.meta.env.VITE_ISSUER_URL,
    'http://localhost:8080',
  ),
  contractId: (import.meta.env.VITE_CONTRACT_ID || '').trim(),
  networkPassphrase:
    import.meta.env.VITE_NETWORK_PASSPHRASE || 'Test SDF Network ; September 2015',
  rpcUrl: import.meta.env.VITE_RPC_URL || 'https://soroban-testnet.stellar.org',
  circuitPath: '/circuit/meritable_circuit.json',
}

export const OPERATOR_LABELS = {
  0: '>=',
  1: '<=',
  2: '==',
  3: '>',
  4: '<',
  5: '!=',
}
