export const CONFIG = {
  issuerUrl: import.meta.env.VITE_ISSUER_URL || 'http://localhost:8080',
  contractId: import.meta.env.VITE_CONTRACT_ID || '',
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
