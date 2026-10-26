import {
  Address,
  Contract,
  TransactionBuilder,
  nativeToScVal,
  scValToNative,
  rpc,
  BASE_FEE,
} from '@stellar/stellar-sdk'
import {
  isConnected,
  requestAccess,
  getNetworkDetails,
  signTransaction,
} from '@stellar/freighter-api'
import { CONFIG } from './config.js'
import { bigintToHex, hexToBytes32, stringToField } from './fields.js'

function createServer() {
  const allowHttp = CONFIG.rpcUrl.startsWith('http://')
  return new rpc.Server(CONFIG.rpcUrl, { allowHttp })
}

export async function connectFreighter() {
  // isConnected() has a 2s timeout when the extension is absent, so we fail
  // fast instead of hanging on a message that will never be answered.
  const status = await isConnected()
  if (status.error) {
    throw new Error(status.error.message || 'Freighter is not available')
  }
  if (!status.isConnected) {
    throw new Error(
      'Freighter extension not detected. Install it from https://freighter.app, unlock it, and refresh this page.',
    )
  }

  // requestAccess() triggers the permission prompt when access has not yet
  // been granted for this origin. getAddress() alone does not prompt.
  const result = await requestAccess()
  if (result.error) {
    throw new Error(result.error.message || 'Freighter access was rejected')
  }
  if (!result.address) {
    throw new Error(
      'Freighter returned no address. Unlock the extension and try again.',
    )
  }
  return result.address
}

export async function getFreighterNetwork() {
  const result = await getNetworkDetails()
  if (result.error) {
    throw new Error(result.error.message || 'Could not read Freighter network')
  }
  return result.network
}

async function signWithFreighter(transactionXdr) {
  const result = await signTransaction(transactionXdr, {
    networkPassphrase: CONFIG.networkPassphrase,
  })
  if (result.error) {
    throw new Error(result.error.message || 'Transaction signing was rejected')
  }
  return result.signedTxXdr
}

async function waitForTransaction(server, hash, { attempts = 30, delayMs = 2000 } = {}) {
  for (let i = 0; i < attempts; i += 1) {
    const result = await server.getTransaction(hash)
    if (result.status === 'SUCCESS') return result
    if (result.status === 'FAILED') {
      throw new Error(`Transaction failed: ${hash}`)
    }
    await new Promise((resolve) => setTimeout(resolve, delayMs))
  }
  throw new Error(`Timed out waiting for transaction ${hash}`)
}

/**
 * Submit an UltraHonk proof to the Soroban verifier contract.
 *
 * @param {object} args
 * @param {string} args.account        Stellar address of the submitting user.
 * @param {string[]} args.publicInputs Public inputs from the prover (hex strings).
 * @param {Uint8Array} args.proofBytes  Raw UltraHonk proof bytes.
 * @param {number} args.operator        Operator code 0-5.
 * @param {number|string} args.threshold
 * @param {string} args.nonce           u64 nonce used in the proof.
 * @returns {Promise<{hash: string}>}
 */
export async function submitVerification({
  account,
  publicInputs,
  proofBytes,
  operator,
  threshold,
  nonce,
}) {
  if (!CONFIG.contractId) {
    throw new Error(
      'VITE_CONTRACT_ID is not configured. Deploy the contract and set the env var.',
    )
  }
  if (publicInputs.length !== 7) {
    throw new Error(`Expected 7 public inputs, received ${publicInputs.length}`)
  }

  const server = createServer()
  const source = await server.getAccount(account)
  const contract = new Contract(CONFIG.contractId)

  const op = contract.call(
    'verify_credential',
    Address.fromString(account).toScVal(),
    nativeToScVal(hexToBytes32(publicInputs[0]), { type: 'bytes' }),
    nativeToScVal(hexToBytes32(publicInputs[1]), { type: 'bytes' }),
    nativeToScVal(hexToBytes32(publicInputs[2]), { type: 'bytes' }),
    nativeToScVal(hexToBytes32(publicInputs[3]), { type: 'bytes' }),
    nativeToScVal(Number(operator), { type: 'u32' }),
    nativeToScVal(BigInt(threshold), { type: 'u64' }),
    nativeToScVal(BigInt(nonce), { type: 'u64' }),
    nativeToScVal(proofBytes, { type: 'bytes' }),
  )

  const tx = new TransactionBuilder(source, {
    fee: BASE_FEE,
    networkPassphrase: CONFIG.networkPassphrase,
  })
    .addOperation(op)
    .setTimeout(60)
    .build()

  const simulation = await server.simulateTransaction(tx)
  if (rpc.Api.isSimulationError(simulation)) {
    throw new Error(`Simulation failed: ${simulation.error}`)
  }

  const prepared = rpc.assembleTransaction(tx, simulation).build()
  const signedXdr = await signWithFreighter(prepared.toXDR())
  const signedTx = TransactionBuilder.fromXDR(signedXdr, CONFIG.networkPassphrase)

  const sendResult = await server.sendTransaction(signedTx)
  if (sendResult.status === 'ERROR') {
    throw new Error(
      `Submission failed: ${JSON.stringify(sendResult.errorResult || sendResult)}`,
    )
  }

  await waitForTransaction(server, sendResult.hash)
  return { hash: sendResult.hash }
}

/**
 * Read `is_session_valid(user, target_key)` from the verifier contract.
 *
 * @param {object} args
 * @param {string} args.account   Stellar address to query.
 * @param {string} args.targetKey Target key string (e.g. "credit_score").
 * @returns {Promise<boolean>}
 */
export async function isSessionValid({ account, targetKey }) {
  if (!CONFIG.contractId) {
    throw new Error('VITE_CONTRACT_ID is not configured.')
  }

  const server = createServer()
  const source = await server.getAccount(account)
  const contract = new Contract(CONFIG.contractId)

  const tx = new TransactionBuilder(source, {
    fee: BASE_FEE,
    networkPassphrase: CONFIG.networkPassphrase,
  })
    .addOperation(
      contract.call(
        'is_session_valid',
        Address.fromString(account).toScVal(),
        nativeToScVal(hexToBytes32(bigintToHex(stringToField(targetKey))), {
          type: 'bytes',
        }),
      ),
    )
    .setTimeout(30)
    .build()

  const simulation = await server.simulateTransaction(tx)
  if (rpc.Api.isSimulationError(simulation)) {
    throw new Error(`Simulation failed: ${simulation.error}`)
  }
  if (!simulation.result) return false
  return Boolean(scValToNative(simulation.result.retval))
}
