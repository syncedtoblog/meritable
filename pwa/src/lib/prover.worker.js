import { Noir } from '@noir-lang/noir_js'
import { UltraHonkBackend } from '@aztec/bb.js'

let circuitPromise = null

function loadCircuit() {
  if (!circuitPromise) {
    circuitPromise = fetch('/circuit/meritable_circuit.json').then((res) => {
      if (!res.ok) {
        throw new Error(`Failed to load circuit artifact: ${res.status}`)
      }
      return res.json()
    })
  }
  return circuitPromise
}

self.onmessage = async (event) => {
  const { id, type, payload } = event.data
  if (type !== 'prove') return

  try {
    const circuit = await loadCircuit()

    const noir = new Noir(circuit)
    const { witness } = await noir.execute(payload.inputs)

    const backend = new UltraHonkBackend(circuit.bytecode)
    const { proof, publicInputs } = await backend.generateProof(witness, {
      keccak: true,
    })
    await backend.destroy()

    // Transfer the proof buffer without copying it.
    const proofBuffer = proof.buffer.slice(
      proof.byteOffset,
      proof.byteOffset + proof.byteLength,
    )
    self.postMessage(
      { id, type: 'result', payload: { proof: proofBuffer, publicInputs } },
      [proofBuffer],
    )
  } catch (err) {
    self.postMessage({
      id,
      type: 'error',
      payload: { message: err?.message || String(err) },
    })
  }
}
