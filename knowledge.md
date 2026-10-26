# ZK Stack on Stellar/Soroban — Concepts & Pipeline

A reference document explaining how the pieces of the Meritable ZK stack fit
together. Covers BN254, Poseidon, Barretenberg (`bb`), UltraHonk flavors, and
the on-chain verifier.

---

## The stack, bottom to top

```text
┌─────────────────────────────────────────────────────┐
│  UltraZKFlavor / UltraKeccakFlavor                  │  ← configuration
│  (which proof system variant BB uses)               │
├─────────────────────────────────────────────────────┤
│  bb (Barretenberg)                                  │  ← toolchain
│  (generates proofs + VKs, runs on your machine)     │
├─────────────────────────────────────────────────────┤
│  BN254 + Poseidon host functions                    │  ← network primitives
│  (math operations inside the Soroban VM)            │
├─────────────────────────────────────────────────────┤
│  Stellar / Soroban network                          │  ← execution
│  (runs the contract, meters the host calls)         │
└─────────────────────────────────────────────────────┘
```

The layers are independent. The network provides math primitives. `bb` uses
those primitives to produce proofs. The flavor decides what the proof hides.
The contract checks the proof using the network's math.

---

## Layer 1: BN254 and Poseidon — the network's math

These are **host functions** the Soroban VM exposes to contracts. They are
implemented natively in the host (Rust/C++), so contracts don't pay the cost of
doing the math in interpreted WASM.

### BN254 (CAP-0074, Protocol 25)

A pairing-friendly elliptic curve. Host functions:

```text
bn254_g1_add              point1 + point2
bn254_g1_mul              scalar × point
bn254_multi_pairing_check pairing equation check
bn254_fr_add / fr_mul / fr_sub / fr_inv / fr_pow   field arithmetic
```

Used for:
- polynomial commitments
- pairing checks in Shplemini
- multi-scalar multiplication (MSM)

### Poseidon / Poseidon2 (CAP-0075, Protocol 25)

A ZK-friendly hash function. Host functions:

```text
poseidon_permutation      generic Poseidon
poseidon2_permutation     Poseidon2
```

Used for:
- the commitment in the Noir circuit (`poseidon::bn254::hash_4`)
- the verifier's internal relations during sumcheck

**Analogy:** BN254 is the calculator on the desk. Poseidon is the hash stamp
next to it. The contract calls them; the host runs them natively.

### Protocol versioning

| Capability | CAP | Protocol |
| --- | --- | --- |
| BN254 host functions | CAP-0074 | 25 |
| Poseidon/Poseidon2 host functions | CAP-0075 | 25 |
| Efficient ZK BN254 use cases | CAP-0080 | 26 |

The primitives landed in **Protocol 25 (X-Ray)**. The `ultrahonk_soroban_verifier`
crate is built against Soroban SDK 28.0.0 and requires **Protocol 28+**, even
though the primitives are available from 25. The network is currently on
Protocol 29.

---

## Layer 2: bb — the prover toolchain

`bb` (Barretenberg) is **not** on the network. It's a C++ program compiled to
WASM and native binaries. It runs:

- on your laptop when you generate `vk.bin`
- in your browser when the PWA generates a proof
- in CI when you rebuild artifacts

### What bb does

1. Takes the ACIR (compiled circuit) and the witness (private inputs)
2. Runs the UltraHonk prover
3. Outputs a proof file (456 field elements, 14,592 bytes)

### Commands used in this project

```bash
bb write_vk \
  --scheme ultra_honk \
  --oracle_hash keccak \
  --bytecode_path target/meritable_circuit.json \
  --output_path target \
  --output_format bytes_and_fields

bb prove \
  --scheme ultra_honk \
  --oracle_hash keccak \
  --bytecode_path target/meritable_circuit.json \
  --witness_path target/meritable_circuit.gz \
  --output_path target \
  --output_format bytes_and_fields
```

**Analogy:** BN254 is the calculator. bb is the accountant who uses the
calculator to produce a signed audit report.

---

## Layer 3: UltraHonk flavors — the prover's configuration

UltraHonk has multiple variants. The "flavor" determines two things:

1. **Which hash function** the Fiat–Shamir transcript uses (Keccak vs Poseidon2)
2. **Whether the proof hides the witness** (ZK vs non-ZK)

| Flavor | Transcript | Hiding | Status |
| --- | --- | --- | --- |
| `UltraKeccakFlavor` | Keccak | ❌ non-ZK | Implemented in Soroban verifier |
| `UltraZKFlavor` | Poseidon2 | ✅ ZK | Not implemented |

### What "ZK" means here

A true zero-knowledge proof lets you prove:

> "I know a secret value that satisfies this condition"

without revealing **anything** about the secret beyond that fact.

The "ZK" in `UltraZKFlavor` means the prover adds a **hiding polynomial** and
**Libra commitments** so the proof's intermediate evaluations don't reveal the
witness. `UltraKeccakFlavor` skips those, so the proof carries witness-dependent
values in the clear.

### Why the Soroban verifier uses the non-ZK flavor

The verifier crate's own README states:

> It provides **no witness-hiding guarantee**: a proof carries witness-dependent
> protocol messages... Do not use it for privacy-sensitive circuits.

The maintainers chose the non-ZK flavor because:

1. It's the default output of `bb prove -s ultra_honk --oracle_hash keccak`
2. The ZK flavor adds significant complexity (hiding polynomial + Libra)
3. The ZK flavor means larger proofs and more on-chain verification cost
4. The examples are explicitly labelled "Demo only" and "instructional"

**Analogy:** Same accountant, two report formats. One redacts the source
documents; one doesn't. The current verifier only accepts the unredacted format.

---

## Layer 4: The network — the judge

Soroban runs the verifier contract. It receives the proof and public inputs and
checks:

1. Recompute the Fiat–Shamir transcript (Keccak)
2. Check sumcheck
3. Check Shplemini batch openings using BN254 pairings
4. Return valid / invalid

The network only knows the proof bytes and the public inputs. It has no idea
whether the prover hid the witness — that's determined by which flavor produced
the bytes.

### Where the host functions are called

In `ultrahonk-soroban-verifier`:

```rust
// ec.rs
env.crypto().bn254().g1_msm(vp, vs)          // MSM
env.crypto().bn254().pairing_check(g1s, g2s) // pairing

// field.rs
env.crypto().bn254().$host_fn(&self.0, &rhs.0) // fr_add, fr_mul, etc.

// relations.rs
accumulate_poseidon_external_relation(...)   // Poseidon2 relations
accumulate_poseidon_internal_relation(...)
```

---

## Step by step: how each gets used

### Prover side (off-chain)

```text
1. Noir circuit + witness (key, value, salt, sig...)
        ↓
2. nargo compile → ACIR bytecode
        ↓
3. bb write_vk → vk.bin (1,760 bytes)
        ↓
4. bb prove → proof (14,592 bytes) + public_inputs (224 bytes)
```

Steps 3–4 use BN254 arithmetic internally (via bb's own implementation), but
they run on your machine. The network isn't involved yet.

### Verifier side (on-chain)

```text
5. Contract receives proof_bytes + public_inputs
        ↓
6. Contract calls UltraHonkVerifier::verify(...)
        ↓
7. Verifier recomputes Fiat–Shamir transcript
        ↓
8. Verifier runs sumcheck
        ↓
9. Verifier runs Shplemini openings:
      - calls env.crypto().bn254().g1_msm(...)
      - calls env.crypto().bn254().pairing_check(...)
        ↓
10. Returns valid / invalid
```

Steps 7–9 are where the network's host functions get called. The Rust verifier
code orchestrates the calls; the host does the math.

### Where Poseidon comes in

Two separate places:

- **Circuit commitment:** `main.nr` does `poseidon::bn254::hash_4([...])`. That's
  computed off-chain during proof generation.
- **Verifier relations:** the verifier checks Poseidon2 relations as part of
  sumcheck. That's computed on-chain using `poseidon2_permutation`.

---

## The "ZK" marketing gap

Stellar advertises "ZK verification" because the network added BN254 and
Poseidon primitives. But the "ZK" in "zk-SNARK" is an acronym with four
properties:

| Letter | Property | Non-ZK flavor? |
| --- | --- | --- |
| **Z** | Zero-knowledge | ❌ |
| **K** | Knowledge (proof of knowledge) | ✅ |
| **S** | Succinct | ✅ |
| **N** | Non-interactive | ✅ |
| **ARK** | Argument of knowledge | ✅ |

The non-ZK flavor is a valid SNARK. It just drops the "Z".

**Analogy:** Stellar built the airport runway and the radar system. That makes
"ZK flights" possible. But whether any given plane is stealth is up to the
airline, not the airport.

### What would make the marketing match the implementation

1. NethermindEth ports `UltraZKFlavor` to Soroban
2. `bb` changes its default flavor to ZK
3. Stellar's docs clarify "ZK-capable" vs "ZK-by-default"

Currently it's option 3: the capability is real, the default implementation
isn't.

---

## Why the flavor matters for this project

The Meritable spec promises "zero data leakage" as a core security principle.
With `UltraKeccakFlavor`:

- The **commitment** still hides the value from other users.
- The **on-chain proof** does not fully hide the witness from someone who
  inspects it.
- The privacy claim in the spec is stronger than what the current toolchain
  delivers.

### Options

1. **Accept it for the PoC.** The proof still verifies; the privacy story is
   just weaker than advertised. Fine if the demo's goal is showing the pipeline
   works.
2. **Find or build a verifier that supports `UltraZKFlavor`.** That's the real
   fix, but it's significant work and may not exist for Soroban yet.
3. **Re-scope the privacy claim.** Document that the proof hides values from
   other users and the public ledger state, but not from someone performing deep
   analysis of the proof bytes.

---

## Quick reference

| Term | What it is | Where it runs |
| --- | --- | --- |
| BN254 | Elliptic curve math | Soroban host |
| Poseidon / Poseidon2 | ZK-friendly hash | Soroban host |
| bb | Prover/verifier toolchain | Your machine / browser |
| ACIR | Compiled circuit bytecode | Generated by `nargo` |
| VK | Verification key | Embedded in contract |
| UltraKeccakFlavor | Non-ZK proof format | bb default |
| UltraZKFlavor | ZK proof format | Not ported to Soroban |
| UltraHonkVerifier | Rust verifier contract | Soroban |
