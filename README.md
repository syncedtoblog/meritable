# Meritable

Privacy-preserving credential verification on Stellar Soroban.

A user proves a condition over a signed credential (e.g. `credit_score >= 700`)
without revealing the credential value. The proof is verified on-chain by a
Soroban contract, which burns a nonce and grants an ephemeral session ticket.

> **Development disclosure:** This project was developed with extensive use of
> large language models (Gemini and DeepSeek) for architecture, code, and
> documentation. The cryptographic design, toolchain pinning, and test results
> should be independently reviewed before production use.

---

## Repository layout

```text
circuit/                    Noir circuit (commitment + Schnorr + operator check)
  src/main.nr
  vendor/poseidon/          Vendored, beta.9-compatible Poseidon/Poseidon2
  vendor/schnorr/           Vendored noir-lang/schnorr v0.4.0, patched for beta.9
  target/                   Build artifacts (gitignored)
issuer/                     Rust Axum issuer API + dev signer
  src/crypto.rs             Poseidon commitment + Grumpkin Schnorr signing
  src/bin/gen_prover.rs     Generates a valid circuit/Prover.toml
contracts/kyc_verifier/     Soroban verifier contract
  vk.bin                    Real 1,760-byte UltraHonk verification key
  tests/fixtures/           Real proof + public inputs
pwa/                        PWA frontend (Stage 4, in progress)
```

---

## Toolchain

The on-chain verifier (`ultrahonk_soroban_verifier` 0.1.0) requires a specific
proof format. Use **exactly** these versions:

| Tool | Version | Notes |
| --- | --- | --- |
| Nargo | `1.0.0-beta.9` | `noirup -v 1.0.0-beta.9` |
| Barretenberg (`bb`) | `0.87.0` | [release tarball](https://github.com/AztecProtocol/aztec-packages/releases/tag/v0.87.0) |
| Proof flavor | `ultra_honk` + `keccak` oracle | matches `UltraKeccakFlavor` |
| soroban-sdk | `28.0.0` | protocol 28+ |

Newer Nargo/`bb` combinations produce proofs the contract cannot verify. Older
Nargo releases (e.g. `1.0.0-rc.5`) produce ACIR that `bb 0.87.0` rejects with
`Length is too large`.

### Installing Barretenberg 0.87.0 (verified download)

```bash
mkdir -p ~/.bb/bin
curl -L --fail \
  https://github.com/AztecProtocol/aztec-packages/releases/download/v0.87.0/barretenberg-amd64-linux.tar.gz \
  -o /tmp/barretenberg-amd64-linux.tar.gz

# SHA-256 pinned by the Nethermind rs-soroban-ultrahonk build script
echo "829b714287085ff4562ba2c64f9c8128463650d833bdd1db5d5a33471dcd67cb  /tmp/barretenberg-amd64-linux.tar.gz" \
  | sha256sum -c -

tar -xzf /tmp/barretenberg-amd64-linux.tar.gz -C ~/.bb/bin
chmod +x ~/.bb/bin/bb
export PATH="$HOME/.bb/bin:$PATH"
bb --version   # expect 0.87.0
```

---

## Step 2 — Generating the real `vk.bin` and proof

The circuit depends on vendored packages, not the upstream git tags. This is
required because upstream `poseidon` v0.4.0 uses syntax that Nargo `beta.9`
cannot parse, and upstream `schnorr` v0.4.0 uses the `rc.5` curve API.

### Vendored dependencies and patches

- `circuit/vendor/poseidon/` — copied from
  [NethermindEth/rs-soroban-ultrahonk](https://github.com/NethermindEth/rs-soroban-ultrahonk)
  `circuits/vendor/poseidon`. This is the version that compiles under beta.9.
- `circuit/vendor/schnorr/` — copied from `noir-lang/schnorr` tag `v0.4.0`,
  with three API adjustments for beta.9:
  1. `r.is_infinite()` → `r.is_infinite` (field access, not a method)
  2. `EmbeddedCurvePoint::new(x, y)` → `EmbeddedCurvePoint { x, y, is_infinite: false }`
     (two test vectors)
  3. `Nargo.toml` dependency changed from git `poseidon` v0.3.0 to
     `path = "../poseidon"` so both packages share one Poseidon implementation.
- `circuit/src/main.nr` — same `EmbeddedCurvePoint::new` → struct literal change
  for the issuer public key.

Review these patches before relying on the verification key. Any change to the
circuit, the vendored packages, or the toolchain produces a different key.

### Build and prove

```bash
# 1. Compile the circuit (writes target/meritable_circuit.json)
cd circuit
nargo compile

# 2. Generate a valid Prover.toml from the dev issuer signer, then execute.
#    gen_prover signs a fresh commitment with the PoC issuer key, so the
#    signature in Prover.toml verifies inside the circuit.
cd ..
cargo run -p issuer --bin gen_prover > circuit/Prover.toml
cd circuit
nargo execute        # writes target/meritable_circuit.gz

# 3. Write the verification key (1,760 bytes)
bb write_vk \
  --scheme ultra_honk \
  --oracle_hash keccak \
  --bytecode_path target/meritable_circuit.json \
  --output_path target \
  --output_format bytes_and_fields
# -> target/vk and target/vk_fields.json

# 4. Generate the proof (14,592 bytes)
bb prove \
  --scheme ultra_honk \
  --oracle_hash keccak \
  --bytecode_path target/meritable_circuit.json \
  --witness_path target/meritable_circuit.gz \
  --output_path target \
  --output_format bytes_and_fields
# -> target/proof, target/proof_fields.json,
#    target/public_inputs, target/public_inputs_fields.json
```

### Copy artifacts into the contract

```bash
cp circuit/target/vk contracts/kyc_verifier/vk.bin
mkdir -p contracts/kyc_verifier/tests/fixtures
cp circuit/target/proof          contracts/kyc_verifier/tests/fixtures/proof.bin
cp circuit/target/public_inputs   contracts/kyc_verifier/tests/fixtures/public_inputs.bin
```

### Expected artifact sizes

| File | Size | Purpose |
| --- | --- | --- |
| `target/meritable_circuit.json` | ~165 KB | ACIR bytecode |
| `target/meritable_circuit.gz` | ~15 KB | Witness |
| `target/vk` | **1,760 B** | Verification key embedded in contract |
| `target/proof` | **14,592 B** | UltraHonk proof |
| `target/public_inputs` | 224 B | 7 × 32-byte big-endian fields |

### Public input order

The circuit declares public inputs in this order, and the contract must build
the `public_inputs` byte string in the same order:

```text
issuer_pubkey_x | issuer_pubkey_y | user_address | target_key | operator | threshold | nonce
```

Each is a 32-byte big-endian field element. `operator`, `threshold`, and `nonce`
are zero-padded on the left.

---

## Step 3 — Dev issuer signer

`issuer/src/crypto.rs` contains a **throwaway** Grumpkin keypair committed to the
repository so the end-to-end flow can be exercised locally. Do not use it for
anything with real value.

The signer reproduces `noir-lang/schnorr` v0.4.0 exactly:

```text
R  = k·G
e  = Poseidon2(DST, R.x, pub.x, pub.y, commitment)
s  = k - e·priv
```

`e` and `s` are split into 128-bit `lo`/`hi` halves. The tests verify the two
pinned Noir Schnorr vectors, so the native signer and the in-circuit verifier
agree byte-for-byte.

`cargo run -p issuer --bin gen_prover` writes a `Prover.toml` whose signature is
valid for the commitment derived from the deterministic credential values in
that binary.

### Generate a credential from the API

```bash
cargo run -p issuer            # listens on :8080
curl -s localhost:8080/issue \
  -H 'content-type: application/json' \
  -d '{"user_address":"GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN","key":"credit_score","value":750}'
```

The endpoint accepts arbitrary key/value pairs and does not authenticate the
caller. It is a demo issuer only.

---

## Contract

```bash
cargo test -p kyc-verifier
```

The contract embeds `vk.bin` via `include_bytes!`, burns nonces in temporary
storage, and stores an ephemeral `(SESS, user, target_key)` ticket. The contract
accepts the issuer public key as an argument, so it is not bound to a single
issuer. Callers relying on sessions should decide which issuer keys they trust.

---

## Security considerations

**The verifier flavor is non-zero-knowledge.** From the
`ultrahonk_soroban_verifier` README:

> It provides **no witness-hiding guarantee**: a proof carries witness-dependent
> protocol messages, and on-chain wrappers accept the full proof as public
> transaction input. Do not use it for privacy-sensitive circuits, and do not
> treat a private circuit input as secret merely because it is not a public
> input. `UltraZKFlavor` is not implemented.

For a privacy-focused KYC product this is a material limitation. Before handling
real credentials, either switch to a ZK flavor the on-chain verifier supports or
re-evaluate what the proof actually hides. The commitment still hides the value
from *other users*, but the proof itself is not zero-knowledge.

Other open items:

- The dev issuer private key is in the repository. Production must use an
  HSM/KMS-backed signer and never commit the key.
- The issuer does not authenticate users or verify claims. It signs whatever it
  is given.
- Sessions do not record which issuer key verified them.
- No replay protection on the issuer API itself.

### PWA caveats

- **Vault fallback is insecure.** If WebAuthn PRF is unavailable, the PWA
  generates a random AES key and stores it in IndexedDB. Records are labelled
  `dev-insecure`. This protects against casual inspection only. Remove the
  fallback in `pwa/src/lib/vault.js` before handling real credentials.
- **Proving is single-threaded by default.** Multithreaded bb.js requires
  `Cross-Origin-Opener-Policy: same-origin` and
  `Cross-Origin-Embedder-Policy: require-corp`. The Rust issuer's CORS layer
  does not send `Cross-Origin-Resource-Policy`, so enabling COEP would currently
  block issuer API calls. Proving works without these headers but is slower.
- **No contract is deployed yet.** `VITE_CONTRACT_ID` is empty, so
  `submitVerification` and `isSessionValid` will throw until a contract ID is
  configured.
- **The browser flow is not yet exercised.** The production build and dev server
  were verified, but bb.js WASM proving, WebAuthn PRF prompts, and Freighter
  signing/submission have not been run in a real browser from this environment.
- **The prover uses a client-generated nonce.** The spec suggests querying a
  nonce from the verifier, but the contract has no nonce getter. A 63-bit random
  nonce is generated per proof and burned on-chain, which is sufficient for
  replay protection.

---

## Stage 4 — PWA

Stack: React + Vite + plain JavaScript, Pico.css (no Tailwind), with a Web
Worker prover. See [`pwa/README.md`](pwa/README.md) for setup and module details.

```bash
cd pwa
cp .env.example .env
npm install
npm run dev
```

Implemented:

- Wallet connection via Freighter.
- Demo credential request against the Rust issuer.
- AES-256-GCM encrypted vault in IndexedDB, keyed by WebAuthn PRF when available.
- Noir witness + UltraHonk proof generation in a module Web Worker.
- `verify_credential` transaction build/sign/submit and `is_session_valid` query.

The build and dev server have been verified. Remaining work:

1. Deploy the contract to Stellar Testnet and set `VITE_CONTRACT_ID`.
2. Run the full flow in a real browser (WebAuthn PRF, bb.js WASM, Freighter).
3. Add end-to-end tests from spec Step 5.
