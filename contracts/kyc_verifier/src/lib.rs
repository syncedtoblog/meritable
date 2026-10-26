#![no_std]
use soroban_sdk::{
    contract, contracterror, contractimpl, symbol_short, Address, Bytes, Env,
};
use ultrahonk_soroban_verifier::UltraHonkVerifier;

// Embedded binary verification key generated from circuit compilation
const VERIFICATION_KEY: &[u8] = include_bytes!("../vk.bin");

// TTL in ledgers (~5 seconds per ledger on Stellar, so 500 ledgers ~ 40 minutes)
const SESSION_TTL_LEDGERS: u32 = 500;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum VerifierError {
    NonceAlreadyConsumed = 1,
    InvalidVerificationKey = 2,
    InvalidProof = 3,
    InvalidFieldLength = 4,
}

#[contract]
pub struct KycVerifier;

#[contractimpl]
impl KycVerifier {
    /// Verifies an UltraHonk ZK proof, burns the single-use nonce,
    /// and grants an ephemeral session ticket for the user and target key.
    pub fn verify_credential(
        env: Env,
        user: Address,
        issuer_pubkey_x: Bytes,    // 32-byte BE field
        issuer_pubkey_y: Bytes,    // 32-byte BE field
        user_address_field: Bytes, // 32-byte BE field matching user
        target_key: Bytes,         // 32-byte BE field
        operator: u32,             // 0: >=, 1: <=, 2: ==, 3: >, 4: <, 5: !=
        threshold: u64,
        nonce: u64,
        proof_bytes: Bytes,
    ) -> Result<bool, VerifierError> {
        // 1. Enforce user authorization (Stellar transaction signature verification)
        user.require_auth();

        // 2. Validate input field lengths (must be 32 bytes each)
        if issuer_pubkey_x.len() != 32
            || issuer_pubkey_y.len() != 32
            || user_address_field.len() != 32
            || target_key.len() != 32
        {
            return Err(VerifierError::InvalidFieldLength);
        }

        // 3. Anti-Replay: Ensure nonce has not been consumed yet, then burn it
        let nonce_key = (symbol_short!("NONCE"), nonce);
        if env.storage().temporary().has(&nonce_key) {
            return Err(VerifierError::NonceAlreadyConsumed);
        }
        env.storage().temporary().set(&nonce_key, &true);
        env.storage()
            .temporary()
            .extend_ttl(&nonce_key, SESSION_TTL_LEDGERS, SESSION_TTL_LEDGERS);

        // 4. Construct canonical 32-byte big-endian public inputs matching Noir ABI:
        // [issuer_pubkey_x, issuer_pubkey_y, user_address_field, target_key, operator, threshold, nonce]
        let mut public_inputs = Bytes::new(&env);
        public_inputs.append(&issuer_pubkey_x);
        public_inputs.append(&issuer_pubkey_y);
        public_inputs.append(&user_address_field);
        public_inputs.append(&target_key);

        let mut op_bytes = [0u8; 32];
        op_bytes[28..32].copy_from_slice(&operator.to_be_bytes());
        public_inputs.append(&Bytes::from_slice(&env, &op_bytes));

        let mut threshold_bytes = [0u8; 32];
        threshold_bytes[24..32].copy_from_slice(&threshold.to_be_bytes());
        public_inputs.append(&Bytes::from_slice(&env, &threshold_bytes));

        let mut nonce_bytes = [0u8; 32];
        nonce_bytes[24..32].copy_from_slice(&nonce.to_be_bytes());
        public_inputs.append(&Bytes::from_slice(&env, &nonce_bytes));

        // 5. Verify UltraHonk proof using native Protocol 25 BN254 host functions
        let vk_bytes = Bytes::from_slice(&env, VERIFICATION_KEY);
        let verifier = UltraHonkVerifier::new(&env, &vk_bytes)
            .map_err(|_| VerifierError::InvalidVerificationKey)?;

        verifier
            .verify(&proof_bytes, &public_inputs)
            .map_err(|_| VerifierError::InvalidProof)?;

        // 6. Anti-Lending: Store ephemeral session ticket with TTL in temporary storage
        let session_key = (symbol_short!("SESS"), user, target_key);
        env.storage().temporary().set(&session_key, &true);
        env.storage()
            .temporary()
            .extend_ttl(&session_key, SESSION_TTL_LEDGERS, SESSION_TTL_LEDGERS);

        Ok(true)
    }

    /// Read method for third parties to check active session validity
    pub fn is_session_valid(env: Env, user: Address, target_key: Bytes) -> bool {
        let session_key = (symbol_short!("SESS"), user, target_key);
        env.storage().temporary().get(&session_key).unwrap_or(false)
    }
}

#[cfg(test)]
mod test;
