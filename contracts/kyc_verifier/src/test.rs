#![cfg(test)]
use super::*;
use soroban_sdk::{testutils::Address as _, Address, Bytes, Env};

#[test]
fn test_rejects_invalid_field_lengths() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(KycVerifier, ());
    let client = KycVerifierClient::new(&env, &contract_id);
    let user = Address::generate(&env);

    // Pass invalid length (< 32 bytes)
    let short_field = Bytes::from_slice(&env, &[1, 2, 3]);
    let valid_field = Bytes::from_slice(&env, &[0u8; 32]);
    let proof = Bytes::from_slice(&env, &[0u8; 64]);

    let res = client.try_verify_credential(
        &user,
        &short_field,
        &valid_field,
        &valid_field,
        &valid_field,
        &0,
        &700,
        &12345,
        &proof,
    );

    assert_eq!(res, Err(Ok(VerifierError::InvalidFieldLength)));
}

#[test]
fn test_session_validity_query_initial_false() {
    let env = Env::default();
    let contract_id = env.register(KycVerifier, ());
    let client = KycVerifierClient::new(&env, &contract_id);
    let user = Address::generate(&env);
    let target_key = Bytes::from_slice(&env, &[0u8; 32]);

    assert_eq!(client.is_session_valid(&user, &target_key), false);
}

#[test]
fn test_nonce_already_consumed_rejection() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(KycVerifier, ());
    let client = KycVerifierClient::new(&env, &contract_id);
    let user = Address::generate(&env);

    let nonce: u64 = 99999;
    let nonce_key = (symbol_short!("NONCE"), nonce);

    // Simulate pre-existing / consumed nonce in temporary storage
    env.as_contract(&contract_id, || {
        env.storage().temporary().set(&nonce_key, &true);
    });

    let valid_field = Bytes::from_slice(&env, &[0u8; 32]);
    let proof = Bytes::from_slice(&env, &[0u8; 64]);

    let res = client.try_verify_credential(
        &user,
        &valid_field,
        &valid_field,
        &valid_field,
        &valid_field,
        &0,
        &700,
        &nonce,
        &proof,
    );

    assert_eq!(res, Err(Ok(VerifierError::NonceAlreadyConsumed)));
}
