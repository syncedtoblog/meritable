use poseidon::poseidon::bn254::hash_4;
use schnorr::assert_valid_signature;
use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar};

// Supported Operator Codes:
// 0: >= (Greater than or equal)
// 1: <= (Less than or equal)
// 2: == (Exactly equal)
// 3: >  (Strictly greater than)
// 4: <  (Strictly less than)
// 5: != (Not equal)

fn evaluate_operator(value: u64, operator: u8, threshold: u64) {
    if operator == 0 {
        assert(value >= threshold, "Condition failed: value >= threshold");
    } else if operator == 1 {
        assert(value <= threshold, "Condition failed: value <= threshold");
    } else if operator == 2 {
        assert(value == threshold, "Condition failed: value == threshold");
    } else if operator == 3 {
        assert(value > threshold, "Condition failed: value > threshold");
    } else if operator == 4 {
        assert(value < threshold, "Condition failed: value < threshold");
    } else if operator == 5 {
        assert(value != threshold, "Condition failed: value != threshold");
    } else {
        assert(false, "Unsupported operator code");
    }
}

fn main(
    // PRIVATE INPUTS (Stays hidden inside client device memory)
    key: Field,
    value: Field,
    salt: Field,
    sig_s_lo: Field,
    sig_s_hi: Field,
    sig_e_lo: Field,
    sig_e_hi: Field,

    // PUBLIC INPUTS (Submitted to and verified by Soroban on Stellar)
    issuer_pubkey_x: pub Field,
    issuer_pubkey_y: pub Field,
    user_address: pub Field,
    target_key: pub Field,
    operator: pub u8,
    threshold: pub u64,
    nonce: pub u64,
) {
    // 1. Enforce Key Matching (e.g. "credit_score" == "credit_score")
    assert(key == target_key, "Target key mismatch");

    // 2. Enforce Generalized Condition (>=, <=, ==, >, <, !=)
    evaluate_operator(value as u64, operator, threshold);

    // 3. Recompute Poseidon BN254 Commitment bound to user's Stellar address
    let commitment = hash_4([user_address, key, value, salt]);

    // 4. Verify Issuer's BN254 Schnorr Signature over the commitment
    let issuer_pubkey = EmbeddedCurvePoint::new(issuer_pubkey_x, issuer_pubkey_y);
    let sig_s = EmbeddedCurveScalar::new(sig_s_lo, sig_s_hi);
    let sig_e = EmbeddedCurveScalar::new(sig_e_lo, sig_e_hi);
    assert_valid_signature(issuer_pubkey, (sig_s, sig_e), commitment);

    // 5. Bind nonce as a verified public input
    assert(nonce == nonce);
}

#[test]
fn test_commitment_binding() {
    let user_address = 0x1234;
    let key = 1;
    let value = 750;
    let salt = 999;

    let commitment = hash_4([user_address, key, value, salt]);
    assert(commitment != 0);

    // Different user cannot reuse the commitment
    let different_user = 0x5678;
    assert(commitment != hash_4([different_user, key, value, salt]));
}

#[test]
fn test_all_comparison_operators() {
    // 0: >=
    evaluate_operator(750, 0, 700);
    evaluate_operator(700, 0, 700);

    // 1: <=
    evaluate_operator(40, 1, 50);
    evaluate_operator(50, 1, 50);

    // 2: ==
    evaluate_operator(840, 2, 840);

    // 3: >
    evaluate_operator(750, 3, 700);

    // 4: <
    evaluate_operator(17, 4, 18);

    // 5: !=
    evaluate_operator(840, 5, 999);
}

#[test(should_fail_with = "Target key mismatch")]
fn test_rejects_key_mismatch() {
    main(
        1,   // key
        750, // value
        999, // salt
        0, 0, 0, 0,
        0, 0,
        0x1234, // user_address
        2,      // target_key (mismatch!)
        0,      // operator (>=)
        700,    // threshold
        42,     // nonce
    );
}

#[test(should_fail_with = "Condition failed: value >= threshold")]
fn test_rejects_failed_gte() {
    main(
        1,   // key
        650, // value (under threshold!)
        999, // salt
        0, 0, 0, 0,
        0, 0,
        0x1234, // user_address
        1,      // target_key
        0,      // operator (>=)
        700,    // threshold
        42,     // nonce
    );
}

#[test(should_fail_with = "Condition failed: value == threshold")]
fn test_rejects_failed_equality() {
    main(
        1,   // key
        1,   // value (e.g. tier 1)
        999, // salt
        0, 0, 0, 0,
        0, 0,
        0x1234, // user_address
        1,      // target_key
        2,      // operator (==)
        2,      // threshold (requires tier 2!)
        42,     // nonce
    );
}

#[test(should_fail_with = "Unsupported operator code")]
fn test_rejects_unsupported_operator() {
    evaluate_operator(750, 99, 700);
}
