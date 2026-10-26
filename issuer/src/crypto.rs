use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use serde::{Deserialize, Serialize};
use stellar_strkey::Strkey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorrSignature {
    pub sig_s_lo: String,
    pub sig_s_hi: String,
    pub sig_e_lo: String,
    pub sig_e_hi: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerPublicKey {
    pub x: String,
    pub y: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundCredentialResponse {
    pub user_address: String,
    pub key: String,
    pub value: u64,
    pub salt: String,
    pub commitment: String,
    pub issuer_pubkey: IssuerPublicKey,
    pub signature: SchnorrSignature,
}

/// Decodes Stellar Strkey (G...) into a 32-byte BE BN254 scalar field element
pub fn stellar_address_to_field(addr: &str) -> Result<Fr, String> {
    let strkey = Strkey::from_string(addr)
        .map_err(|e| format!("Invalid Stellar address: {:?}", e))?;
    match strkey {
        Strkey::PublicKeyEd25519(pk) => Ok(Fr::from_be_bytes_mod_order(&pk.0)),
        _ => Err("Expected an Ed25519 public key (G...)".to_string()),
    }
}

/// Maps ASCII key string into a BN254 scalar field element
pub fn string_to_field(s: &str) -> Fr {
    let bytes = s.as_bytes();
    let mut buf = [0u8; 32];
    let len = bytes.len().min(32);
    buf[32 - len..].copy_from_slice(&bytes[..len]);
    Fr::from_be_bytes_mod_order(&buf)
}

/// Computes Poseidon BN254 hash for 4 inputs matching Noir's poseidon::bn254::hash_4
pub fn compute_poseidon_hash_4(inputs: &[Fr; 4]) -> Result<Fr, String> {
    let mut hasher = Poseidon::<Fr>::new_circom(4)
        .map_err(|e| format!("Poseidon init error: {:?}", e))?;
    hasher
        .hash(inputs)
        .map_err(|e| format!("Poseidon hashing error: {:?}", e))
}

pub fn field_to_hex(f: &Fr) -> String {
    let bigint = f.into_bigint();
    let bytes = bigint.to_bytes_be();
    format!("0x{}", hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_stellar_address_decoding() {
        // Known valid Stellar testnet account address
        let addr = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN";
        let res = stellar_address_to_field(addr);
        assert!(res.is_ok());
        let field = res.unwrap();
        assert_ne!(field, Fr::from(0u64));
    }

    #[test]
    fn test_invalid_stellar_address_rejected() {
        let bad_addr = "NOT_A_STELLAR_ADDRESS";
        assert!(stellar_address_to_field(bad_addr).is_err());
    }

    #[test]
    fn test_poseidon_hash_deterministic_and_unique() {
        let user = Fr::from(42u64);
        let key = string_to_field("credit_score");
        let val = Fr::from(750u64);
        let salt = Fr::from(999u64);

        let h1 = compute_poseidon_hash_4(&[user, key, val, salt]).unwrap();
        let h2 = compute_poseidon_hash_4(&[user, key, val, salt]).unwrap();
        assert_eq!(h1, h2);

        // Different user produces completely different commitment
        let other_user = Fr::from(43u64);
        let h3 = compute_poseidon_hash_4(&[other_user, key, val, salt]).unwrap();
        assert_ne!(h1, h3);
    }
}
