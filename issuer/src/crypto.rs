use ark_bn254::Fr;
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, MontFp, PrimeField, Zero};
use ark_grumpkin::{
    Affine as GrumpkinAffine, Fr as GrumpkinScalar, Projective as GrumpkinProjective,
};
use outbe_poseidon::{Poseidon, Poseidon2, PoseidonHasher};
use serde::{Deserialize, Serialize};
use stellar_strkey::Strkey;

/// PoC ONLY. This is a throwaway issuer signing key committed to the repo so
/// the end-to-end flow can be exercised locally. Never use this key for
/// anything with real value.
pub const DEV_ISSUER_PRIVATE_KEY_HEX: &str =
    "0xe82dfc9126620d96affdb2f11a49727984e5f7f7d9ec6de074955b8f18867b";

/// Domain separation tag used by noir-lang/schnorr v0.4.0.
const SCHNORR_CHALLENGE_DST: Fr =
    MontFp!("0x024c76938ed06b8ec1d9094b1013d190baa4011372f0604643bda812a63b832e");

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

/// Raw field-element signature, useful for tests and for formatting into the
/// API response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevIssuerSignature {
    pub issuer_pubkey_x: Fr,
    pub issuer_pubkey_y: Fr,
    pub sig_s_lo: Fr,
    pub sig_s_hi: Fr,
    pub sig_e_lo: Fr,
    pub sig_e_hi: Fr,
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

/// Returns the Grumpkin scalar represented by the hardcoded PoC key.
pub fn dev_issuer_private_key() -> GrumpkinScalar {
    let bytes = hex::decode(DEV_ISSUER_PRIVATE_KEY_HEX.trim_start_matches("0x"))
        .expect("DEV_ISSUER_PRIVATE_KEY_HEX must be valid hex");
    GrumpkinScalar::from_be_bytes_mod_order(&bytes)
}

/// Derives the issuer's Grumpkin public key from the hardcoded PoC key.
pub fn dev_issuer_public_key() -> (Fr, Fr) {
    let public = (GrumpkinProjective::generator() * dev_issuer_private_key()).into_affine();
    public
        .xy()
        .expect("dev issuer public key must not be the point at infinity")
}

/// e = Poseidon2(DST, R.x, pub.x, pub.y, commitment), matching noir-lang/schnorr v0.4.0.
fn schnorr_challenge(r_x: Fr, pub_x: Fr, pub_y: Fr, commitment: Fr) -> Fr {
    let mut hasher = Poseidon2::<Fr>::new();
    hasher
        .hash(&[SCHNORR_CHALLENGE_DST, r_x, pub_x, pub_y, commitment])
        .expect("Poseidon2 hashing is infallible")
}

/// Splits a 256-bit scalar into 128-bit lo/hi field elements, matching Noir's
/// `EmbeddedCurveScalar` representation.
fn scalar_to_halves<F: PrimeField>(value: F) -> (Fr, Fr) {
    let bytes = value.into_bigint().to_bytes_le();
    assert!(bytes.len() >= 32, "scalar must be at least 32 bytes");

    let lo = u128::from_le_bytes(bytes[0..16].try_into().expect("16-byte slice"));
    let hi = u128::from_le_bytes(bytes[16..32].try_into().expect("16-byte slice"));
    (Fr::from(lo), Fr::from(hi))
}

/// Rebuilds the little-endian 256-bit representation from lo/hi halves.
fn halves_to_le_bytes(lo: Fr, hi: Fr) -> [u8; 32] {
    let lo_bytes = lo.into_bigint().to_bytes_le();
    let hi_bytes = hi.into_bigint().to_bytes_le();

    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&lo_bytes[..16]);
    out[16..].copy_from_slice(&hi_bytes[..16]);
    out
}

fn halves_to_scalar<F: PrimeField>(lo: Fr, hi: Fr) -> F {
    F::from_le_bytes_mod_order(&halves_to_le_bytes(lo, hi))
}

/// Signs a commitment with the PoC issuer key using the exact Schnorr scheme
/// verified by noir-lang/schnorr v0.4.0.
pub fn sign_commitment(commitment: Fr) -> DevIssuerSignature {
    let private_key = dev_issuer_private_key();
    let (pub_x, pub_y) = dev_issuer_public_key();

    // Fresh random nonce for each signature. For a PoC key this is enough;
    // production signers should use a properly managed CSPRNG / RFC 6979-style
    // deterministic nonce.
    let nonce = loop {
        let bytes: [u8; 32] = rand::random();
        let candidate = GrumpkinScalar::from_be_bytes_mod_order(&bytes);
        if !candidate.is_zero() {
            break candidate;
        }
    };

    let r = (GrumpkinProjective::generator() * nonce).into_affine();
    let (r_x, _) = r
        .xy()
        .expect("Schnorr nonce point must not be the point at infinity");

    let e = schnorr_challenge(r_x, pub_x, pub_y, commitment);
    let e_scalar =
        GrumpkinScalar::from_le_bytes_mod_order(&e.into_bigint().to_bytes_le());
    let s = nonce - e_scalar * private_key;

    let (s_lo, s_hi) = scalar_to_halves(s);
    let (e_lo, e_hi) = scalar_to_halves(e);

    DevIssuerSignature {
        issuer_pubkey_x: pub_x,
        issuer_pubkey_y: pub_y,
        sig_s_lo: s_lo,
        sig_s_hi: s_hi,
        sig_e_lo: e_lo,
        sig_e_hi: e_hi,
    }
}

/// Verifies a signature exactly the way Noir's schnorr library does. Used by
/// tests and as a sanity check for the signer implementation.
pub fn verify_commitment_signature(sig: &DevIssuerSignature, commitment: Fr) -> bool {
    let s: GrumpkinScalar = halves_to_scalar(sig.sig_s_lo, sig.sig_s_hi);
    let e_scalar: GrumpkinScalar = halves_to_scalar(sig.sig_e_lo, sig.sig_e_hi);
    let e_field: Fr = halves_to_scalar(sig.sig_e_lo, sig.sig_e_hi);

    let public = GrumpkinAffine::new_unchecked(sig.issuer_pubkey_x, sig.issuer_pubkey_y);
    let r = GrumpkinProjective::generator() * s + public.into_group() * e_scalar;

    if r.is_zero() {
        return false;
    }

    let (r_x, _) = r
        .into_affine()
        .xy()
        .expect("Schnorr verification point must not be the point at infinity");

    schnorr_challenge(
        r_x,
        sig.issuer_pubkey_x,
        sig.issuer_pubkey_y,
        commitment,
    ) == e_field
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

    #[test]
    fn test_schnorr_pinned_vector_small() {
        // Pinned test vector from noir-lang/schnorr v0.4.0.
        let sig = DevIssuerSignature {
            issuer_pubkey_x: MontFp!(
                "0x2c39bbbde2d0ffcb5c4317dcbfa1771cf554a2f33c647446632fa707a5bf5f3f"
            ),
            issuer_pubkey_y: MontFp!(
                "0x2b9c81935298af5ebe22f1a7279bb76781e6cadba3fb6c5c41ed942392dc687c"
            ),
            sig_s_lo: MontFp!("0x5fd1ac0ad411110674830c54cb506212"),
            sig_s_hi: MontFp!("0x281906862cdb4e0efec7226d757fe803"),
            sig_e_lo: MontFp!("0x6c368959f958e525d761d06c47fd2ad6"),
            sig_e_hi: MontFp!("0x013f6a902c6c0efafdadbd4de409690d"),
        };

        assert!(verify_commitment_signature(&sig, Fr::from(0x2bcu64)));
    }

    #[test]
    fn test_schnorr_pinned_vector_large() {
        // Pinned test vector from noir-lang/schnorr v0.4.0. This is also the
        // exact sample key/signature that the old issuer returned for every
        // credential.
        let sig = DevIssuerSignature {
            issuer_pubkey_x: MontFp!(
                "0x065812e335a97c2108ea8cf4ccfe2f9dd6b117a0714f5e18461575be93f61da6"
            ),
            issuer_pubkey_y: MontFp!(
                "0x1a915003e8ec534f9a15d926a7ded478e178468ccc4f28e236e67450a55ac622"
            ),
            sig_s_lo: MontFp!("0xf3bc3b7147acb9c621fd9f72dbf15ffa"),
            sig_s_hi: MontFp!("0x08599f379f0301dfefdbd0272554454d"),
            sig_e_lo: MontFp!("0x97065383ebbbd76620398792bd259bc2"),
            sig_e_hi: MontFp!("0x2ceaee87f45b7a417f0ffb05451a8c92"),
        };

        let message = MontFp!(
            "0x0123456789abcdef0fedcba9876543210123456789abcdef0fedcba987654321"
        );
        assert!(verify_commitment_signature(&sig, message));
    }

    #[test]
    fn test_dev_issuer_signs_and_verifies_commitments() {
        let commitment = Fr::from(0x1234_5678_9abc_def0u64);
        let sig = sign_commitment(commitment);

        assert_eq!(
            (sig.issuer_pubkey_x, sig.issuer_pubkey_y),
            dev_issuer_public_key()
        );
        assert!(verify_commitment_signature(&sig, commitment));
        assert!(!verify_commitment_signature(
            &sig,
            commitment + Fr::from(1u64)
        ));
    }
}
