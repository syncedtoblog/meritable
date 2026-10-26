use ark_ff::PrimeField;
use issuer::crypto;
use axum::{
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};

#[derive(Debug, Deserialize)]
pub struct IssueRequest {
    pub user_address: String,
    pub key: String,
    pub value: u64,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
}

async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: "0.1.0",
    })
}

async fn issue_credential(
    Json(req): Json<IssueRequest>,
) -> Result<Json<crypto::BoundCredentialResponse>, (axum::http::StatusCode, String)> {
    // 1. Decode Stellar G_USER... address to BN254 Field
    let user_field = crypto::stellar_address_to_field(&req.user_address)
        .map_err(|e| (axum::http::StatusCode::BAD_REQUEST, e))?;

    // 2. Map credential key to Field
    let key_field = crypto::string_to_field(&req.key);

    // 3. Map value to Field
    let val_field = ark_bn254::Fr::from(req.value);

    // 4. Generate random 256-bit salt
    let salt_bytes: [u8; 32] = rand::random();
    let salt_field = ark_bn254::Fr::from_be_bytes_mod_order(&salt_bytes);

    // 5. Compute Poseidon BN254 Commitment over (user, key, value, salt)
    let commitment = crypto::compute_poseidon_hash_4(&[user_field, key_field, val_field, salt_field])
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e))?;

    // 6. Sign the commitment with the PoC issuer key
    // (In production, the issuer holds the Grumpkin private key in secure hardware/env)
    let signed = crypto::sign_commitment(commitment);

    let resp = crypto::BoundCredentialResponse {
        user_address: req.user_address,
        key: req.key,
        value: req.value,
        salt: crypto::field_to_hex(&salt_field),
        commitment: crypto::field_to_hex(&commitment),
        issuer_pubkey: crypto::IssuerPublicKey {
            x: crypto::field_to_hex(&signed.issuer_pubkey_x),
            y: crypto::field_to_hex(&signed.issuer_pubkey_y),
        },
        signature: crypto::SchnorrSignature {
            sig_s_lo: crypto::field_to_hex(&signed.sig_s_lo),
            sig_s_hi: crypto::field_to_hex(&signed.sig_s_hi),
            sig_e_lo: crypto::field_to_hex(&signed.sig_e_lo),
            sig_e_hi: crypto::field_to_hex(&signed.sig_e_hi),
        },
    };

    Ok(Json(resp))
}

#[tokio::main]
async fn main() {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/issue", post(issue_credential))
        .layer(cors);

    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .unwrap_or(8080);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("Meritable Issuer API running on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
