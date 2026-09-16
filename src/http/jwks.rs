use axum::Json;
use serde::Serialize;

use crate::crypto::base64url;
use crate::crypto::ed25519;
use crate::state::AppState;

#[derive(Serialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Serialize)]
pub struct Jwk {
    pub kty: &'static str,
    pub crv: &'static str,
    pub x: String,
    #[serde(rename = "use")]
    pub use_: &'static str,
    pub alg: &'static str,
    pub kid: String,
}

pub async fn jwks(axum::extract::State(state): axum::extract::State<AppState>) -> Json<Jwks> {
    Json(Jwks {
        keys: vec![Jwk {
            kty: "OKP",
            crv: "Ed25519",
            x: base64url::encode(&ed25519::public_key_raw(&state.signing_key)),
            use_: "sig",
            alg: "EdDSA",
            kid: state.signing_kid.clone(),
        }],
    })
}
