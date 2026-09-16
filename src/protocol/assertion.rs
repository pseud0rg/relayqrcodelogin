use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::constants::{PROTOCOL_VERSION, RELAY_ORIGIN};
use crate::crypto::{ed25519, jcs};
use crate::error::{ProblemCode, RelayError};
use crate::protocol::validation::{
    validate_display_name, validate_id, validate_kid, validate_signature_b64, validate_site_account_id,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayAssertion {
    pub version: i64,
    pub iss: String,
    pub aud: String,
    pub sub: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub nonce: String,
    pub jti: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "subjectKeyVersion")]
    pub subject_key_version: i32,
    pub kid: String,
    pub signature: String,
}

impl RelayAssertion {
    pub fn sign(
        signing_key: &SigningKey,
        kid: &str,
        aud: String,
        sub: String,
        session_id: String,
        nonce: String,
        jti: String,
        iat: i64,
        exp: i64,
        display_name: String,
        subject_key_version: i32,
    ) -> Result<Self, RelayError> {
        validate_kid(kid)?;
        validate_id(&session_id)?;
        validate_id(&nonce)?;
        validate_site_account_id(&sub)?;
        validate_display_name(&display_name, true)?;
        let mut assertion = Self {
            version: PROTOCOL_VERSION,
            iss: RELAY_ORIGIN.to_string(),
            aud,
            sub,
            session_id,
            nonce,
            jti,
            iat,
            nbf: iat,
            exp,
            display_name,
            subject_key_version,
            kid: kid.to_string(),
            signature: String::new(),
        };
        let canonical = assertion.canonical_without_signature()?;
        assertion.signature = ed25519::sign(signing_key, canonical.as_bytes());
        validate_signature_b64(&assertion.signature)?;
        Ok(assertion)
    }

    pub fn canonical_without_signature(&self) -> Result<String, RelayError> {
        jcs::canonicalize_object(&[
            ("aud", serde_json::json!(self.aud)),
            ("displayName", serde_json::json!(self.display_name)),
            ("exp", serde_json::json!(self.exp)),
            ("iat", serde_json::json!(self.iat)),
            ("iss", serde_json::json!(self.iss)),
            ("jti", serde_json::json!(self.jti)),
            ("kid", serde_json::json!(self.kid)),
            ("nbf", serde_json::json!(self.nbf)),
            ("nonce", serde_json::json!(self.nonce)),
            ("sessionId", serde_json::json!(self.session_id)),
            ("sub", serde_json::json!(self.sub)),
            ("subjectKeyVersion", serde_json::json!(self.subject_key_version)),
            ("version", serde_json::json!(self.version)),
        ])
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, RelayError> {
        serde_json::to_vec(self).map_err(|_| RelayError::problem(ProblemCode::InternalError))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::base64url;
    use crate::crypto::ed25519;
    use rand::rngs::OsRng;

    #[test]
    fn assertion_is_flat_jcs_not_jwt() {
        let key = SigningKey::generate(&mut OsRng);
        let assertion = RelayAssertion::sign(
            &key,
            "relay-2026-01",
            "login.example.org".into(),
            base64url::encode(&[3u8; 32]),
            "session_123456789".into(),
            "nonce_12345678901".into(),
            base64url::encode(&[4u8; 16]),
            1_800_000_003_500,
            1_800_000_300_000,
            "Alice".into(),
            1,
        )
        .unwrap();
        let bytes = String::from_utf8(assertion.to_bytes().unwrap()).unwrap();
        assert!(!bytes.contains("eyJ"));
        assert!(bytes.contains("\"iss\":\"https://relay.pseud0.org\""));
        ed25519::verify(
            &base64url::encode(&ed25519::public_key_raw(&key)),
            assertion.canonical_without_signature().unwrap().as_bytes(),
            &assertion.signature,
        )
        .unwrap();
    }
}
