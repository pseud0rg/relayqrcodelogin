use serde::{Deserialize, Serialize};

use crate::constants::PROTOCOL_VERSION;
use crate::crypto::jcs;
use crate::error::{ProblemCode, RelayError};
use crate::protocol::time::validate_window;
use crate::protocol::validation::{
    validate_display_name, validate_domain_field, validate_id, validate_signature_b64,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationRequest {
    pub version: i64,
    pub domain: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub nonce: String,
    pub iat: i64,
    pub exp: i64,
    #[serde(rename = "requestedDisplayName")]
    pub requested_display_name: String,
    #[serde(rename = "qrSignature")]
    pub qr_signature: String,
    #[serde(rename = "registrationSignature")]
    pub registration_signature: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistrationResponse {
    pub version: i64,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub status: &'static str,
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
}

impl RegistrationRequest {
    pub fn validate(&self) -> Result<(), RelayError> {
        if self.version != PROTOCOL_VERSION {
            return Err(RelayError::problem(ProblemCode::UnsupportedVersion));
        }
        validate_domain_field(&self.domain)?;
        validate_id(&self.session_id)?;
        validate_id(&self.nonce)?;
        validate_window(self.iat, self.exp)?;
        validate_display_name(&self.requested_display_name, false)?;
        validate_signature_b64(&self.qr_signature)?;
        validate_signature_b64(&self.registration_signature)?;
        Ok(())
    }

    pub fn qr_canonical(&self) -> Result<Vec<u8>, RelayError> {
        Ok(jcs::canonicalize_object(&[
            ("domain", serde_json::json!(self.domain)),
            ("exp", serde_json::json!(self.exp)),
            ("iat", serde_json::json!(self.iat)),
            ("nonce", serde_json::json!(self.nonce)),
            ("session", serde_json::json!(self.session_id)),
            ("v", serde_json::json!(self.version)),
        ])?
        .into_bytes())
    }

    pub fn registration_canonical(&self) -> Result<Vec<u8>, RelayError> {
        Ok(jcs::canonicalize_object(&[
            ("domain", serde_json::json!(self.domain)),
            ("exp", serde_json::json!(self.exp)),
            ("iat", serde_json::json!(self.iat)),
            ("nonce", serde_json::json!(self.nonce)),
            ("qrSignature", serde_json::json!(self.qr_signature)),
            ("requestedDisplayName", serde_json::json!(self.requested_display_name)),
            ("sessionId", serde_json::json!(self.session_id)),
            ("version", serde_json::json!(self.version)),
        ])?
        .into_bytes())
    }
}
