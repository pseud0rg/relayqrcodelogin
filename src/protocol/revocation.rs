use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::constants::{PROTOCOL_VERSION, RELAY_ORIGIN};
use crate::crypto::{ed25519, jcs};
use crate::error::{ProblemCode, RelayError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayRevocation {
    pub version: i64,
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub jti: String,
    pub iat: i64,
    pub reason: String,
    pub kid: String,
    pub signature: String,
}

impl RelayRevocation {
    pub fn sign(
        signing_key: &SigningKey,
        kid: &str,
        aud: String,
        sub: String,
        jti: String,
        iat: i64,
        reason: String,
    ) -> Result<Self, RelayError> {
        let mut revocation = Self {
            version: PROTOCOL_VERSION,
            iss: RELAY_ORIGIN.to_string(),
            aud,
            sub,
            jti,
            iat,
            reason,
            kid: kid.to_string(),
            signature: String::new(),
        };
        let canonical = revocation.canonical_without_signature()?;
        revocation.signature = ed25519::sign(signing_key, canonical.as_bytes());
        Ok(revocation)
    }

    pub fn canonical_without_signature(&self) -> Result<String, RelayError> {
        jcs::canonicalize_object(&[
            ("aud", serde_json::json!(self.aud)),
            ("iat", serde_json::json!(self.iat)),
            ("iss", serde_json::json!(self.iss)),
            ("jti", serde_json::json!(self.jti)),
            ("kid", serde_json::json!(self.kid)),
            ("reason", serde_json::json!(self.reason)),
            ("sub", serde_json::json!(self.sub)),
            ("version", serde_json::json!(self.version)),
        ])
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, RelayError> {
        serde_json::to_vec(self).map_err(|_| RelayError::problem(ProblemCode::InternalError))
    }
}
