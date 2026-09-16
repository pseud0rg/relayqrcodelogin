use serde::Deserialize;

use crate::constants::{MAX_DISPLAY_NAME, PROTOCOL_VERSION};
use crate::crypto::ed25519;
use crate::crypto::jcs;
use crate::error::{ProblemCode, RelayError};
use crate::protocol::validation::validate_domain_field;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SiteMetadata {
    pub version: i64,
    pub domain: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub signature: String,
}

impl SiteMetadata {
    pub fn validate_for_domain(&self, expected_domain: &str) -> Result<(), RelayError> {
        if self.version != PROTOCOL_VERSION {
            return Err(RelayError::problem(ProblemCode::UnsupportedVersion));
        }
        validate_domain_field(&self.domain)?;
        if self.domain != expected_domain {
            return Err(RelayError::problem(ProblemCode::DomainVerificationFailed));
        }
        if self.display_name.trim().is_empty() || self.display_name.len() > MAX_DISPLAY_NAME {
            return Err(RelayError::problem(ProblemCode::DomainVerificationFailed));
        }
        if self.public_key.len() != 43 {
            return Err(RelayError::problem(ProblemCode::DomainVerificationFailed));
        }
        let canonical = jcs::canonicalize_object(&[
            ("displayName", serde_json::json!(self.display_name)),
            ("domain", serde_json::json!(self.domain)),
            ("publicKey", serde_json::json!(self.public_key)),
            ("version", serde_json::json!(self.version)),
        ])?;
        ed25519::verify(&self.public_key, canonical.as_bytes(), &self.signature)
            .map_err(|_| RelayError::problem(ProblemCode::DomainVerificationFailed))
    }
}
