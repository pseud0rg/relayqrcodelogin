use serde::{Deserialize, Serialize};

use crate::constants::{MATRIX_PREFIX, MAX_DECODED_BODY};
use crate::crypto::base64url;
use crate::error::{ProblemCode, RelayError};
use crate::json::strict;
use crate::protocol::validation::{validate_challenge_token, validate_domain_field, validate_id, validate_reason};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum MatrixMessage {
    #[serde(rename = "request")]
    Request {
        #[serde(rename = "sessionId")]
        session_id: String,
        nonce: String,
        #[serde(rename = "sentAt")]
        sent_at: i64,
        domain: String,
    },
    #[serde(rename = "challenge")]
    Challenge {
        #[serde(rename = "sessionId")]
        session_id: String,
        nonce: String,
        #[serde(rename = "sentAt")]
        sent_at: i64,
        #[serde(rename = "siteName")]
        site_name: String,
        domain: String,
        #[serde(rename = "requestedDisplayName")]
        requested_display_name: String,
        challenge: String,
        #[serde(rename = "expiresAt")]
        expires_at: i64,
    },
    #[serde(rename = "consent")]
    Consent {
        #[serde(rename = "sessionId")]
        session_id: String,
        nonce: String,
        #[serde(rename = "sentAt")]
        sent_at: i64,
        approved: bool,
        #[serde(rename = "displayName")]
        display_name: Option<String>,
        challenge: String,
        #[serde(rename = "keyId")]
        key_id: String,
        signature: String,
    },
    #[serde(rename = "result")]
    Result {
        #[serde(rename = "sessionId")]
        session_id: String,
        nonce: String,
        #[serde(rename = "sentAt")]
        sent_at: i64,
        success: bool,
        #[serde(rename = "siteAccountId")]
        site_account_id: Option<String>,
        reason: Option<String>,
    },
    #[serde(rename = "revocation")]
    Revocation {
        #[serde(rename = "sessionId")]
        session_id: String,
        nonce: String,
        #[serde(rename = "sentAt")]
        sent_at: i64,
        #[serde(rename = "siteAccountId")]
        site_account_id: String,
        reason: Option<String>,
    },
}

pub fn encode(message: &MatrixMessage) -> Result<String, RelayError> {
    validate_outbound(message)?;
    let json = serde_json::to_vec(message)
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    if json.len() > MAX_DECODED_BODY {
        return Err(RelayError::problem(ProblemCode::InvalidRequest));
    }
    Ok(format!("{}{}", MATRIX_PREFIX, base64url::encode(&json)))
}

pub fn decode(body: &str) -> Result<MatrixMessage, RelayError> {
    if body.len() > MAX_DECODED_BODY * 2 || !body.starts_with(MATRIX_PREFIX) {
        return Err(RelayError::problem(ProblemCode::InvalidRequest));
    }
    let encoded = &body[MATRIX_PREFIX.len()..];
    let bytes = base64url::decode(encoded)?;
    if bytes.len() > MAX_DECODED_BODY {
        return Err(RelayError::problem(ProblemCode::InvalidRequest));
    }
    let message: MatrixMessage = strict::from_slice(&bytes)?;
    validate_inbound(&message)?;
    Ok(message)
}

fn validate_outbound(message: &MatrixMessage) -> Result<(), RelayError> {
    match message {
        MatrixMessage::Challenge {
            session_id,
            nonce,
            site_name,
            domain,
            requested_display_name,
            challenge,
            ..
        } => {
            validate_id(session_id)?;
            validate_id(nonce)?;
            validate_domain_field(domain)?;
            if site_name.is_empty() || site_name.len() > crate::constants::MAX_DISPLAY_NAME {
                return Err(RelayError::problem(ProblemCode::InvalidRequest));
            }
            if requested_display_name.len() > crate::constants::MAX_DISPLAY_NAME {
                return Err(RelayError::problem(ProblemCode::InvalidRequest));
            }
            validate_challenge_token(challenge)?;
        }
        MatrixMessage::Result {
            session_id,
            nonce,
            site_account_id,
            reason,
            ..
        } => {
            validate_id(session_id)?;
            validate_id(nonce)?;
            if let Some(account) = site_account_id {
                crate::protocol::validation::validate_site_account_id(account)?;
            }
            if let Some(reason) = reason {
                validate_reason(reason)?;
            }
        }
        MatrixMessage::Revocation {
            session_id,
            nonce,
            site_account_id,
            reason,
            ..
        } => {
            validate_id(session_id)?;
            validate_id(nonce)?;
            crate::protocol::validation::validate_site_account_id(site_account_id)?;
            if let Some(reason) = reason {
                validate_reason(reason)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_inbound(message: &MatrixMessage) -> Result<(), RelayError> {
    match message {
        MatrixMessage::Request {
            session_id,
            nonce,
            domain,
            ..
        } => {
            validate_id(session_id)?;
            validate_id(nonce)?;
            validate_domain_field(domain)?;
        }
        MatrixMessage::Consent {
            session_id,
            nonce,
            approved,
            display_name,
            challenge,
            key_id,
            signature,
            ..
        } => {
            validate_id(session_id)?;
            validate_id(nonce)?;
            validate_challenge_token(challenge)?;
            if !key_id.starts_with("did:") || key_id.len() > 512 {
                return Err(RelayError::problem(ProblemCode::InvalidSignature));
            }
            crate::protocol::validation::validate_signature_b64(signature)?;
            match (approved, display_name) {
                (true, Some(name))
                    if !name.is_empty() && name.len() <= crate::constants::MAX_DISPLAY_NAME => {}
                (false, None) => {}
                _ => return Err(RelayError::problem(ProblemCode::InvalidRequest)),
            }
        }
        MatrixMessage::Revocation {
            session_id,
            nonce,
            site_account_id,
            reason,
            ..
        } => {
            validate_id(session_id)?;
            validate_id(nonce)?;
            crate::protocol::validation::validate_site_account_id(site_account_id)?;
            if let Some(reason) = reason {
                validate_reason(reason)?;
            }
        }
        MatrixMessage::Challenge { .. } | MatrixMessage::Result { .. } => {
            return Err(RelayError::problem(ProblemCode::InvalidRequest));
        }
    }
    Ok(())
}

pub fn consent_signed_bytes(
    approved: bool,
    challenge: &str,
    display_name: Option<&str>,
    nonce: &str,
    session_id: &str,
    sent_at: i64,
) -> Result<Vec<u8>, RelayError> {
    let mut fields = vec![
        ("approved", serde_json::json!(approved)),
        ("challenge", serde_json::json!(challenge)),
        ("nonce", serde_json::json!(nonce)),
        ("sessionId", serde_json::json!(session_id)),
        ("sentAt", serde_json::json!(sent_at)),
    ];
    if let Some(name) = display_name {
        fields.push(("displayName", serde_json::json!(name)));
    }
    Ok(crate::crypto::jcs::canonicalize_object(&fields)?.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip_matches_kind_discriminator() {
        let message = MatrixMessage::Request {
            session_id: "session_123456789".into(),
            nonce: "nonce_12345678901".into(),
            sent_at: 1_800_000_001_000,
            domain: "login.example.org".into(),
        };
        let encoded = encode(&message).unwrap();
        assert!(encoded.starts_with(MATRIX_PREFIX));
        assert!(!encoded.contains('='));
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, message);
        let json = String::from_utf8(base64url::decode(&encoded[MATRIX_PREFIX.len()..]).unwrap()).unwrap();
        assert!(json.contains(r#""kind":"request""#));
        assert!(json.contains(r#""sessionId""#));
    }

    #[test]
    fn result_emits_explicit_nulls() {
        let message = MatrixMessage::Result {
            session_id: "session_123456789".into(),
            nonce: "nonce_12345678901".into(),
            sent_at: 4,
            success: false,
            site_account_id: None,
            reason: Some("request_expired".into()),
        };
        let json = serde_json::to_string(&message).unwrap();
        assert!(json.contains(r#""siteAccountId":null"#));
        assert!(json.contains(r#""reason":"request_expired""#));
    }

    #[test]
    fn consent_signed_object_omits_null_display_name() {
        let with_name = String::from_utf8(consent_signed_bytes(
            true,
            "challenge_123456",
            Some("Alice"),
            "nonce_12345678901",
            "session_123456789",
            1_800_000_003_000,
        ).unwrap()).unwrap();
        assert!(with_name.contains("displayName"));
        let refused = String::from_utf8(consent_signed_bytes(
            false,
            "challenge_123456",
            None,
            "nonce_12345678901",
            "session_123456789",
            1_800_000_003_000,
        ).unwrap()).unwrap();
        assert!(!refused.contains("displayName"));
    }
}
