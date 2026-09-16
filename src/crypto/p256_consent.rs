use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use signature::hazmat::PrehashVerifier;

use crate::crypto::base64url;
use crate::crypto::did_key;
use crate::error::{ProblemCode, RelayError};

pub fn verify_consent_signature(
    key_id: &str,
    canonical: &[u8],
    signature: &str,
) -> Result<(), RelayError> {
    let public = did_key::decode_p256_did_key(key_id)?;
    let verifying = VerifyingKey::from(public);
    let raw = base64url::decode(signature)?;
    if raw.len() != 64 {
        return Err(RelayError::problem(ProblemCode::InvalidSignature));
    }
    if looks_like_der(&raw) {
        return Err(RelayError::problem(ProblemCode::InvalidSignature));
    }
    let signature = Signature::from_slice(&raw)
        .map_err(|_| RelayError::problem(ProblemCode::InvalidSignature))?;
    let digest = Sha256::digest(canonical);
    verifying
        .verify_prehash(&digest, &signature)
        .map_err(|_| RelayError::problem(ProblemCode::InvalidSignature))
}

fn looks_like_der(bytes: &[u8]) -> bool {
    bytes.first() == Some(&0x30)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::base64url;
    use crate::crypto::did_key;
    use crate::crypto::jcs;
    use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
    use rand::rngs::OsRng;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    fn sign_raw(signing: &SigningKey, message: &[u8]) -> String {
        let digest = Sha256::digest(message);
        let (sig, _): (Signature, _) = signing.sign_prehash(&digest).unwrap();
        base64url::encode(&sig.to_bytes())
    }

    #[test]
    fn raw_r_s_succeeds_and_omits_null_display_name() {
        let signing = SigningKey::random(&mut OsRng);
        let did = did_key::encode_p256_did_key(&p256::PublicKey::from(signing.verifying_key()));
        let canonical = jcs::canonicalize(&json!({
            "approved": false,
            "challenge": "challenge_123456",
            "nonce": "nonce_12345678901",
            "sessionId": "session_123456789",
            "sentAt": 1800000003000_i64
        }))
        .unwrap();
        assert!(!canonical.contains("displayName"));
        let signature = sign_raw(&signing, canonical.as_bytes());
        verify_consent_signature(&did, canonical.as_bytes(), &signature).unwrap();
    }

    #[test]
    fn der_and_wrong_did_fail() {
        let signing = SigningKey::random(&mut OsRng);
        let did = did_key::encode_p256_did_key(&p256::PublicKey::from(signing.verifying_key()));
        let message = b"{\"approved\":true}";
        let digest = Sha256::digest(message);
        let (sig, _): (Signature, _) = signing.sign_prehash(&digest).unwrap();
        let der = sig.to_der();
        let der_b64 = base64url::encode(der.as_bytes());
        assert!(verify_consent_signature(&did, message, &der_b64).is_err());
        assert!(verify_consent_signature("did:key:zWrong", message, &base64url::encode(&sig.to_bytes())).is_err());
    }
}
