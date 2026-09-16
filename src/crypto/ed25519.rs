use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::crypto::base64url;
use crate::error::{ProblemCode, RelayError};

pub fn parse_public_key(encoded: &str) -> Result<VerifyingKey, RelayError> {
    let raw = base64url::decode(encoded)?;
    let key_bytes: [u8; 32] = match raw.len() {
        32 => raw.as_slice().try_into().unwrap(),
        44 => raw[raw.len() - 32..]
            .try_into()
            .map_err(|_| RelayError::problem(ProblemCode::InvalidSignature))?,
        _ => return Err(RelayError::problem(ProblemCode::InvalidSignature)),
    };
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| RelayError::problem(ProblemCode::InvalidSignature))
}

pub fn parse_signing_key(raw: &[u8]) -> Result<SigningKey, RelayError> {
    let seed = normalize_secret(raw)?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn public_key_raw(signing_key: &SigningKey) -> [u8; 32] {
    signing_key.verifying_key().to_bytes()
}

pub fn sign(signing_key: &SigningKey, message: &[u8]) -> String {
    base64url::encode(&signing_key.sign(message).to_bytes())
}

pub fn verify(public_key: &str, message: &[u8], signature: &str) -> Result<(), RelayError> {
    let verifying = parse_public_key(public_key)?;
    let sig_bytes = base64url::decode(signature)?;
    if sig_bytes.len() != 64 {
        return Err(RelayError::problem(ProblemCode::InvalidSignature));
    }
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|_| RelayError::problem(ProblemCode::InvalidSignature))?;
    verifying
        .verify(message, &signature)
        .map_err(|_| RelayError::problem(ProblemCode::InvalidSignature))
}

fn normalize_secret(raw: &[u8]) -> Result<[u8; 32], RelayError> {
    if raw.len() == 32 {
        return Ok(raw.try_into().unwrap());
    }
    let text = std::str::from_utf8(raw)
        .map_err(|_| RelayError::problem(ProblemCode::InvalidRequest))?
        .trim();
    if let Ok(bytes) = hex::decode(text) {
        if bytes.len() == 32 {
            return Ok(bytes.try_into().unwrap());
        }
    }
    if let Ok(bytes) = base64url::decode(text) {
        if bytes.len() == 32 {
            return Ok(bytes.try_into().unwrap());
        }
    }
    Err(RelayError::problem(ProblemCode::InvalidRequest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::jcs;
    use rand::rngs::OsRng;
    use serde_json::json;

    #[test]
    fn signs_and_verifies_metadata_object() {
        let key = SigningKey::generate(&mut OsRng);
        let public = base64url::encode(&public_key_raw(&key));
        let message = jcs::canonicalize(&json!({
            "displayName": "Example",
            "domain": "login.example.org",
            "publicKey": public,
            "version": 1
        }))
        .unwrap();
        let signature = sign(&key, message.as_bytes());
        assert_eq!(signature.len(), 86);
        verify(&public, message.as_bytes(), &signature).unwrap();
        assert!(verify(&public, b"mutated", &signature).is_err());
    }
}
