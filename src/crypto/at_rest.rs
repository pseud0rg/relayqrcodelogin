use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;

use crate::crypto::base64url;
use crate::error::{ProblemCode, RelayError};

const NONCE_LEN: usize = 12;

#[derive(Clone)]
pub struct AtRestKey([u8; 32]);

impl AtRestKey {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, RelayError> {
        let bytes = normalize_32(raw)?;
        Ok(Self(bytes))
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, RelayError> {
        let cipher = Aes256Gcm::new_from_slice(&self.0)
            .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut out = nonce_bytes.to_vec();
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>, RelayError> {
        if blob.len() <= NONCE_LEN {
            return Err(RelayError::problem(ProblemCode::InternalError));
        }
        let cipher = Aes256Gcm::new_from_slice(&self.0)
            .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
        let nonce = Nonce::from_slice(&blob[..NONCE_LEN]);
        cipher
            .decrypt(nonce, &blob[NONCE_LEN..])
            .map_err(|_| RelayError::problem(ProblemCode::InternalError))
    }
}

pub fn keyed_hash(pepper: &[u8], data: &[u8]) -> Result<[u8; 32], RelayError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(pepper)
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

fn normalize_32(raw: &[u8]) -> Result<[u8; 32], RelayError> {
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

    #[test]
    fn encrypt_round_trip() {
        let key = AtRestKey::from_bytes(&[9u8; 32]).unwrap();
        let blob = key.encrypt(b"hidden").unwrap();
        assert_eq!(key.decrypt(&blob).unwrap(), b"hidden");
    }
}
