use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;

use crate::error::{ProblemCode, RelayError};

const MULTICODEC_P256: [u8; 2] = [0x80, 0x24];

pub fn decode_p256_did_key(key_id: &str) -> Result<PublicKey, RelayError> {
    let encoded = key_id
        .strip_prefix("did:key:z")
        .ok_or(RelayError::problem(ProblemCode::InvalidSignature))?;
    let decoded = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| RelayError::problem(ProblemCode::InvalidSignature))?;
    if decoded.len() != 35 || decoded[0] != MULTICODEC_P256[0] || decoded[1] != MULTICODEC_P256[1] {
        return Err(RelayError::problem(ProblemCode::InvalidSignature));
    }
    if decoded[2] != 0x02 && decoded[2] != 0x03 {
        return Err(RelayError::problem(ProblemCode::InvalidSignature));
    }
    PublicKey::from_sec1_bytes(&decoded[2..])
        .map_err(|_| RelayError::problem(ProblemCode::InvalidSignature))
}

pub fn encode_p256_did_key(public_key: &PublicKey) -> String {
    let point = public_key.to_encoded_point(true);
    let mut payload = Vec::with_capacity(35);
    payload.extend_from_slice(&MULTICODEC_P256);
    payload.extend_from_slice(point.as_bytes());
    format!("did:key:z{}", bs58::encode(payload).into_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn round_trip_compressed_p256() {
        let signing = SigningKey::random(&mut OsRng);
        let public = p256::PublicKey::from(signing.verifying_key());
        let did = encode_p256_did_key(&public);
        assert!(did.starts_with("did:key:z"));
        let decoded = decode_p256_did_key(&did).unwrap();
        assert_eq!(decoded, public);
    }

    #[test]
    fn rejects_other_methods() {
        assert!(decode_p256_did_key("did:web:example.org").is_err());
        assert!(decode_p256_did_key("did:key:zQ3shokFTS3brHcDQmzN").is_err());
    }
}
