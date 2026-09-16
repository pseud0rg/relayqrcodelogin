use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use crate::error::{ProblemCode, RelayError};

pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode(value: &str) -> Result<Vec<u8>, RelayError> {
    if value.as_bytes().iter().any(|b| *b == b'=') {
        return Err(RelayError::problem(ProblemCode::InvalidRequest));
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(RelayError::problem(ProblemCode::InvalidRequest));
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| RelayError::problem(ProblemCode::InvalidRequest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_unpadded() {
        let encoded = encode(&[1, 2, 3, 4]);
        assert!(!encoded.contains('='));
        assert_eq!(decode(&encoded).unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn rejects_padding() {
        assert!(decode("AQIDBA==").is_err());
    }
}
