use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::constants::SUBJECT_CONTEXT;
use crate::crypto::base64url;
use crate::error::{ProblemCode, RelayError};

type HmacSha256 = Hmac<Sha256>;

pub fn derive_pairwise_sub(
    subject_secret: &[u8],
    domain: &str,
    matrix_user_id: &str,
) -> Result<String, RelayError> {
    if subject_secret.len() < 32 {
        return Err(RelayError::problem(ProblemCode::InternalError));
    }
    let mut mac = <HmacSha256 as Mac>::new_from_slice(subject_secret)
        .map_err(|_| RelayError::problem(ProblemCode::InternalError))?;
    mac.update(SUBJECT_CONTEXT);
    mac.update(&(domain.len() as u32).to_be_bytes());
    mac.update(domain.as_bytes());
    mac.update(&(matrix_user_id.len() as u32).to_be_bytes());
    mac.update(matrix_user_id.as_bytes());
    let sub = base64url::encode(&mac.finalize().into_bytes());
    if sub.len() != 43 {
        return Err(RelayError::problem(ProblemCode::InternalError));
    }
    Ok(sub)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_per_domain_and_unlinkable_across_domains() {
        let secret = [7u8; 32];
        let a = derive_pairwise_sub(&secret, "login.example.org", "@alice:pseud0.org").unwrap();
        let b = derive_pairwise_sub(&secret, "login.example.org", "@alice:pseud0.org").unwrap();
        let c = derive_pairwise_sub(&secret, "other.example.org", "@alice:pseud0.org").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 43);
        assert!(!a.contains('@'));
    }
}
