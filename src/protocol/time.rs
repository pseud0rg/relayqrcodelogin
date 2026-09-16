use crate::constants::{CLOCK_SKEW_MS, MAX_TTL_MS};
use crate::error::{ProblemCode, RelayError};

pub fn validate_window(iat: i64, exp: i64) -> Result<(), RelayError> {
    if exp <= iat || exp.saturating_sub(iat) > MAX_TTL_MS {
        return Err(RelayError::problem(ProblemCode::RequestExpired));
    }
    Ok(())
}

pub fn sent_at_in_qr_window(sent_at: i64, iat: i64, exp: i64) -> bool {
    sent_at >= iat.saturating_sub(CLOCK_SKEW_MS) && sent_at <= exp
}

pub fn challenge_expires_at(sent_at: i64, registration_exp: i64) -> i64 {
    sent_at.saturating_add(MAX_TTL_MS).min(registration_exp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_over_five_minutes_fails() {
        assert!(validate_window(1_800_000_000_000, 1_800_000_000_000 + 300_001).is_err());
        validate_window(1_800_000_000_000, 1_800_000_000_000 + 300_000).unwrap();
    }

    #[test]
    fn milliseconds_not_seconds() {
        let iat = 1_800_000_000_000;
        assert!(sent_at_in_qr_window(iat, iat, iat + 300_000));
        assert!(!sent_at_in_qr_window(1_800_000_000, iat, iat + 300_000));
    }
}
