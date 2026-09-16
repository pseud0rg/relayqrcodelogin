use once_cell::sync::Lazy;
use regex::Regex;

use crate::constants::MAX_DISPLAY_NAME;
use crate::error::{ProblemCode, RelayError};
use crate::protocol::domain::validate_domain;

static ID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9_-]{16,128}$").expect("id"));
static SIG_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9_-]{86}$").expect("sig"));
static ACCOUNT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9_-]{22,128}$").expect("sub"));
static CHALLENGE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9_-]{16,512}$").expect("ch"));
static KID_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z0-9._-]{1,64}$").expect("kid"));

pub fn validate_id(value: &str) -> Result<(), RelayError> {
    if ID_RE.is_match(value) {
        Ok(())
    } else {
        Err(RelayError::problem(ProblemCode::InvalidRequest))
    }
}

pub fn validate_signature_b64(value: &str) -> Result<(), RelayError> {
    if SIG_RE.is_match(value) {
        Ok(())
    } else {
        Err(RelayError::problem(ProblemCode::InvalidSignature))
    }
}

pub fn validate_site_account_id(value: &str) -> Result<(), RelayError> {
    if ACCOUNT_RE.is_match(value) {
        Ok(())
    } else {
        Err(RelayError::problem(ProblemCode::InvalidRequest))
    }
}

pub fn validate_challenge_token(value: &str) -> Result<(), RelayError> {
    if CHALLENGE_RE.is_match(value) {
        Ok(())
    } else {
        Err(RelayError::problem(ProblemCode::InvalidRequest))
    }
}

pub fn validate_kid(value: &str) -> Result<(), RelayError> {
    if KID_RE.is_match(value) {
        Ok(())
    } else {
        Err(RelayError::problem(ProblemCode::InvalidRequest))
    }
}

pub fn validate_reason(value: &str) -> Result<(), RelayError> {
    if value.len() <= 100 {
        Ok(())
    } else {
        Err(RelayError::problem(ProblemCode::InvalidRequest))
    }
}

pub fn validate_display_name(value: &str, required: bool) -> Result<(), RelayError> {
    if required && (value.is_empty() || value.len() > MAX_DISPLAY_NAME) {
        return Err(RelayError::problem(ProblemCode::InvalidRequest));
    }
    if value.len() > MAX_DISPLAY_NAME {
        return Err(RelayError::problem(ProblemCode::InvalidRequest));
    }
    Ok(())
}

pub fn validate_domain_field(domain: &str) -> Result<(), RelayError> {
    validate_domain(domain)
}
