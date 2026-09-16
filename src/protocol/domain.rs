use once_cell::sync::Lazy;
use regex::Regex;

use crate::constants::MAX_DOMAIN;
use crate::error::{ProblemCode, RelayError};

static DOMAIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$").expect("domain regex")
});

pub fn validate_domain(domain: &str) -> Result<(), RelayError> {
    if domain.len() > MAX_DOMAIN
        || domain.ends_with('.')
        || domain.contains(':')
        || domain.contains('/')
        || domain.contains('@')
        || domain.parse::<std::net::IpAddr>().is_ok()
        || !DOMAIN_RE.is_match(domain)
    {
        return Err(RelayError::problem(ProblemCode::InvalidRequest));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_bare_dns() {
        validate_domain("login.example.org").unwrap();
    }

    #[test]
    fn rejects_ip_and_trailing_dot() {
        assert!(validate_domain("127.0.0.1").is_err());
        assert!(validate_domain("login.example.org.").is_err());
        assert!(validate_domain("LOGIN.EXAMPLE.ORG").is_err());
    }
}
