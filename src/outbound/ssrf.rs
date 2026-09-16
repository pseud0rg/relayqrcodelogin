use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::error::{ProblemCode, RelayError};
use crate::protocol::domain::validate_domain;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(5);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeTarget {
    pub host: String,
    pub path: &'static str,
    pub addr: SocketAddr,
}

pub fn site_url(domain: &str, path: &'static str) -> Result<(String, &'static str), RelayError> {
    validate_domain(domain)?;
    if !path.starts_with('/') || path.contains("://") || path.contains('@') || path.contains('#') {
        return Err(RelayError::problem(ProblemCode::DomainVerificationFailed));
    }
    Ok((domain.to_string(), path))
}

pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => is_blocked_v6(v6),
    }
}

fn is_blocked_v4(ip: Ipv4Addr) -> bool {
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || matches!(ip.octets(), [100, 64..=127, _, _]) // CGNAT
        || matches!(ip.octets(), [192, 0, 0, _])
        || matches!(ip.octets(), [198, 18..=19, _, _])
        || matches!(ip.octets(), [169, 254, _, _])
        || ip == Ipv4Addr::new(169, 254, 169, 254)
        || ip == Ipv4Addr::new(0, 0, 0, 0)
}

fn is_blocked_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_blocked_v4(v4);
    }
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || ip.is_unique_local()
        || (ip.segments()[0] & 0xffc0) == 0xfe80 // link-local
        || ip.segments()[0] == 0x2001 && ip.segments()[1] == 0xdb8
        || ip == Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0)
}

pub fn pick_public_address(resolved: &[IpAddr]) -> Result<IpAddr, RelayError> {
    resolved
        .iter()
        .copied()
        .find(|ip| !is_blocked_ip(*ip))
        .ok_or(RelayError::problem(ProblemCode::DomainVerificationFailed))
}

pub fn pinned_socket(ip: IpAddr) -> SocketAddr {
    SocketAddr::new(ip, 443)
}

pub fn timeouts() -> (Duration, Duration, Duration) {
    (CONNECT_TIMEOUT, FIRST_BYTE_TIMEOUT, TOTAL_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_private_metadata_and_loopback() {
        assert!(is_blocked_ip("127.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("10.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("192.168.1.1".parse().unwrap()));
        assert!(is_blocked_ip("169.254.169.254".parse().unwrap()));
        assert!(is_blocked_ip("100.64.0.1".parse().unwrap()));
        assert!(is_blocked_ip("::1".parse().unwrap()));
        assert!(is_blocked_ip("::ffff:10.1.2.3".parse().unwrap()));
        assert!(!is_blocked_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn rejects_unsafe_url_inputs() {
        assert!(site_url("login.example.org.", "/.well-known/pseud0-web-login").is_err());
        assert!(site_url("127.0.0.1", "/.well-known/pseud0-web-login").is_err());
        site_url("login.example.org", "/.well-known/pseud0-web-login").unwrap();
    }
}
