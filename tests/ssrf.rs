use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use pseud0_web_login_relay::constants::METADATA_PATH;
use pseud0_web_login_relay::error::ProblemCode;
use pseud0_web_login_relay::outbound::site_client::{DnsResolver, SiteFetcher, SsrfSiteClient};
use pseud0_web_login_relay::outbound::ssrf::{is_blocked_ip, pick_public_address, site_url};

struct FixedDns(Vec<IpAddr>);

#[async_trait]
impl DnsResolver for FixedDns {
    async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, pseud0_web_login_relay::error::RelayError> {
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn private_and_metadata_ips_are_rejected() {
    for ip in ["127.0.0.1", "10.1.2.3", "192.168.0.8", "169.254.169.254", "100.64.1.1"] {
        let parsed: IpAddr = ip.parse().unwrap();
        assert!(is_blocked_ip(parsed), "{ip}");
        let client = SsrfSiteClient::new(Arc::new(FixedDns(vec![parsed])));
        let error = client.fetch_metadata("login.example.org").await.unwrap_err();
        assert_eq!(error.code(), ProblemCode::DomainVerificationFailed);
    }
}

#[test]
fn alternate_port_and_userinfo_never_enter_url_builder() {
    assert!(site_url("login.example.org:8443", METADATA_PATH).is_err());
    assert!(site_url("user:pass@login.example.org", METADATA_PATH).is_err());
    let (host, path) = site_url("login.example.org", METADATA_PATH).unwrap();
    assert_eq!(host, "login.example.org");
    assert_eq!(path, METADATA_PATH);
}

#[test]
fn dns_rebinding_to_only_private_addresses_fails() {
    let ips = vec![
        "10.0.0.1".parse().unwrap(),
        "169.254.169.254".parse().unwrap(),
    ];
    assert!(pick_public_address(&ips).is_err());
}
