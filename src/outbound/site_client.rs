use std::net::IpAddr;
use std::sync::Arc;
use async_trait::async_trait;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::constants::{MAX_METADATA_BYTES, MAX_SITE_RESPONSE_BYTES, METADATA_PATH};
use crate::error::{ProblemCode, RelayError};
use crate::json::strict;
use crate::outbound::ssrf::{
    is_blocked_ip, pick_public_address, pinned_socket, site_url, timeouts,
};
use crate::protocol::metadata::SiteMetadata;

#[derive(Debug, Clone)]
pub struct SiteResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

#[async_trait]
pub trait SiteFetcher: Send + Sync {
    async fn fetch_metadata(&self, domain: &str) -> Result<SiteMetadata, RelayError>;
    async fn post_json(
        &self,
        domain: &str,
        path: &'static str,
        body: &[u8],
        idempotency_key: Option<&str>,
    ) -> Result<SiteResponse, RelayError>;
}

#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, RelayError>;
}

pub struct SystemDns;

#[async_trait]
impl DnsResolver for SystemDns {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, RelayError> {
        let host = host.to_string();
        tokio::task::spawn_blocking(move || {
            std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), 443))
                .map(|iter| iter.map(|addr| addr.ip()).collect::<Vec<_>>())
                .map_err(|_| RelayError::problem(ProblemCode::DomainVerificationFailed))
        })
        .await
        .map_err(|_| RelayError::problem(ProblemCode::RelayUnavailable))?
    }
}

pub struct SsrfSiteClient {
    resolver: Arc<dyn DnsResolver>,
    tls: TlsConnector,
}

impl SsrfSiteClient {
    pub fn new(resolver: Arc<dyn DnsResolver>) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            resolver,
            tls: TlsConnector::from(Arc::new(config)),
        }
    }

    pub fn production() -> Self {
        Self::new(Arc::new(SystemDns))
    }

    async fn request(
        &self,
        domain: &str,
        path: &'static str,
        method: &str,
        extra_headers: &[(&str, &str)],
        body: &[u8],
        max_body: usize,
    ) -> Result<SiteResponse, RelayError> {
        let (host, path) = site_url(domain, path)?;
        let ips = self.resolver.resolve(&host).await?;
        let ip = pick_public_address(&ips)?;
        if is_blocked_ip(ip) {
            return Err(RelayError::problem(ProblemCode::DomainVerificationFailed));
        }
        let (connect_t, first_byte_t, total_t) = timeouts();
        timeout(total_t, async {
            let stream = timeout(connect_t, TcpStream::connect(pinned_socket(ip)))
                .await
                .map_err(|_| RelayError::problem(ProblemCode::DomainVerificationFailed))?
                .map_err(|_| RelayError::problem(ProblemCode::DomainVerificationFailed))?;
            let server_name = ServerName::try_from(host.clone())
                .map_err(|_| RelayError::problem(ProblemCode::DomainVerificationFailed))?;
            let mut tls = timeout(connect_t, self.tls.connect(server_name, stream))
                .await
                .map_err(|_| RelayError::problem(ProblemCode::DomainVerificationFailed))?
                .map_err(|_| RelayError::problem(ProblemCode::DomainVerificationFailed))?;

            let mut request = format!(
                "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nConnection: close\r\n"
            );
            if !body.is_empty() {
                request.push_str("Content-Type: application/json\r\n");
                request.push_str(&format!("Content-Length: {}\r\n", body.len()));
            }
            for (name, value) in extra_headers {
                request.push_str(&format!("{name}: {value}\r\n"));
            }
            request.push_str("\r\n");
            tls.write_all(request.as_bytes())
                .await
                .map_err(|_| RelayError::problem(ProblemCode::DomainVerificationFailed))?;
            if !body.is_empty() {
                tls.write_all(body)
                    .await
                    .map_err(|_| RelayError::problem(ProblemCode::DomainVerificationFailed))?;
            }
            tls.flush()
                .await
                .map_err(|_| RelayError::problem(ProblemCode::DomainVerificationFailed))?;

            let mut buf = Vec::new();
            timeout(first_byte_t, tls.read_buf(&mut buf))
                .await
                .map_err(|_| RelayError::problem(ProblemCode::DomainVerificationFailed))?
                .map_err(|_| RelayError::problem(ProblemCode::DomainVerificationFailed))?;
            let mut tmp = [0u8; 2048];
            loop {
                if buf.len() > max_body + 1024 {
                    return Err(RelayError::problem(ProblemCode::DomainVerificationFailed));
                }
                match tls.read(&mut tmp).await {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => return Err(RelayError::problem(ProblemCode::DomainVerificationFailed)),
                }
            }
            parse_http_response(&buf, max_body)
        })
        .await
        .map_err(|_| RelayError::problem(ProblemCode::DomainVerificationFailed))?
    }
}

#[async_trait]
impl SiteFetcher for SsrfSiteClient {
    async fn fetch_metadata(&self, domain: &str) -> Result<SiteMetadata, RelayError> {
        let response = self
            .request(domain, METADATA_PATH, "GET", &[], &[], MAX_METADATA_BYTES)
            .await?;
        if response.status != 200 {
            return Err(RelayError::problem(ProblemCode::DomainVerificationFailed));
        }
        let metadata: SiteMetadata = strict::from_slice(&response.body)
            .map_err(|_| RelayError::problem(ProblemCode::DomainVerificationFailed))?;
        metadata.validate_for_domain(domain)?;
        Ok(metadata)
    }

    async fn post_json(
        &self,
        domain: &str,
        path: &'static str,
        body: &[u8],
        idempotency_key: Option<&str>,
    ) -> Result<SiteResponse, RelayError> {
        let mut headers = Vec::new();
        if let Some(key) = idempotency_key {
            headers.push(("Idempotency-Key", key));
        }
        self.request(
            domain,
            path,
            "POST",
            &headers,
            body,
            MAX_SITE_RESPONSE_BYTES,
        )
        .await
    }
}

fn parse_http_response(raw: &[u8], max_body: usize) -> Result<SiteResponse, RelayError> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| RelayError::problem(ProblemCode::DomainVerificationFailed))?;
    let (header, body) = text
        .split_once("\r\n\r\n")
        .ok_or(RelayError::problem(ProblemCode::DomainVerificationFailed))?;
    let mut lines = header.split("\r\n");
    let status_line = lines
        .next()
        .ok_or(RelayError::problem(ProblemCode::DomainVerificationFailed))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or(RelayError::problem(ProblemCode::DomainVerificationFailed))?;
    let mut redirected = false;
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("location:") {
            redirected = true;
        }
    }
    if redirected || (300..400).contains(&status) {
        return Err(RelayError::problem(ProblemCode::DomainVerificationFailed));
    }
    if body.len() > max_body {
        return Err(RelayError::problem(ProblemCode::DomainVerificationFailed));
    }
    Ok(SiteResponse {
        status,
        body: body.as_bytes().to_vec(),
    })
}

#[derive(Default)]
pub struct RecordingSite {
    pub metadata: std::sync::Mutex<Option<SiteMetadata>>,
    pub posts: std::sync::Mutex<Vec<(String, String, Vec<u8>)>>,
    pub post_status: std::sync::Mutex<u16>,
}

impl RecordingSite {
    pub fn with_metadata(metadata: SiteMetadata) -> Self {
        Self {
            metadata: std::sync::Mutex::new(Some(metadata)),
            posts: std::sync::Mutex::new(Vec::new()),
            post_status: std::sync::Mutex::new(202),
        }
    }
}

#[async_trait]
impl SiteFetcher for RecordingSite {
    async fn fetch_metadata(&self, domain: &str) -> Result<SiteMetadata, RelayError> {
        let metadata = self
            .metadata
            .lock()
            .unwrap()
            .clone()
            .ok_or(RelayError::problem(ProblemCode::DomainVerificationFailed))?;
        metadata.validate_for_domain(domain)?;
        Ok(metadata)
    }

    async fn post_json(
        &self,
        domain: &str,
        path: &'static str,
        body: &[u8],
        _idempotency_key: Option<&str>,
    ) -> Result<SiteResponse, RelayError> {
        self.posts
            .lock()
            .unwrap()
            .push((domain.to_string(), path.to_string(), body.to_vec()));
        Ok(SiteResponse {
            status: *self.post_status.lock().unwrap(),
            body: br#"{"status":"accepted"}"#.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_redirect_status() {
        let raw = b"HTTP/1.1 302 Found\r\nLocation: https://evil/\r\n\r\n";
        assert!(parse_http_response(raw, 1024).is_err());
    }
}
