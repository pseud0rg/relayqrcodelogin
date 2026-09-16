use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use ed25519_dalek::SigningKey;

use crate::db::PgPool;

use crate::clock::Clock;
use crate::crypto::at_rest::AtRestKey;
use crate::outbound::site_client::SiteFetcher;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub clock: Arc<dyn Clock>,
    pub site: Arc<dyn SiteFetcher>,
    pub outbox: Arc<dyn MessageSink>,
    pub at_rest: AtRestKey,
    pub lookup_pepper: Vec<u8>,
    pub subject_secret: Vec<u8>,
    pub subject_key_version: i32,
    pub signing_key: SigningKey,
    pub signing_kid: String,
    pub relay_user_id: String,
    pub sync_ready: Arc<AtomicBool>,
    pub metrics: Arc<Metrics>,
}

#[derive(Default)]
pub struct Metrics {
    pub registrations: AtomicU64,
    pub registration_failures: AtomicU64,
    pub challenges: AtomicU64,
    pub consents: AtomicU64,
    pub replay_conflicts: AtomicU64,
    pub ssrf_rejections: AtomicU64,
    pub room_violations: AtomicU64,
    pub deliveries: AtomicU64,
}

impl Metrics {
    pub fn inc(field: &AtomicU64) {
        field.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundNotice {
    pub room_id: String,
    pub body: String,
}

#[async_trait::async_trait]
pub trait MessageSink: Send + Sync {
    async fn send_notice(&self, room_id: &str, body: &str) -> Result<(), crate::error::RelayError>;
    fn recorded(&self) -> Vec<OutboundNotice> {
        Vec::new()
    }
}

#[derive(Default)]
pub struct RecordingSink {
    pub messages: std::sync::Mutex<Vec<OutboundNotice>>,
}

#[async_trait::async_trait]
impl MessageSink for RecordingSink {
    async fn send_notice(&self, room_id: &str, body: &str) -> Result<(), crate::error::RelayError> {
        self.messages.lock().unwrap().push(OutboundNotice {
            room_id: room_id.to_string(),
            body: body.to_string(),
        });
        Ok(())
    }

    fn recorded(&self) -> Vec<OutboundNotice> {
        self.messages.lock().unwrap().clone()
    }
}

pub struct NoopSink;

#[async_trait::async_trait]
impl MessageSink for NoopSink {
    async fn send_notice(&self, _room_id: &str, _body: &str) -> Result<(), crate::error::RelayError> {
        Ok(())
    }
}
