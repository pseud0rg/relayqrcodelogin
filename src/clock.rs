use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use chrono::Utc;

pub trait Clock: Send + Sync {
    fn now_ms(&self) -> i64;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        Utc::now().timestamp_millis()
    }
}

#[derive(Debug, Clone)]
pub struct FrozenClock {
    value: Arc<AtomicI64>,
}

impl FrozenClock {
    pub fn new(ms: i64) -> Self {
        Self {
            value: Arc::new(AtomicI64::new(ms)),
        }
    }

    pub fn set(&self, ms: i64) {
        self.value.store(ms, Ordering::SeqCst);
    }
}

impl Clock for FrozenClock {
    fn now_ms(&self) -> i64 {
        self.value.load(Ordering::SeqCst)
    }
}
