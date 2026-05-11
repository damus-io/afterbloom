use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::RateLimitConfig;

/// Simple per-IP token bucket for upload count and a rolling byte budget for size.
pub struct RateLimiter {
    cfg: RateLimitConfig,
    state: Mutex<HashMap<IpAddr, IpState>>,
}

struct IpState {
    /// Token bucket for upload-count limit.
    tokens: f64,
    last_refill: Instant,
    /// Rolling byte budget — refills linearly over an hour.
    bytes_remaining: f64,
    bytes_last_refill: Instant,
}

#[derive(Debug)]
pub enum RateDecision {
    Ok,
    TooManyRequests,
    QuotaExceeded,
}

impl RateLimiter {
    pub fn new(cfg: RateLimitConfig) -> Self {
        Self {
            cfg,
            state: Mutex::new(HashMap::new()),
        }
    }

    pub fn check_upload(&self, ip: IpAddr, bytes: u64) -> RateDecision {
        let now = Instant::now();
        let mut map = self.state.lock().unwrap();
        let s = map.entry(ip).or_insert_with(|| IpState {
            tokens: self.cfg.uploads_burst as f64,
            last_refill: now,
            bytes_remaining: self.cfg.bytes_per_hour as f64,
            bytes_last_refill: now,
        });

        // Refill tokens.
        let elapsed_min = now.duration_since(s.last_refill).as_secs_f64() / 60.0;
        s.tokens = (s.tokens + elapsed_min * self.cfg.uploads_refill_per_minute as f64)
            .min(self.cfg.uploads_burst as f64);
        s.last_refill = now;

        // Refill byte budget.
        let elapsed_hr = now.duration_since(s.bytes_last_refill).as_secs_f64() / 3600.0;
        s.bytes_remaining = (s.bytes_remaining + elapsed_hr * self.cfg.bytes_per_hour as f64)
            .min(self.cfg.bytes_per_hour as f64);
        s.bytes_last_refill = now;

        if s.tokens < 1.0 {
            return RateDecision::TooManyRequests;
        }
        if (bytes as f64) > s.bytes_remaining {
            return RateDecision::QuotaExceeded;
        }

        s.tokens -= 1.0;
        s.bytes_remaining -= bytes as f64;
        RateDecision::Ok
    }

    /// Drop entries that have been idle long enough to have fully refilled,
    /// to keep the map from growing unbounded.
    pub fn gc(&self) {
        let now = Instant::now();
        let mut map = self.state.lock().unwrap();
        map.retain(|_, s| now.duration_since(s.last_refill) < Duration::from_secs(2 * 3600));
    }
}
