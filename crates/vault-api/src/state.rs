//! Shared application state.

use std::sync::Arc;

use sqlx::SqlitePool;
use vault_core::screen::Screening;
use vault_core::sign::Signer;

use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub db: SqlitePool,
    pub signer: Signer,
    pub screening: Arc<Screening>,
    /// PKEK. Read from config at boot; released only to gated sessions.
    pub portal_key_hex: Arc<String>,
    pub rate_limiter: Arc<crate::ratelimit::RateLimiter>,
}

impl AppState {
    pub fn now(&self) -> i64 {
        now()
    }
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
