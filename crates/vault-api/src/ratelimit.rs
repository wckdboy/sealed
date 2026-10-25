//! Per-client-IP rate limiting.
//!
//! The product has no email, no captcha and no signup friction, so the cheap
//! abuse paths are exactly the ones an attacker finds first: create accounts in a
//! loop, spray account numbers at `/v1/auth`, or hammer upload init. The
//! per-account lockout in `routes::accounts` does not help there (each attempt
//! uses a fresh account number), so this layer is the one that holds.
//!
//! Design choices:
//!   * In-process sliding window. One node, one process — a shared store would be
//!     a second dependency for no benefit at this scale. If the API is ever run
//!     as more than one replica, move this to the edge (the CDN's rate rules) and
//!     say so, rather than pretending a per-process counter is global.
//!   * Keyed on the client IP. Behind Coolify/Traefik/Bunny the socket address is
//!     the proxy, so `VAULT_TRUST_PROXY=1` makes us read the *first* hop of
//!     `X-Forwarded-For` — and only then, because a client can forge it.
//!   * Static assets and `/healthz` are exempt: they carry no abuse value and
//!     counting them would throttle ordinary page loads on a slow connection.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Mutex;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use vault_core::wire::ErrorBody;

use crate::state::{now, AppState};

/// Abuse classes. Each gets its own budget so a burst of uploads cannot lock the
/// user out of logging in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// `POST /v1/accounts` — the spam-account path.
    Signup,
    /// `/v1/auth/prepare`, `/v1/auth` — the guessing path.
    Auth,
    /// `POST /v1/files` — quota evasion / upload flooding.
    Upload,
    /// `/v1/reports` — report spam against other users.
    Report,
    /// Everything else under `/v1`, coarse DoS guard.
    General,
}

impl Class {
    /// `(limit, window_seconds)`. Chosen against the real UX, not rounded to
    /// pretty numbers: a human never signs up 3 times in 10 minutes, but a
    /// household behind one NAT does create a couple of accounts.
    fn policy(self) -> (usize, i64) {
        match self {
            Class::Signup => (3, 600),
            Class::Auth => (30, 60),
            Class::Upload => (120, 60),
            Class::Report => (20, 60),
            Class::General => (600, 60),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Class::Signup => "signup",
            Class::Auth => "auth",
            Class::Upload => "upload",
            Class::Report => "report",
            Class::General => "general",
        }
    }
}

pub struct RateLimiter {
    hits: Mutex<HashMap<(String, Class), VecDeque<i64>>>,
    enabled: bool,
}

impl RateLimiter {
    pub fn new(enabled: bool) -> Self {
        Self {
            hits: Mutex::new(HashMap::new()),
            enabled,
        }
    }

    /// Record a hit and return `Err(retry_after_seconds)` when over budget.
    pub fn check(&self, key: &str, class: Class) -> Result<(), i64> {
        if !self.enabled {
            return Ok(());
        }
        let (limit, window) = class.policy();
        let ts = now();
        let mut map = self.hits.lock().expect("rate limiter mutex poisoned");

        // Keep the map from growing without bound on a long-lived process.
        if map.len() > 20_000 {
            map.retain(|_, q| q.back().map(|last| ts - *last < window).unwrap_or(false));
        }

        let bucket = map.entry((key.to_string(), class)).or_default();
        while bucket.front().map(|t| ts - *t >= window).unwrap_or(false) {
            bucket.pop_front();
        }
        if bucket.len() >= limit {
            let oldest = *bucket.front().unwrap_or(&ts);
            return Err((window - (ts - oldest)).max(1));
        }
        bucket.push_back(ts);
        Ok(())
    }
}

/// Which class a request belongs to, or `None` when it is exempt.
pub fn classify(method: &Method, path: &str) -> Option<Class> {
    if !path.starts_with("/v1/") {
        return None; // static client, /healthz, /dmca
    }
    Some(match (method, path) {
        (&Method::POST, "/v1/accounts") => Class::Signup,
        (&Method::POST, "/v1/auth") | (&Method::POST, "/v1/auth/prepare") => Class::Auth,
        (&Method::POST, "/v1/files") => Class::Upload,
        (&Method::POST, "/v1/reports") => Class::Report,
        _ => Class::General,
    })
}

/// First hop of `X-Forwarded-For`, or the socket address, or "unknown".
pub fn client_key(trust_forwarded: bool, headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    if trust_forwarded {
        if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = v.split(',').next() {
                let first = first.trim();
                if !first.is_empty() {
                    return first.to_string();
                }
            }
        }
    }
    match peer {
        Some(addr) => addr.ip().to_string(),
        // No proxy trust and no peer info (unit tests, unix sockets): one shared
        // bucket. Better to throttle everyone under a misconfiguration than to
        // silently disable the control.
        None => "unknown".to_string(),
    }
}

pub async fn limit(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let class = match classify(req.method(), req.uri().path()) {
        Some(c) => c,
        None => return next.run(req).await,
    };
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let key = client_key(st.cfg.trust_forwarded, req.headers(), peer);

    match st.rate_limiter.check(&key, class) {
        Ok(()) => next.run(req).await,
        Err(retry_after) => {
            tracing::warn!(key = %key, class = class.label(), retry_after, "rate limited");
            let body = Json(ErrorBody {
                error: "rate_limited".into(),
                message: format!(
                    "too many {} requests; retry in {}s",
                    class.label(),
                    retry_after
                ),
            });
            let mut resp = (StatusCode::TOO_MANY_REQUESTS, body).into_response();
            if let Ok(v) = HeaderValue::from_str(&retry_after.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
            resp
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signup_budget_is_enforced_and_scoped_per_ip() {
        let rl = RateLimiter::new(true);
        for _ in 0..3 {
            assert!(rl.check("1.2.3.4", Class::Signup).is_ok());
        }
        let err = rl.check("1.2.3.4", Class::Signup).unwrap_err();
        assert!(err > 0 && err <= 600, "retry_after out of range: {err}");
        // A different client is unaffected.
        assert!(rl.check("5.6.7.8", Class::Signup).is_ok());
        // Classes do not share budgets.
        assert!(rl.check("1.2.3.4", Class::Auth).is_ok());
    }

    #[test]
    fn disabled_limiter_allows_everything() {
        let rl = RateLimiter::new(false);
        for _ in 0..1000 {
            assert!(rl.check("1.2.3.4", Class::Signup).is_ok());
        }
    }

    #[test]
    fn classification() {
        assert_eq!(classify(&Method::POST, "/v1/accounts"), Some(Class::Signup));
        assert_eq!(classify(&Method::POST, "/v1/auth"), Some(Class::Auth));
        assert_eq!(classify(&Method::POST, "/v1/files"), Some(Class::Upload));
        assert_eq!(classify(&Method::GET, "/v1/files"), Some(Class::General));
        assert_eq!(classify(&Method::GET, "/healthz"), None);
        assert_eq!(classify(&Method::GET, "/assets/app.js"), None);
        assert_eq!(classify(&Method::GET, "/"), None);
    }

    #[test]
    fn forwarded_for_only_when_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("9.9.9.9, 10.0.0.1"),
        );
        let peer: SocketAddr = "10.0.0.1:5555".parse().unwrap();
        assert_eq!(client_key(true, &headers, Some(peer)), "9.9.9.9");
        assert_eq!(client_key(false, &headers, Some(peer)), "10.0.0.1");
        assert_eq!(client_key(false, &HeaderMap::new(), None), "unknown");
    }
}
