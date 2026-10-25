//! Router and request extractors.

pub mod accounts;
pub mod files;
pub mod misc;

use axum::extract::{FromRequestParts, State};
use axum::http::{header, request::Parts, HeaderValue, Method};
use axum::routing::{get, post, put};
use axum::Router;
use sqlx::Row;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use vault_core::auth;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// An authenticated session. Extract it as a handler argument and the request is
/// guaranteed to carry a live bearer token.
pub struct Session {
    pub account_id: i64,
    pub gate_at: Option<i64>,
    pub token_hash: String,
}

impl FromRequestParts<AppState> for Session {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let raw = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(ApiError::Unauthorized)?;
        let token_hash = auth::token_hash(raw.trim());
        let row = sqlx::query(
            "SELECT account_id, gate_at, expires_at FROM sessions WHERE token_hash = ?",
        )
        .bind(&token_hash)
        .fetch_optional(&state.db)
        .await?
        .ok_or(ApiError::Unauthorized)?;

        let expires_at: i64 = row.get("expires_at");
        if expires_at <= crate::state::now() {
            return Err(ApiError::Unauthorized);
        }
        Ok(Session {
            account_id: row.get("account_id"),
            gate_at: row.get("gate_at"),
            token_hash,
        })
    }
}

pub fn router(state: AppState) -> Router {
    let cors = if state.cfg.allowed_origins.is_empty() {
        CorsLayer::new()
    } else {
        let origins: Vec<HeaderValue> = state
            .cfg
            .allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
    };

    let mut router = Router::new()
        .route("/healthz", get(misc::healthz))
        .route("/dmca", get(misc::dmca))
        .route("/v1/accounts", post(accounts::create))
        .route("/v1/auth/prepare", post(accounts::prepare))
        .route("/v1/auth", post(accounts::login))
        .route("/v1/gate", post(accounts::gate))
        .route("/v1/me", get(accounts::me))
        .route("/v1/files", post(files::init).get(files::list))
        .route("/v1/files/{id}/blob", put(files::upload))
        .route("/v1/files/{id}/complete", post(files::complete))
        .route("/v1/files/{id}/keys", get(files::keys))
        .route("/v1/files/{id}/url", get(files::owner_url))
        .route("/v1/p/{id}", get(files::public_manifest))
        .route("/v1/blobs/{blob_ref}", get(files::blob))
        .route("/v1/reports", post(misc::report))
        .route("/v1/account/recovery-ack", post(misc::ack_recovery))
        // Public brand document: baked defaults + anything the operator saved, so a
        // rename is a saved setting rather than a rebuild.
        .route("/v1/brand", get(public_brand))
        // Operator surface. 404 unless VAULT_ADMIN_TOKEN is set.
        .route("/v1/admin/stats", get(crate::admin::stats))
        .route("/v1/admin/accounts", get(crate::admin::accounts))
        .route(
            "/v1/admin/accounts/{id}",
            axum::routing::patch(crate::admin::patch_account),
        )
        .route("/v1/admin/files", get(crate::admin::files))
        .route(
            "/v1/admin/files/{id}/quarantine",
            post(crate::admin::quarantine),
        )
        .route("/v1/admin/reports", get(crate::admin::reports))
        .route(
            "/v1/admin/reports/{id}/resolve",
            post(crate::admin::resolve_report),
        )
        .route(
            "/v1/admin/brand",
            get(crate::admin::get_brand).patch(crate::admin::patch_brand),
        )
        // Catch-all for the API namespace so an unknown endpoint stays a JSON
        // 404 instead of falling through to the SPA shell below.
        .route("/v1/{*rest}", axum::routing::any(misc::api_not_found))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        // Runs after routing so it can see the path; exempt for non-/v1 traffic.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::ratelimit::limit,
        ));

    // One container in production: the API serves the built PWA on the same
    // origin. Unknown paths fall back to index.html so the SPA can route, but API
    // prefixes never fall through (a missing endpoint must stay a JSON 404).
    if let Some(dir) = state.cfg.web_dir.clone() {
        let index = dir.join("index.html");

        // Cache headers are not decoration: a CDN in front of this origin needs to
        // know which bytes may live at the edge for a year and which must be
        // revalidated on every deploy. Vite emits content-hashed filenames under
        // /assets, so those are immutable; index.html names the current bundle and
        // must never be cached, or a deploy leaves the edge serving the old shell
        // until the CDN TTL expires.
        let assets = Router::new()
            .fallback_service(ServeDir::new(dir.join("assets")))
            .layer(SetResponseHeaderLayer::overriding(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            ));
        router = router.nest_service("/assets", assets);

        let spa = Router::new()
            .fallback_service(ServeDir::new(&dir).fallback(ServeFile::new(index)))
            .layer(SetResponseHeaderLayer::overriding(
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-cache"),
            ));
        router = router.fallback_service(spa);
    }

    router.with_state(state)
}

/// `GET /v1/brand` — the brand the instance actually renders right now.
async fn public_brand(
    State(st): State<AppState>,
) -> crate::error::ApiResult<axum::Json<serde_json::Value>> {
    Ok(axum::Json(crate::admin::brand(&st).await?))
}

/// Owner-or-404 lookup helper shared by the file handlers.
pub(crate) async fn account_row(state: &AppState, account_id: i64) -> ApiResult<AccountRow> {
    let row = sqlx::query(
        "SELECT id, account_number, tier, storage_used, storage_quota, gate_at, strikes, ban_flag, created_at
         FROM accounts WHERE id = ?",
    )
    .bind(account_id)
    .fetch_one(&state.db)
    .await?;
    Ok(AccountRow {
        id: row.get("id"),
        account_number: row.get("account_number"),
        tier: row.get("tier"),
        storage_used: row.get("storage_used"),
        storage_quota: row.get("storage_quota"),
        gate_at: row.get("gate_at"),
        strikes: row.get("strikes"),
        ban_flag: row.get("ban_flag"),
        created_at: row.get("created_at"),
    })
}

pub(crate) struct AccountRow {
    pub id: i64,
    pub account_number: String,
    pub tier: String,
    pub storage_used: i64,
    pub storage_quota: i64,
    pub gate_at: Option<i64>,
    pub strikes: i64,
    pub ban_flag: i64,
    pub created_at: i64,
}
