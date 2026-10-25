//! HTTP error mapping.
//!
//! Rules:
//!   * Never leak whether a screening hit occurred (upload gets a generic 403).
//!   * Never distinguish "no such account" from "wrong passphrase" on login.
//!   * Internal errors are logged in full, reported as a bare 500.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use vault_core::wire::ErrorBody;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("locked out for {0} seconds")]
    Locked(i64),
    #[error("{0}")]
    Forbidden(&'static str),
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    BadRequest(&'static str),
    #[error("quota exceeded")]
    Quota,
    #[error("conflict: {0}")]
    Conflict(&'static str),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("too many requests")]
    RateLimited,
}

impl ApiError {
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            ApiError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "session required".into(),
            ),
            // Same status, same body for every credential failure.
            ApiError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "account number or passphrase is wrong".into(),
            ),
            ApiError::Locked(secs) => (
                StatusCode::TOO_MANY_REQUESTS,
                "locked",
                format!("too many attempts; try again in {secs}s"),
            ),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, "forbidden", (*m).to_string()),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not_found", "not found".into()),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, "bad_request", (*m).to_string()),
            ApiError::Quota => (
                StatusCode::INSUFFICIENT_STORAGE,
                "quota_exceeded",
                "storage quota exhausted; upgrade or delete files".into(),
            ),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, "conflict", (*m).to_string()),
            ApiError::Internal(d) => {
                tracing::error!(detail = %d, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "internal error".into(),
                )
            }
            ApiError::Storage(d) => {
                tracing::error!(detail = %d, "storage error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "storage",
                    "storage error".into(),
                )
            }
            ApiError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "slow down".into(),
            ),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error, message) = self.parts();
        (
            status,
            Json(ErrorBody {
                error: error.into(),
                message,
            }),
        )
            .into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::RowNotFound => ApiError::NotFound,
            other => ApiError::Internal(other.to_string()),
        }
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::NotFound => ApiError::NotFound,
            _ => ApiError::Storage(e.to_string()),
        }
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
