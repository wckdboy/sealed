//! Signup, login, 18+ gate, /me.
//!
//! Enumeration resistance: an unknown account number gets a deterministic fake
//! salt (HMAC of the pepper, so it is stable across probes) instead of a 404,
//! and login always returns the same error body. An attacker cannot tell a real
//! account number from a fake one without guessing the passphrase too.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use sqlx::Row;
use vault_core::account::AccountNumber;
use vault_core::auth;
use vault_core::keys::Key;
use vault_core::wire::{
    AccountCreateRequest, AccountCreateResponse, AuthPrepareRequest, AuthPrepareResponse,
    AuthRequest, AuthResponse, GateRequest, GateResponse, MeResponse, Tier,
};

use crate::error::{ApiError, ApiResult};
use crate::routes::{account_row, Session};
use crate::state::{now, AppState};

/// Lockout after this many consecutive failures.
const MAX_AUTH_FAILURES: i64 = 5;
const LOCK_SECONDS: i64 = 15 * 60;

pub async fn create(
    State(st): State<AppState>,
    Json(req): Json<AccountCreateRequest>,
) -> ApiResult<(StatusCode, Json<AccountCreateResponse>)> {
    req.validate().map_err(ApiError::BadRequest)?;

    let number = AccountNumber::generate();
    let digits = number.digits();
    let auth_secret =
        Key::from_hex(&req.auth_secret).map_err(|_| ApiError::BadRequest("bad auth_secret"))?;
    let verifier = auth::verifier(&st.cfg.pepper, &auth_secret, &digits)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let tier = Tier::parse(&st.cfg.default_tier).unwrap_or(Tier::Basic);
    let ts = now();

    sqlx::query(
        "INSERT INTO accounts
           (account_number, kdf_salt, kdf_version, auth_verifier, recovery_blob, tier,
            storage_quota, created_at, tos_accepted_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&digits)
    .bind(&req.kdf_salt)
    .bind(req.kdf_version.unwrap_or(1) as i64)
    .bind(&verifier)
    .bind(&req.recovery_blob)
    .bind(tier.as_str())
    .bind(tier.quota_bytes() as i64)
    .bind(ts)
    .bind(ts)
    .execute(&st.db)
    .await?;

    tracing::info!(fingerprint = %number.fingerprint(), tier = tier.as_str(), "account created");
    Ok((
        StatusCode::CREATED,
        Json(AccountCreateResponse {
            account_number: number.formatted(),
            digits,
            fingerprint: number.fingerprint(),
            recovery_acknowledged: false,
        }),
    ))
}

pub async fn prepare(
    State(st): State<AppState>,
    Json(req): Json<AuthPrepareRequest>,
) -> ApiResult<Json<AuthPrepareResponse>> {
    let number = AccountNumber::parse(&req.account_number)
        .map_err(|_| ApiError::BadRequest("bad account number"))?;
    let digits = number.digits();

    let row = sqlx::query("SELECT kdf_salt, kdf_ops, kdf_mem_bytes, kdf_version FROM accounts WHERE account_number = ?")
        .bind(&digits)
        .fetch_optional(&st.db)
        .await?;

    match row {
        Some(row) => Ok(Json(AuthPrepareResponse {
            kdf_salt: row.get("kdf_salt"),
            kdf_ops: row.get::<i64, _>("kdf_ops") as u64,
            kdf_mem_bytes: row.get::<i64, _>("kdf_mem_bytes") as u64,
            kdf_version: row.get::<i64, _>("kdf_version") as u8,
        })),
        None => {
            // Same shape, stable value, no information.
            let fake = auth::verifier(
                &st.cfg.pepper,
                &Key::from_bytes([0u8; 32]),
                &format!("probe{digits}"),
            )
            .map_err(|e| ApiError::Internal(e.to_string()))?;
            Ok(Json(AuthPrepareResponse {
                kdf_salt: fake[..32].to_string(),
                kdf_ops: 3,
                kdf_mem_bytes: 64 * 1024 * 1024,
                kdf_version: 1,
            }))
        }
    }
}

pub async fn login(
    State(st): State<AppState>,
    Json(req): Json<AuthRequest>,
) -> ApiResult<Json<AuthResponse>> {
    req.validate().map_err(ApiError::BadRequest)?;
    let number = AccountNumber::parse(&req.account_number).map_err(|_| {
        // Also a credential error, not a validation error: no free oracle.
        ApiError::InvalidCredentials
    })?;
    let digits = number.digits();

    let row = sqlx::query(
        "SELECT id, auth_verifier, tier, storage_used, storage_quota, gate_at, ban_flag, auth_failures, locked_until
         FROM accounts WHERE account_number = ?",
    )
    .bind(&digits)
    .fetch_optional(&st.db)
    .await?;

    let Some(row) = row else {
        return Err(ApiError::InvalidCredentials);
    };

    let ts = now();
    if let Some(until) = row.get::<Option<i64>, _>("locked_until") {
        if until > ts {
            return Err(ApiError::Locked(until - ts));
        }
    }

    let secret = Key::from_hex(&req.auth_secret).map_err(|_| ApiError::InvalidCredentials)?;
    let stored: String = row.get("auth_verifier");
    let ok = auth::verify(&st.cfg.pepper, &secret, &digits, &stored).unwrap_or(false);

    if !ok {
        let failures: i64 = row.get::<i64, _>("auth_failures") + 1;
        let lock = if failures >= MAX_AUTH_FAILURES {
            Some(ts + LOCK_SECONDS)
        } else {
            None
        };
        sqlx::query("UPDATE accounts SET auth_failures = ?, locked_until = ? WHERE id = ?")
            .bind(failures)
            .bind(lock)
            .bind(row.get::<i64, _>("id"))
            .execute(&st.db)
            .await?;
        tracing::warn!(fingerprint = %number.fingerprint(), failures, "failed login");
        return Err(ApiError::InvalidCredentials);
    }

    let account_id: i64 = row.get("id");
    let token = auth::new_session_token();
    sqlx::query("INSERT INTO sessions (token_hash, account_id, created_at, expires_at, gate_at) VALUES (?, ?, ?, ?, ?)")
        .bind(auth::token_hash(&token))
        .bind(account_id)
        .bind(ts)
        .bind(ts + st.cfg.session_ttl_seconds)
        .bind(row.get::<Option<i64>, _>("gate_at"))
        .execute(&st.db)
        .await?;
    sqlx::query("UPDATE accounts SET auth_failures = 0, locked_until = NULL WHERE id = ?")
        .bind(account_id)
        .execute(&st.db)
        .await?;

    // Drop expired sessions opportunistically; keeps the table small without a
    // background job.
    sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
        .bind(ts)
        .execute(&st.db)
        .await?;

    let tier = Tier::parse(row.get::<String, _>("tier").as_str()).unwrap_or(Tier::Basic);
    Ok(Json(AuthResponse {
        token,
        expires_at: ts + st.cfg.session_ttl_seconds,
        tier,
        storage_used: row.get::<i64, _>("storage_used") as u64,
        storage_quota: row.get::<i64, _>("storage_quota") as u64,
        gate_passed: row.get::<Option<i64>, _>("gate_at").is_some(),
        fingerprint: number.fingerprint(),
    }))
}

/// 18+ / ToS gate. Stores the timestamp on both the session and the account.
/// Releases the portal key: without it nothing public can be decrypted.
pub async fn gate(
    State(st): State<AppState>,
    session: Session,
    Json(req): Json<GateRequest>,
) -> ApiResult<Json<GateResponse>> {
    if !req.confirmed {
        return Err(ApiError::BadRequest("confirmation required"));
    }
    let ts = now();
    sqlx::query("UPDATE sessions SET gate_at = ? WHERE token_hash = ?")
        .bind(ts)
        .bind(&session.token_hash)
        .execute(&st.db)
        .await?;
    sqlx::query("UPDATE accounts SET gate_at = COALESCE(gate_at, ?), age_verified_at = COALESCE(age_verified_at, ?) WHERE id = ?")
        .bind(ts)
        .bind(ts)
        .bind(session.account_id)
        .execute(&st.db)
        .await?;
    Ok(Json(GateResponse {
        gate_passed: true,
        gate_at: ts,
        portal_key: Some(st.portal_key_hex.to_string()),
    }))
}

pub async fn me(State(st): State<AppState>, session: Session) -> ApiResult<Json<MeResponse>> {
    let row = account_row(&st, session.account_id).await?;
    Ok(Json(MeResponse {
        fingerprint: AccountNumber::parse(&row.account_number)
            .map(|a| a.fingerprint())
            .unwrap_or_default(),
        account_number: AccountNumber::parse(&row.account_number)
            .map(|a| a.formatted())
            .unwrap_or_default(),
        tier: Tier::parse(&row.tier).unwrap_or(Tier::Basic),
        storage_used: row.storage_used as u64,
        storage_quota: row.storage_quota as u64,
        gate_passed: row.gate_at.is_some(),
        created_at: row.created_at,
        strikes: row.strikes as u32,
        ban_flag: row.ban_flag != 0,
    }))
}
