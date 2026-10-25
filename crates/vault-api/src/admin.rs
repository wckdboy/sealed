//! Operator surface: stats, moderation, and runtime branding.
//!
//! Two rules shape this module:
//!
//! 1. **Off by default.** With no `VAULT_ADMIN_TOKEN` the routes behave as if they do
//!    not exist (404), so an instance that never configures an admin has no admin
//!    surface to scan for.
//! 2. **The operator cannot read user content.** These endpoints expose metadata,
//!    counters and moderation actions — never keys, passphrases, or plaintext. The
//!    whole product is built so that even an admin cannot decrypt a user's files,
//!    and the admin panel does not pretend otherwise.
//!
//! Every mutating action is written to `mod_log` with the actor `admin`, because the
//! only thing worse than a moderation decision is one with no record of who made it.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use vault_core::wire::Tier;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Constant-time comparison, so a wrong token cannot be found byte by byte.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn require_admin(st: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    let Some(expected) = st.cfg.admin_token.as_deref() else {
        return Err(ApiError::NotFound);
    };
    let got = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .trim();
    if !ct_eq(got.as_bytes(), expected.as_bytes()) {
        // Deliberately the same answer as a missing session elsewhere: no hint that
        // an admin surface exists and the token was merely wrong.
        return Err(ApiError::Forbidden("admin token required"));
    }
    Ok(())
}

async fn audit(
    st: &AppState,
    action: &str,
    subject: Option<&str>,
    detail: Option<String>,
) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO mod_log (actor, action, subject, detail, created_at) VALUES ('admin', ?, ?, ?, ?)",
    )
    .bind(action)
    .bind(subject)
    .bind(detail)
    .bind(crate::now())
    .execute(&st.db)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(())
}

// ------------------------------------------------------------------- stats

pub async fn stats(State(st): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    require_admin(&st, &headers)?;

    let accounts: (i64, i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(storage_used), 0), COALESCE(SUM(ban_flag), 0) FROM accounts",
    )
    .fetch_one(&st.db)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    let files: (i64, i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), COALESCE(SUM(plaintext_size), 0), COALESCE(SUM(dead_flag), 0) FROM files",
    )
    .fetch_one(&st.db)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    let open_reports: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reports WHERE state = 'open'")
        .fetch_one(&st.db)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let mut tiers = serde_json::Map::new();
    for row in sqlx::query("SELECT tier, COUNT(*) AS n FROM accounts GROUP BY tier")
        .fetch_all(&st.db)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
    {
        let name: String = row.get("tier");
        tiers.insert(name, json!(row.get::<i64, _>("n")));
    }

    let blob_bytes = crate::routes::misc::dir_size(&st.cfg.blob_dir);
    Ok(Json(json!({
        "accounts": accounts.0,
        "banned": accounts.2,
        "storage_used": accounts.1,
        "files": files.0,
        "plaintext_bytes": files.1,
        "quarantined": files.2,
        "open_reports": open_reports,
        "tiers": tiers,
        "blob_bytes": blob_bytes,
        "screening": st.cfg.screening_mode(),
        "secrets": {
            "pepper": st.cfg.secret_sources[0].as_str(),
            "signing": st.cfg.secret_sources[1].as_str(),
            "portal": st.cfg.secret_sources[2].as_str(),
        },
    })))
}

// ---------------------------------------------------------------- accounts

#[derive(Deserialize)]
pub struct Page {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
    #[serde(default)]
    pub q: Option<String>,
}

pub async fn accounts(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> ApiResult<Json<Value>> {
    require_admin(&st, &headers)?;
    let limit = page.limit.unwrap_or(50).clamp(1, 200);
    let offset = page.offset.unwrap_or(0).max(0);
    let like = page.q.map(|q| format!("%{}%", q.replace('%', "")));

    let rows = sqlx::query(
        "SELECT id, account_number, tier, storage_used, storage_quota, created_at,
                strikes, ban_flag, recovery_ack, (SELECT MAX(created_at) FROM sessions s WHERE s.account_id = accounts.id) AS last_seen
           FROM accounts
          WHERE (?1 IS NULL OR account_number LIKE ?1)
          ORDER BY created_at DESC
          LIMIT ?2 OFFSET ?3",
    )
    .bind(like)
    .bind(limit)
    .bind(offset)
    .fetch_all(&st.db)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    let items: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<i64, _>("id"),
                "account_number": r.get::<String, _>("account_number"),
                "tier": r.get::<String, _>("tier"),
                "storage_used": r.get::<i64, _>("storage_used"),
                "storage_quota": r.get::<i64, _>("storage_quota"),
                "created_at": r.get::<i64, _>("created_at"),
                "strikes": r.get::<i64, _>("strikes"),
                "banned": r.get::<i64, _>("ban_flag") != 0,
                "recovery_ack": r.get::<i64, _>("recovery_ack") != 0,
                "last_seen": r.get::<Option<i64>, _>("last_seen"),
            })
        })
        .collect();

    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts")
        .fetch_one(&st.db)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(
        json!({ "total": total, "limit": limit, "offset": offset, "items": items }),
    ))
}

#[derive(Deserialize)]
pub struct AccountPatch {
    pub tier: Option<String>,
    pub banned: Option<bool>,
    pub strikes: Option<i64>,
    pub storage_quota: Option<i64>,
}

pub async fn patch_account(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(patch): Json<AccountPatch>,
) -> ApiResult<Json<Value>> {
    require_admin(&st, &headers)?;

    let mut changes = Vec::new();
    if let Some(tier) = patch.tier.as_deref() {
        let t = Tier::parse(tier).ok_or(ApiError::BadRequest("unknown tier"))?;
        sqlx::query("UPDATE accounts SET tier = ?, storage_quota = ? WHERE id = ?")
            .bind(t.as_str())
            .bind(t.quota_bytes() as i64)
            .bind(id)
            .execute(&st.db)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        changes.push(format!("tier={}", t.as_str()));
    }
    if let Some(banned) = patch.banned {
        sqlx::query("UPDATE accounts SET ban_flag = ? WHERE id = ?")
            .bind(if banned { 1i64 } else { 0 })
            .bind(id)
            .execute(&st.db)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        if banned {
            // A ban must also kill live sessions, or the user keeps browsing for a month.
            sqlx::query("DELETE FROM sessions WHERE account_id = ?")
                .bind(id)
                .execute(&st.db)
                .await
                .map_err(|e| ApiError::Internal(e.to_string()))?;
        }
        changes.push(format!("banned={banned}"));
    }
    if let Some(strikes) = patch.strikes {
        sqlx::query("UPDATE accounts SET strikes = ? WHERE id = ?")
            .bind(strikes.clamp(0, 99))
            .bind(id)
            .execute(&st.db)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        changes.push(format!("strikes={strikes}"));
    }
    if let Some(quota) = patch.storage_quota {
        sqlx::query("UPDATE accounts SET storage_quota = ? WHERE id = ?")
            .bind(quota.max(0))
            .bind(id)
            .execute(&st.db)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        changes.push(format!("storage_quota={quota}"));
    }

    if changes.is_empty() {
        return Err(ApiError::BadRequest("nothing to change"));
    }
    audit(
        &st,
        "account.patch",
        Some(&id.to_string()),
        Some(changes.join(" ")),
    )
    .await?;
    Ok(Json(json!({ "id": id, "applied": changes })))
}

// ------------------------------------------------------------------- files

pub async fn files(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> ApiResult<Json<Value>> {
    require_admin(&st, &headers)?;
    let limit = page.limit.unwrap_or(50).clamp(1, 200);
    let offset = page.offset.unwrap_or(0).max(0);

    let rows = sqlx::query(
        "SELECT f.id, f.blob_ref, f.plaintext_size, f.ciphertext_size, f.mime, f.visibility,
                f.status, f.dead_flag, f.created_at, f.view_count, a.account_number
           FROM files f JOIN accounts a ON a.id = f.owner_id
          ORDER BY f.created_at DESC LIMIT ?1 OFFSET ?2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&st.db)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    let items: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<String, _>("id"),
                "blob_ref": r.get::<String, _>("blob_ref"),
                "owner": r.get::<String, _>("account_number"),
                "plaintext_size": r.get::<i64, _>("plaintext_size"),
                "ciphertext_size": r.get::<Option<i64>, _>("ciphertext_size"),
                "mime": r.get::<String, _>("mime"),
                "visibility": r.get::<String, _>("visibility"),
                "status": r.get::<String, _>("status"),
                "quarantined": r.get::<i64, _>("dead_flag") != 0,
                "views": r.get::<i64, _>("view_count"),
                "created_at": r.get::<i64, _>("created_at"),
            })
        })
        .collect();

    Ok(Json(
        json!({ "limit": limit, "offset": offset, "items": items }),
    ))
}

#[derive(Deserialize)]
pub struct QuarantineReq {
    #[serde(default)]
    pub reason: Option<String>,
}

pub async fn quarantine(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
    Json(req): Json<QuarantineReq>,
) -> ApiResult<Json<Value>> {
    require_admin(&st, &headers)?;

    let row = sqlx::query("SELECT blob_ref, owner_id, plaintext_size FROM files WHERE id = ?")
        .bind(&file_id)
        .fetch_optional(&st.db)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or(ApiError::NotFound)?;
    let blob_ref: String = row.get("blob_ref");

    sqlx::query("UPDATE files SET dead_flag = 1, status = 'quarantined' WHERE id = ?")
        .bind(&file_id)
        .execute(&st.db)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    audit(
        &st,
        "file.quarantine",
        Some(&file_id),
        Some(format!(
            "blob={blob_ref} reason={}",
            req.reason.unwrap_or_default()
        )),
    )
    .await?;

    // The CDN holds the object for VAULT_BLOB_CACHE_SECONDS; say so in the response
    // so the operator knows to purge instead of assuming it vanished.
    Ok(Json(json!({
        "id": file_id,
        "blob_ref": blob_ref,
        "purge_path": format!("/v1/blobs/{blob_ref}"),
        "cdn_ttl_seconds": st.cfg.blob_cache_seconds,
    })))
}

// ----------------------------------------------------------------- reports

pub async fn reports(State(st): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    require_admin(&st, &headers)?;
    let rows = sqlx::query(
        "SELECT r.id, r.file_id, r.reason, r.detail, r.created_at, r.state, f.visibility, f.dead_flag,
                a.account_number AS owner
           FROM reports r
           LEFT JOIN files f ON f.id = r.file_id
           LEFT JOIN accounts a ON a.id = f.owner_id
          WHERE r.state = 'open'
          ORDER BY r.created_at DESC LIMIT 200",
    )
    .fetch_all(&st.db)
    .await
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    let items: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<String, _>("id"),
                "file_id": r.get::<String, _>("file_id"),
                "reason": r.get::<String, _>("reason"),
                "detail": r.get::<Option<String>, _>("detail"),
                "state": r.get::<String, _>("state"),
                "owner": r.get::<Option<String>, _>("owner"),
                "visibility": r.get::<Option<String>, _>("visibility"),
                "quarantined": r.get::<Option<i64>, _>("dead_flag").unwrap_or(0) != 0,
                "created_at": r.get::<i64, _>("created_at"),
            })
        })
        .collect();
    Ok(Json(json!({ "items": items })))
}

#[derive(Deserialize)]
pub struct ResolveReq {
    /// `action` is recorded verbatim: dismissed, quarantined, warned, banned.
    pub action: String,
}

pub async fn resolve_report(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<ResolveReq>,
) -> ApiResult<Json<Value>> {
    require_admin(&st, &headers)?;
    let allowed = ["dismissed", "quarantined", "warned", "banned"];
    if !allowed.contains(&req.action.as_str()) {
        return Err(ApiError::BadRequest("unknown action"));
    }
    let n = sqlx::query("UPDATE reports SET state = ? WHERE id = ?")
        .bind(&req.action)
        .bind(&id)
        .execute(&st.db)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound);
    }
    audit(&st, "report.resolve", Some(&id), Some(req.action.clone())).await?;
    Ok(Json(json!({ "id": id, "state": req.action })))
}

// ------------------------------------------------------------------- brand

/// Public brand document: baked defaults, overridden by anything the operator saved.
pub async fn brand(st: &AppState) -> ApiResult<Value> {
    let mut doc = serde_json::to_value(crate::brand::brand())
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let rows = sqlx::query("SELECT key, value FROM settings WHERE key LIKE 'brand.%'")
        .fetch_all(&st.db)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    if let Some(obj) = doc.as_object_mut() {
        for row in rows {
            let key: String = row.get("key");
            let value: String = row.get("value");
            if let Some(field) = key.strip_prefix("brand.") {
                obj.insert(field.to_string(), Value::String(value));
            }
        }
    }
    Ok(doc)
}

#[derive(Deserialize, Serialize, Default)]
pub struct BrandPatch {
    pub name: Option<String>,
    pub tagline: Option<String>,
    pub accent: Option<String>,
    pub logo: Option<String>,
}

/// Validate a brand field. A brand string is rendered into HTML and into the page
/// title, so it is checked as data, not trusted as markup.
fn clean_brand(patch: &BrandPatch) -> Result<Vec<(String, String)>, ApiError> {
    let mut out = Vec::new();
    if let Some(name) = patch.name.as_deref() {
        let name = name.trim();
        if name.is_empty() || name.len() > 32 {
            return Err(ApiError::BadRequest("name must be 1-32 characters"));
        }
        if !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == ' ' || c == '_' || c == '-')
        {
            return Err(ApiError::BadRequest(
                "name may only contain letters, digits, space, _ and -",
            ));
        }
        if name.to_ascii_lowercase().starts_with("vault") || name.contains('/') {
            return Err(ApiError::BadRequest("name must not look like a namespace"));
        }
        out.push(("brand.name".into(), name.to_string()));
    }
    if let Some(tagline) = patch.tagline.as_deref() {
        let tagline = tagline.trim();
        if tagline.len() > 80 {
            return Err(ApiError::BadRequest(
                "tagline must be 80 characters or fewer",
            ));
        }
        if tagline.chars().any(|c| c.is_control()) {
            return Err(ApiError::BadRequest("tagline must be a single line"));
        }
        out.push(("brand.tagline".into(), tagline.to_string()));
    }
    if let Some(accent) = patch.accent.as_deref() {
        let accent = accent.trim();
        let ok = accent.len() == 7
            && accent.starts_with('#')
            && accent[1..].chars().all(|c| c.is_ascii_hexdigit());
        if !ok {
            return Err(ApiError::BadRequest("accent must be #rrggbb"));
        }
        out.push(("brand.accent".into(), accent.to_ascii_lowercase()));
    }
    if let Some(logo) = patch.logo.as_deref() {
        let logo = logo.trim();
        if logo.len() > 64 || !logo.chars().all(|c| !c.is_control()) {
            return Err(ApiError::BadRequest("logo must be 64 characters or fewer"));
        }
        out.push(("brand.logo".into(), logo.to_string()));
    }
    Ok(out)
}

pub async fn get_brand(State(st): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    require_admin(&st, &headers)?;
    Ok(Json(brand(&st).await?))
}

pub async fn patch_brand(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(patch): Json<BrandPatch>,
) -> ApiResult<Json<Value>> {
    require_admin(&st, &headers)?;
    let fields = clean_brand(&patch)?;
    if fields.is_empty() {
        return Err(ApiError::BadRequest("nothing to change"));
    }
    for (key, value) in &fields {
        sqlx::query(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        )
        .bind(key)
        .bind(value)
        .bind(crate::now())
        .execute(&st.db)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    }
    audit(&st, "brand.patch", None, Some(format!("{:?}", fields))).await?;
    Ok(Json(brand(&st).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_comparison_is_exact() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"", b"x"));
    }

    #[test]
    fn brand_input_is_data_not_markup() {
        assert!(clean_brand(&BrandPatch {
            name: Some("Sealed".into()),
            ..Default::default()
        })
        .is_ok());
        assert!(clean_brand(&BrandPatch {
            name: Some("<script>x</script>".into()),
            ..Default::default()
        })
        .is_err());
        assert!(clean_brand(&BrandPatch {
            name: Some("vault".into()),
            ..Default::default()
        })
        .is_err());
        assert!(clean_brand(&BrandPatch {
            accent: Some("red".into()),
            ..Default::default()
        })
        .is_err());
        assert!(clean_brand(&BrandPatch {
            accent: Some("#ff4d6d".into()),
            ..Default::default()
        })
        .is_ok());
        assert!(clean_brand(&BrandPatch {
            tagline: Some("line\nbreak".into()),
            ..Default::default()
        })
        .is_err());
        assert!(clean_brand(&BrandPatch {
            name: Some("A".repeat(33)),
            ..Default::default()
        })
        .is_err());
    }
}
