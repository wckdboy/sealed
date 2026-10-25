//! File lifecycle: init -> signed upload -> complete, plus owner listing and
//! the public streaming path.
//!
//! What the server enforces (and can enforce, given it never sees plaintext):
//!   * the declared plaintext size matches the framed ciphertext exactly
//!     (`stream::ciphertext_len_for`), so nobody smuggles extra bytes;
//!   * the wrap matrix in `FileInitRequest::validate` (no private file may
//!     carry a portal wrap, no public file may lack one);
//!   * quota, tier, ban state, and the 18+ gate for public uploads;
//!   * hash screening on the client-supplied plaintext digest.
//!
//! What it cannot enforce: that the client told the truth about the digest. That
//! is the price of zero knowledge, and it is why uploads cost money.

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::StreamExt;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;
use vault_core::ids;
use vault_core::screen::Verdict;
use vault_core::stream;
use vault_core::wire::{
    Ack, FileInitRequest, FileInitResponse, FileListResponse, FileStatus, FileSummary, KeyResponse,
    PublicManifest, SignedUpload, Tier, Visibility, WrapType, WrappedKey,
};

use crate::error::{ApiError, ApiResult};
use crate::routes::{account_row, Session};
use crate::state::{now, AppState};

/// How long an upload URL is valid. Long enough for a slow mobile uplink to
/// finish one blob, short enough that a leaked URL is worthless tomorrow.
const UPLOAD_TTL: u64 = 60 * 60;
const DOWNLOAD_TTL: u64 = 2 * 60 * 60;

fn status_from_str(s: &str) -> FileStatus {
    match s {
        "pending" => FileStatus::Pending,
        "ready" => FileStatus::Ready,
        "quarantined" => FileStatus::Quarantined,
        _ => FileStatus::Dead,
    }
}

fn visibility_from_str(s: &str) -> Visibility {
    match s {
        "public" => Visibility::Public,
        "passphrase" => Visibility::Passphrase,
        _ => Visibility::Private,
    }
}

pub async fn init(
    State(st): State<AppState>,
    session: Session,
    Json(req): Json<FileInitRequest>,
) -> ApiResult<(StatusCode, Json<FileInitResponse>)> {
    req.validate().map_err(ApiError::BadRequest)?;
    let acct = account_row(&st, session.account_id).await?;
    if acct.ban_flag != 0 {
        return Err(ApiError::Forbidden("this account is restricted"));
    }
    let tier = Tier::parse(&acct.tier).unwrap_or(Tier::Basic);
    if !tier.can_upload() {
        return Err(ApiError::Forbidden("uploading requires a paid tier"));
    }
    if req.size > st.cfg.max_upload_bytes {
        return Err(ApiError::BadRequest("file exceeds the server upload limit"));
    }
    if matches!(req.visibility, Visibility::Public)
        && acct.gate_at.is_none()
        && session.gate_at.is_none()
    {
        return Err(ApiError::Forbidden(
            "public uploads require 18+ confirmation",
        ));
    }
    if acct.storage_used as u64 + req.size > acct.storage_quota as u64 {
        return Err(ApiError::Quota);
    }

    match st.screening.screen(&req.plaintext_digest, req.size) {
        Verdict::Allow => {}
        Verdict::KnownBad { list } => {
            // Freeze now, report from the runbook, keep the evidence (nothing is
            // stored yet, so the evidence is this attempt).
            sqlx::query("UPDATE accounts SET ban_flag = 1, strikes = strikes + 1 WHERE id = ?")
                .bind(acct.id)
                .execute(&st.db)
                .await?;
            sqlx::query(
                "INSERT INTO mod_log (actor, action, subject, evidence_ref, detail, created_at)
                 VALUES ('system', 'quarantine_on_hash_match', ?, ?, ?, ?)",
            )
            .bind(&req.plaintext_digest)
            .bind(&list)
            .bind(format!("account {} upload blocked", acct.id))
            .bind(now())
            .execute(&st.db)
            .await?;
            tracing::warn!(list = %list, account_id = acct.id, "blocked upload on hash match");
            // Deliberately indistinguishable from any other refusal.
            return Err(ApiError::Forbidden("upload rejected"));
        }
        Verdict::Reject { reason } => return Err(ApiError::BadRequest(reason)),
    }

    let file_id = ids::new_file_id();
    let blob_ref = ids::new_blob_ref();
    let ts = now();

    let mut tx = st.db.begin().await?;
    sqlx::query(
        "INSERT INTO files
           (id, owner_id, blob_ref, plaintext_digest, plaintext_size, mime, duration_ms,
            visibility, status, thumb_ref, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, ?)",
    )
    .bind(&file_id)
    .bind(acct.id)
    .bind(&blob_ref)
    .bind(&req.plaintext_digest)
    .bind(req.size as i64)
    .bind(&req.mime)
    .bind(req.duration_ms.map(|d| d as i64))
    .bind(match req.visibility {
        Visibility::Private => "private",
        Visibility::Public => "public",
        Visibility::Passphrase => "passphrase",
    })
    .bind(ts)
    .execute(&mut *tx)
    .await?;

    for key in &req.keys {
        sqlx::query("INSERT INTO file_keys (file_id, wrap_type, wrapped_key) VALUES (?, ?, ?)")
            .bind(&file_id)
            .bind(match key.wrap_type {
                WrapType::User => "user",
                WrapType::Portal => "portal",
                WrapType::Passphrase => "passphrase",
            })
            .bind(&key.blob)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;

    let resource = upload_resource(&file_id);
    let signed = st
        .signer
        .sign_resource("PUT", &resource, now() as u64 + UPLOAD_TTL)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    tracing::info!(file_id = %file_id, bytes = req.size, "upload initialised");
    Ok((
        StatusCode::CREATED,
        Json(FileInitResponse {
            file_id,
            blob_ref,
            status: FileStatus::Pending,
            upload: SignedUpload {
                path: format!(
                    "{}?exp={}&sig={}",
                    signed.resource, signed.expires_at, signed.token
                ),
                expires_at: signed.expires_at as i64,
                token: signed.token,
            },
        }),
    ))
}

fn upload_resource(file_id: &str) -> String {
    format!("/v1/files/{file_id}/blob")
}

fn blob_resource(blob_ref: &str) -> String {
    format!("/v1/blobs/{blob_ref}")
}

#[derive(Debug, Deserialize)]
pub struct SignedQuery {
    pub exp: Option<u64>,
    pub sig: Option<String>,
}

/// PUT the ciphertext. Authenticated by signature, not by session: the client
/// may hand the URL to an uploader thread/worker that has no session.
pub async fn upload(
    State(st): State<AppState>,
    Path(file_id): Path<String>,
    Query(q): Query<SignedQuery>,
    body: Body,
) -> ApiResult<Json<Ack>> {
    let exp = q.exp.ok_or(ApiError::Forbidden("bad upload signature"))?;
    let sig = q.sig.ok_or(ApiError::Forbidden("bad upload signature"))?;
    st.signer
        .verify_resource("PUT", &upload_resource(&file_id), exp, &sig, now() as u64)
        .map_err(|_| ApiError::Forbidden("bad upload signature"))?;

    let row = sqlx::query("SELECT blob_ref, plaintext_size, status FROM files WHERE id = ?")
        .bind(&file_id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    let status: String = row.get("status");
    if status != "pending" {
        return Err(ApiError::Conflict("file is not awaiting upload"));
    }
    let blob_ref: String = row.get("blob_ref");
    let declared: u64 = row.get::<i64, _>("plaintext_size") as u64;
    let expected = stream::ciphertext_len_for(declared);

    let tmp_path = st.cfg.blob_dir.join(format!(".{blob_ref}.part"));
    let final_path = st.cfg.blob_dir.join(&blob_ref);
    let mut file = tokio::fs::File::create(&tmp_path).await?;
    let mut hasher = Sha256::new();
    let mut written: u64 = 0;
    let mut stream = body.into_data_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(_) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(ApiError::BadRequest("upload stream failed"));
            }
        };
        written += chunk.len() as u64;
        if written > expected {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(ApiError::BadRequest("body larger than the declared size"));
        }
        hasher.update(&chunk);
        if let Err(e) = file.write_all(&chunk).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(ApiError::Storage(e.to_string()));
        }
    }
    file.flush().await?;
    drop(file);

    if written != expected {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(ApiError::BadRequest(
            "body does not match the declared size",
        ));
    }

    tokio::fs::rename(&tmp_path, &final_path).await?;
    let digest = hex::encode(hasher.finalize());
    sqlx::query("UPDATE files SET ciphertext_sha256 = ?, ciphertext_size = ? WHERE id = ?")
        .bind(&digest)
        .bind(written as i64)
        .bind(&file_id)
        .execute(&st.db)
        .await?;

    tracing::info!(file_id = %file_id, bytes = written, "ciphertext stored");
    Ok(Json(Ack { ok: true }))
}

pub async fn complete(
    State(st): State<AppState>,
    session: Session,
    Path(file_id): Path<String>,
) -> ApiResult<Json<Ack>> {
    let row = sqlx::query(
        "SELECT owner_id, plaintext_size, status, ciphertext_sha256 FROM files WHERE id = ?",
    )
    .bind(&file_id)
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    if row.get::<i64, _>("owner_id") != session.account_id {
        return Err(ApiError::NotFound);
    }
    let status: String = row.get("status");
    if status != "pending" {
        return Err(ApiError::Conflict("file is not awaiting completion"));
    }
    if row.get::<Option<String>, _>("ciphertext_sha256").is_none() {
        return Err(ApiError::Conflict("ciphertext has not been uploaded"));
    }
    let size: i64 = row.get("plaintext_size");

    let acct = account_row(&st, session.account_id).await?;
    if acct.storage_used + size > acct.storage_quota {
        return Err(ApiError::Quota);
    }

    let mut tx = st.db.begin().await?;
    sqlx::query("UPDATE files SET status = 'ready' WHERE id = ?")
        .bind(&file_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE accounts SET storage_used = storage_used + ? WHERE id = ?")
        .bind(size)
        .bind(session.account_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(Json(Ack { ok: true }))
}

pub async fn list(
    State(st): State<AppState>,
    session: Session,
) -> ApiResult<Json<FileListResponse>> {
    let rows = sqlx::query(
        "SELECT id, mime, plaintext_size, duration_ms, visibility, status, created_at, view_count, thumb_ref
         FROM files WHERE owner_id = ? ORDER BY created_at DESC LIMIT 500",
    )
    .bind(session.account_id)
    .fetch_all(&st.db)
    .await?;

    let files = rows
        .into_iter()
        .map(|row| FileSummary {
            file_id: row.get("id"),
            mime: row.get("mime"),
            size: row.get::<i64, _>("plaintext_size") as u64,
            duration_ms: row.get::<Option<i64>, _>("duration_ms").map(|d| d as u64),
            visibility: visibility_from_str(&row.get::<String, _>("visibility")),
            status: status_from_str(&row.get::<String, _>("status")),
            created_at: row.get("created_at"),
            view_count: row.get::<i64, _>("view_count") as u64,
            thumb_ref: row.get("thumb_ref"),
        })
        .collect();
    Ok(Json(FileListResponse { files }))
}

pub async fn keys(
    State(st): State<AppState>,
    session: Session,
    Path(file_id): Path<String>,
) -> ApiResult<Json<KeyResponse>> {
    let owner = sqlx::query("SELECT owner_id FROM files WHERE id = ?")
        .bind(&file_id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    if owner.get::<i64, _>("owner_id") != session.account_id {
        return Err(ApiError::NotFound);
    }
    let rows = sqlx::query("SELECT wrap_type, wrapped_key FROM file_keys WHERE file_id = ?")
        .bind(&file_id)
        .fetch_all(&st.db)
        .await?;
    let keys = rows
        .into_iter()
        .map(|row| WrappedKey {
            wrap_type: match row.get::<String, _>("wrap_type").as_str() {
                "portal" => WrapType::Portal,
                "passphrase" => WrapType::Passphrase,
                _ => WrapType::User,
            },
            blob: row.get("wrapped_key"),
        })
        .collect();
    Ok(Json(KeyResponse { file_id, keys }))
}

/// Public stream manifest. Requires a gated session: the portal key is the only
/// thing standing between the whole internet and every public file.
pub async fn public_manifest(
    State(st): State<AppState>,
    session: Session,
    Path(file_id): Path<String>,
) -> ApiResult<Json<PublicManifest>> {
    let gated = session.gate_at.is_some()
        || account_row(&st, session.account_id)
            .await?
            .gate_at
            .is_some();
    if !gated {
        return Err(ApiError::Forbidden("18+ confirmation required"));
    }
    let row = sqlx::query(
        "SELECT id, mime, plaintext_size, duration_ms, visibility, status, created_at, view_count, thumb_ref, blob_ref
         FROM files WHERE id = ?",
    )
    .bind(&file_id)
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    if row.get::<String, _>("visibility") != "public" || row.get::<String, _>("status") != "ready" {
        return Err(ApiError::NotFound);
    }
    let portal_key: String =
        sqlx::query("SELECT wrapped_key FROM file_keys WHERE file_id = ? AND wrap_type = 'portal'")
            .bind(&file_id)
            .fetch_optional(&st.db)
            .await?
            .ok_or(ApiError::NotFound)?
            .get("wrapped_key");

    let blob_ref: String = row.get("blob_ref");
    let signed = st
        .signer
        .sign_resource(
            "GET",
            &blob_resource(&blob_ref),
            now() as u64 + DOWNLOAD_TTL,
        )
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    sqlx::query("UPDATE files SET view_count = view_count + 1 WHERE id = ?")
        .bind(&file_id)
        .execute(&st.db)
        .await?;

    Ok(Json(PublicManifest {
        file_id: row.get("id"),
        mime: row.get("mime"),
        size: row.get::<i64, _>("plaintext_size") as u64,
        duration_ms: row.get::<Option<i64>, _>("duration_ms").map(|d| d as u64),
        created_at: row.get("created_at"),
        view_count: row.get::<i64, _>("view_count") as u64 + 1,
        portal_key,
        thumb_ref: row.get("thumb_ref"),
        blob: SignedUpload {
            path: format!(
                "{}?exp={}&sig={}",
                signed.resource, signed.expires_at, signed.token
            ),
            expires_at: signed.expires_at as i64,
            token: signed.token,
        },
    }))
}

/// Signed URL for the owner to pull their own ciphertext back. There is no
/// separate "download" permission here: if you hold the UKEK you can read it, if
/// you do not, the bytes are noise either way.
pub async fn owner_url(
    State(st): State<AppState>,
    session: Session,
    Path(file_id): Path<String>,
) -> ApiResult<Json<SignedUpload>> {
    let row = sqlx::query("SELECT owner_id, blob_ref, status FROM files WHERE id = ?")
        .bind(&file_id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;
    if row.get::<i64, _>("owner_id") != session.account_id {
        return Err(ApiError::NotFound);
    }
    if row.get::<String, _>("status") != "ready" {
        return Err(ApiError::Conflict("file is not servable"));
    }
    let blob_ref: String = row.get("blob_ref");
    let signed = st
        .signer
        .sign_resource(
            "GET",
            &blob_resource(&blob_ref),
            now() as u64 + DOWNLOAD_TTL,
        )
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(SignedUpload {
        path: format!(
            "{}?exp={}&sig={}",
            signed.resource, signed.expires_at, signed.token
        ),
        expires_at: signed.expires_at as i64,
        token: signed.token,
    }))
}

/// Serve ciphertext. The origin only ever holds opaque bytes; CDN caches in
/// front of it can be purged per blob_ref without knowing anything either.
pub async fn blob(
    State(st): State<AppState>,
    Path(blob_ref): Path<String>,
    Query(q): Query<SignedQuery>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    // Optional second lock on the origin: when the CDN is configured to inject
    // `x-origin-secret`, a direct hit on the VPS IP is refused even if the
    // firewall allowlist is wrong. Constant-time compare; see docs/deploy-hetzner.md.
    if let Some(secret) = &st.cfg.origin_secret {
        let got = headers
            .get("x-origin-secret")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        if !vault_core::sodium::ct_eq(got.as_bytes(), secret.as_bytes()) {
            return Err(ApiError::Forbidden("origin only"));
        }
    }

    let exp = q.exp.ok_or(ApiError::Forbidden("bad signature"))?;
    let sig = q.sig.ok_or(ApiError::Forbidden("bad signature"))?;
    st.signer
        .verify_resource("GET", &blob_resource(&blob_ref), exp, &sig, now() as u64)
        .map_err(|_| ApiError::Forbidden("bad signature"))?;

    // Refuse to serve anything not in a servable state (quarantined files must
    // stay unservable even to holders of an old signature).
    let row = sqlx::query(
        "SELECT status, ciphertext_size, ciphertext_sha256 FROM files WHERE blob_ref = ?",
    )
    .bind(&blob_ref)
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::NotFound)?;
    if row.get::<String, _>("status") != "ready" {
        return Err(ApiError::NotFound);
    }
    let digest: Option<String> = row.get("ciphertext_sha256");
    let etag = digest.as_ref().map(|d| format!("\"{d}\""));

    if let (Some(etag), Some(if_none_match)) = (&etag, headers.get(header::IF_NONE_MATCH)) {
        if if_none_match
            .to_str()
            .map(|v| v.trim() == etag)
            .unwrap_or(false)
        {
            let mut resp = StatusCode::NOT_MODIFIED.into_response();
            set_blob_headers(resp.headers_mut(), &st, Some(etag), None);
            return Ok(resp);
        }
    }

    let path = st.cfg.blob_dir.join(&blob_ref);
    let file = tokio::fs::File::open(&path).await?;
    let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);

    // Range support: a player that cannot seek is not a video player, and CDNs
    // pass `Range` straight through to the origin.
    let range = match headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        Some(raw) => match parse_range(raw, len) {
            RangeParse::Satisfiable { start, end } => Some((start, end)),
            RangeParse::Unsatisfiable => {
                let mut resp = (StatusCode::RANGE_NOT_SATISFIABLE, "").into_response();
                if let Ok(v) = header::HeaderValue::from_str(&format!("bytes */{len}")) {
                    resp.headers_mut().insert(header::CONTENT_RANGE, v);
                }
                return Ok(resp);
            }
            // Multi-range or malformed: allowed to ignore the header entirely.
            RangeParse::Ignore => None,
        },
        None => None,
    };

    let mut file = file;
    let (status, body, length, content_range) = match range {
        Some((start, end)) => {
            use tokio::io::{AsyncReadExt, AsyncSeekExt};
            file.seek(std::io::SeekFrom::Start(start)).await?;
            let take = end - start + 1;
            let stream = ReaderStream::new(file.take(take));
            (
                StatusCode::PARTIAL_CONTENT,
                Body::from_stream(stream),
                take,
                Some(format!("bytes {start}-{end}/{len}")),
            )
        }
        None => (
            StatusCode::OK,
            Body::from_stream(ReaderStream::new(file)),
            len,
            None,
        ),
    };

    let mut resp = body.into_response();
    *resp.status_mut() = status;
    set_blob_headers(
        resp.headers_mut(),
        &st,
        etag.as_deref(),
        Some((length, content_range.as_deref())),
    );
    Ok(resp)
}

fn set_blob_headers(
    h: &mut HeaderMap,
    st: &AppState,
    etag: Option<&str>,
    len: Option<(u64, Option<&str>)>,
) {
    h.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(
        header::ACCEPT_RANGES,
        header::HeaderValue::from_static("bytes"),
    );
    let cache = if st.cfg.blob_cache_seconds == 0 {
        "no-store".to_string()
    } else {
        format!(
            "public, max-age={0}, s-maxage={0}",
            st.cfg.blob_cache_seconds
        )
    };
    if let Ok(v) = header::HeaderValue::from_str(&cache) {
        h.insert(header::CACHE_CONTROL, v);
    }
    if let Some(etag) = etag {
        if let Ok(v) = header::HeaderValue::from_str(etag) {
            h.insert(header::ETAG, v);
        }
    }
    if let Some((length, content_range)) = len {
        if let Ok(v) = header::HeaderValue::from_str(&length.to_string()) {
            h.insert(header::CONTENT_LENGTH, v);
        }
        if let Some(cr) = content_range {
            if let Ok(v) = header::HeaderValue::from_str(cr) {
                h.insert(header::CONTENT_RANGE, v);
            }
        }
    }
    h.insert(
        header::HeaderName::from_static("x-vault-cipher"),
        header::HeaderValue::from_static("xchacha20poly1305-secretstream"),
    );
}

enum RangeParse {
    Satisfiable { start: u64, end: u64 },
    Unsatisfiable,
    Ignore,
}

/// Parse a single byte range. Multi-range is ignored (a legal option under
/// RFC 9110) rather than answered with `multipart/byteranges`, because no video
/// player asks for it and getting it wrong would corrupt playback.
fn parse_range(raw: &str, len: u64) -> RangeParse {
    let Some(spec) = raw.trim().strip_prefix("bytes=") else {
        return RangeParse::Ignore;
    };
    if spec.contains(',') {
        return RangeParse::Ignore;
    }
    let Some((a, b)) = spec.split_once('-') else {
        return RangeParse::Ignore;
    };
    let (a, b) = (a.trim(), b.trim());
    if len == 0 {
        return RangeParse::Unsatisfiable;
    }

    if a.is_empty() {
        // Suffix form: last N bytes.
        let Ok(n) = b.parse::<u64>() else {
            return RangeParse::Ignore;
        };
        if n == 0 {
            return RangeParse::Unsatisfiable;
        }
        let n = n.min(len);
        return RangeParse::Satisfiable {
            start: len - n,
            end: len - 1,
        };
    }

    let Ok(start) = a.parse::<u64>() else {
        return RangeParse::Ignore;
    };
    let end = if b.is_empty() {
        len - 1
    } else {
        match b.parse::<u64>() {
            Ok(e) => e.min(len - 1),
            Err(_) => return RangeParse::Ignore,
        }
    };
    if start >= len || start > end {
        return RangeParse::Unsatisfiable;
    }
    RangeParse::Satisfiable { start, end }
}
