//! Health, DMCA, community reports.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use sqlx::Row;
use vault_core::ids;
use vault_core::wire::{Ack, ReportRequest, ReportResponse};

use crate::error::{ApiError, ApiResult};
use crate::routes::Session;
use crate::state::{now, AppState};

/// Reasons we accept. Anything else is rejected so the mod queue stays usable
/// and the CSAM path is not diluted by typos.
const REASONS: [&str; 6] = [
    "csam",
    "nonconsensual",
    "copyright",
    "underage",
    "spam",
    "other",
];

pub async fn healthz(State(st): State<AppState>) -> Response {
    let db_ok = sqlx::query("SELECT 1").fetch_one(&st.db).await.is_ok();
    let blobs_ok = tokio::fs::metadata(&st.cfg.blob_dir).await.is_ok();
    let status = if db_ok && blobs_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "status": if db_ok && blobs_ok { "ok" } else { "degraded" },
            "product": crate::brand::brand().name,
            "version": env!("CARGO_PKG_VERSION"),
            "db": db_ok,
            "blobs": blobs_ok,
            "hash_lists": st.screening.list_names(),
            "screening": if st.screening.list_names().is_empty() {
                "none"
            } else if st.screening.list_names().iter().all(|n| *n == "placeholder") {
                "placeholder-only"
            } else {
                "configured"
            },
            // Sources and fingerprints only — never the secrets themselves. An
            // operator can compare fingerprints across restarts to prove the
            // secrets volume is doing its job.
            "secrets": {
                "pepper": {"source": st.cfg.secret_sources[0].as_str(), "fingerprint": st.cfg.secret_fingerprints[0]},
                "signing": {"source": st.cfg.secret_sources[1].as_str(), "fingerprint": st.cfg.secret_fingerprints[1]},
                "portal": {"source": st.cfg.secret_sources[2].as_str(), "fingerprint": st.cfg.secret_fingerprints[2], "derived": st.cfg.portal_key_derived},
                "dir": st.cfg.secret_dir.display().to_string(),
                "generated_this_boot": st.cfg.secrets_generated,
            },
            "rate_limit": st.cfg.rate_limit_enabled,
            "trust_proxy": st.cfg.trust_forwarded,
        })),
    )
        .into_response()
}

pub async fn dmca() -> Response {
    let brand = crate::brand::brand();
    let contact = std::env::var("VAULT_DMCA_CONTACT").unwrap_or_else(|_| {
        if brand.dmca_default.is_empty() {
            "NOT CONFIGURED".to_string()
        } else {
            format!("{} (default, not verified)", brand.dmca_default)
        }
    });
    let body = format!(
        "{name} — Copyright and Takedown\n\
         ================================\n\n\
         Designated agent contact: {contact}\n\
         Response window: 48 hours.\n\n\
         Send: (1) the URL or file id, (2) the work claimed, (3) your contact\n\
         details, (4) a statement of good-faith belief, (5) a statement under\n\
         penalty of perjury that the information is accurate and you are\n\
         authorised to act, (6) your signature.\n\n\
         Every notice is logged in the moderation log with its action and\n\
         timestamp. Files that are removed are marked dead, not deleted, for the\n\
         retention period required by law.\n\n\
         Counter-notices go to the same address.\n\
         Files uploaded here are stored as ciphertext; we cannot read them and\n\
         we serve content we cannot inspect. See /v1/reports for abuse.\n",
        contact = contact,
        name = brand.name
    );
    (
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

/// Community report. A `csam` report freezes the file and the uploader
/// immediately; everything else queues for a human.
pub async fn report(
    State(st): State<AppState>,
    session: Session,
    Json(req): Json<ReportRequest>,
) -> ApiResult<(StatusCode, Json<ReportResponse>)> {
    if !REASONS.contains(&req.reason.as_str()) {
        return Err(ApiError::BadRequest("unknown report reason"));
    }
    if req.detail.as_ref().map(|d| d.len()).unwrap_or(0) > 4000 {
        return Err(ApiError::BadRequest("detail too long"));
    }
    let file = sqlx::query("SELECT owner_id, status FROM files WHERE id = ?")
        .bind(&req.file_id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound)?;

    let report_id = ids::new_prefixed_id("r");
    let ts = now();
    sqlx::query(
        "INSERT INTO reports (id, file_id, reporter_id, reason, detail, created_at, state)
         VALUES (?, ?, ?, ?, ?, ?, 'open')",
    )
    .bind(&report_id)
    .bind(&req.file_id)
    .bind(session.account_id)
    .bind(&req.reason)
    .bind(&req.detail)
    .bind(ts)
    .execute(&st.db)
    .await?;

    if req.reason == "csam" || req.reason == "underage" {
        let owner_id: i64 = file.get("owner_id");
        let mut tx = st.db.begin().await?;
        sqlx::query("UPDATE files SET status = 'quarantined' WHERE id = ?")
            .bind(&req.file_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE accounts SET ban_flag = 1, strikes = strikes + 1 WHERE id = ?")
            .bind(owner_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO mod_log (actor, action, subject, evidence_ref, detail, created_at)
             VALUES ('system', 'report_quarantine', ?, ?, ?, ?)",
        )
        .bind(&req.file_id)
        .bind(&report_id)
        .bind(format!(
            "reason={} reporter={}",
            req.reason, session.account_id
        ))
        .bind(ts)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        tracing::error!(file_id = %req.file_id, report_id = %report_id, "CSAM-class report: quarantined, follow docs/ts-runbook.md");
    } else {
        sqlx::query(
            "INSERT INTO mod_log (actor, action, subject, evidence_ref, detail, created_at)
             VALUES ('system', 'report_queued', ?, ?, ?, ?)",
        )
        .bind(&req.file_id)
        .bind(&report_id)
        .bind(format!("reason={}", req.reason))
        .bind(ts)
        .execute(&st.db)
        .await?;
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(ReportResponse {
            report_id,
            accepted: true,
        }),
    ))
}

/// Unknown endpoint under `/v1`. Exists so the static-client fallback can never
/// answer an API typo with `index.html`.
pub async fn api_not_found() -> ApiError {
    ApiError::NotFound
}

/// Acknowledge the recovery phrase. Separate call so the client can require the
/// user to write it down before this fires.
pub async fn ack_recovery(State(st): State<AppState>, session: Session) -> ApiResult<Json<Ack>> {
    sqlx::query("UPDATE accounts SET recovery_ack = 1 WHERE id = ?")
        .bind(session.account_id)
        .execute(&st.db)
        .await?;
    Ok(Json(Ack { ok: true }))
}

/// Total bytes of regular files under `dir`, ignoring errors. Used only for the
/// admin panel's storage readout, so a missing directory is "zero", not a failure.
pub fn dir_size(dir: &std::path::Path) -> u64 {
    fn walk(dir: &std::path::Path, total: &mut u64) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                walk(&entry.path(), total);
            } else if meta.is_file() {
                *total += meta.len();
            }
        }
    }
    let mut total = 0;
    walk(dir, &mut total);
    total
}
