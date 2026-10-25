//! Sealed API crate root. `main.rs` is a thin shell around this so integration
//! tests can build the same router the server serves.

pub mod admin;
pub mod brand;
pub mod config;
pub mod db;
pub mod error;
pub mod ratelimit;
pub mod routes;
pub mod secrets;
pub mod state;

/// Unix seconds. One definition so every table shares the same clock.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

use std::path::Path;
use std::sync::Arc;

use axum::Router;
use vault_core::screen::{HashList, Screening};

pub use config::Config;
pub use state::AppState;

/// Build the process-wide state: database (schema applied), blob directory,
/// screening lists, secrets.
///
/// The order is the point:
///   1. connect + apply schema,
///   2. check the secrets against the database and refuse on mismatch
///      (`secrets::decide_startup`),
///   3. only then write generated secrets to disk,
///   4. load screening lists, failing loudly on a broken one.
pub async fn build_state(cfg: Config) -> Result<AppState, String> {
    std::fs::create_dir_all(&cfg.blob_dir)
        .map_err(|e| format!("creating blob dir {}: {e}", cfg.blob_dir.display()))?;

    // A misconfigured static dir is a boot failure, not a 404 storm in production.
    if let Some(dir) = &cfg.web_dir {
        if !dir.join("index.html").is_file() {
            return Err(format!(
                "VAULT_WEB_DIR={} does not contain index.html; build the web client first (cd web && npm run build)",
                dir.display()
            ));
        }
        tracing::info!(dir = %dir.display(), "serving static client");
    }

    let db = db::connect(&cfg.database_url).await?;

    let accounts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts")
        .fetch_one(&db)
        .await
        .map_err(|e| format!("counting accounts: {e}"))?;
    // Account numbers went from 12 to 16 digits. Rows written by the older build
    // cannot authenticate here, and finding that out at login (per user, silently)
    // is the wrong failure. Refuse at boot instead.
    let wanted = vault_core::account::DIGITS as i64;
    let incompatible: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM accounts WHERE length(account_number) <> ?")
            .bind(wanted)
            .fetch_one(&db)
            .await
            .map_err(|e| format!("checking account-number format: {e}"))?;
    if incompatible > 0 {
        if cfg.allow_unsafe {
            tracing::error!(
                accounts = incompatible,
                "VAULT_ALLOW_UNSAFE=1: starting with {incompatible} account(s) whose number is not \
                 {wanted} digits — those accounts cannot log in"
            );
        } else {
            return Err(format!(
                "refusing to start: {incompatible} account(s) in this database have an account number \
                 that is not {wanted} digits (this build only accepts the 16-digit format). Those \
                 accounts cannot log in. Export or delete them, or run the previous release. \
                 To start anyway, set VAULT_ALLOW_UNSAFE=1."
            ));
        }
    }

    let recorded: Option<String> =
        sqlx::query_scalar("SELECT value FROM settings WHERE key = 'pepper_fingerprint'")
            .fetch_optional(&db)
            .await
            .map_err(|e| format!("reading pepper fingerprint: {e}"))?;

    let decision = secrets::decide_startup(
        recorded.as_deref(),
        &cfg.secret_fingerprints[0],
        accounts,
        cfg.secrets_generated,
        cfg.allow_unsafe,
    )?;

    match decision {
        secrets::Startup::Verified => {
            tracing::info!(accounts, "secrets verified against this database")
        }
        secrets::Startup::Fresh => {
            tracing::info!("new instance — recording the secret fingerprint")
        }
        secrets::Startup::Adopt => tracing::warn!(
            accounts,
            "adopting the loaded secrets as authoritative for this pre-existing database"
        ),
    }
    if decision != secrets::Startup::Verified {
        sqlx::query(
            "INSERT INTO settings (key, value, updated_at) VALUES ('pepper_fingerprint', ?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        )
        .bind(&cfg.secret_fingerprints[0])
        .bind(state::now())
        .execute(&db)
        .await
        .map_err(|e| format!("recording pepper fingerprint: {e}"))?;
    }

    // Only now may generated secrets touch the disk: the guard has agreed that doing
    // so will not silently break accounts that already exist.
    secrets::persist_generated(&cfg.secret_dir, &cfg.secrets)
        .map_err(|e| format!("persisting generated secrets: {e}"))?;
    if cfg.secrets_generated {
        tracing::warn!(
            dir = %cfg.secret_dir.display(),
            "secrets were generated on this boot; they exist only on that volume — back it up \
             separately from the database"
        );
    }

    let mut screening = Screening::new(cfg.max_upload_bytes);
    for (name, path) in &cfg.hash_lists {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading hash list {} ({}): {e}", name, path.display()))?;
        let list = HashList::from_lines(name.clone(), &text)
            .map_err(|e| format!("parsing hash list {name}: {e}"))?;
        tracing::info!(list = %name, entries = list.len(), "loaded hash list");
        screening.add_list(list);
    }
    // A placeholder-only configuration must be visibly inert, not quietly so.
    let placeholder_only = !screening.list_names().is_empty()
        && screening.list_names().iter().all(|n| *n == "placeholder");
    if placeholder_only {
        tracing::warn!(
            "screening has only the placeholder list: it matches nothing. Uploads are gated by \
             tier/quota/strikes only — point VAULT_HASH_LISTS at real feeds before opening a feed."
        );
    }

    let signer = cfg.signer();
    let portal_key_hex = Arc::new(cfg.portal_key_hex.clone());
    let rate_limiter = Arc::new(crate::ratelimit::RateLimiter::new(cfg.rate_limit_enabled));
    if !cfg.rate_limit_enabled {
        tracing::warn!("per-IP rate limiting is disabled");
    }
    let screening_mode = if placeholder_only {
        "placeholder-only"
    } else if screening.list_names().is_empty() {
        "none"
    } else {
        "configured"
    };
    tracing::info!(screening = screening_mode, "screening mode");
    Ok(AppState {
        cfg: Arc::new(cfg),
        db,
        signer,
        screening: Arc::new(screening),
        portal_key_hex,
        rate_limiter,
    })
}

/// The HTTP app. Cheap to construct; one per process, many per test.
pub fn app(state: AppState) -> Router {
    routes::router(state)
}

/// Write a starter hash list so a fresh deployment screens against *something*
/// instead of nothing. Content: the digests of the empty string and of "vault
/// self-test", which cannot match a real upload; the file exists to make the
/// wiring visible and testable.
pub fn write_starter_hash_list(dir: &Path) -> Result<std::path::PathBuf, String> {
    use vault_core::ids::plaintext_digest;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let path = dir.join("starter.txt");
    let body = format!(
        "# Starter screening list. Replace with NCMEC/PhotoDNA/Thorn feeds.\n\
         # Format: one lowercase sha256 hex digest per line.\n\
         {}\n{}\n",
        plaintext_digest(b""),
        plaintext_digest(b"vault self-test")
    );
    std::fs::write(&path, body).map_err(|e| e.to_string())?;
    Ok(path)
}
