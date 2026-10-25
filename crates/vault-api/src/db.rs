//! SQLite schema and connection setup.
//!
//! SQLite in WAL mode with one writer is plenty for phase 0/1 (thousands of
//! daily users). The schema is written so a move to Postgres is a mechanical
//! translation: no SQLite-only types, no triggers, no `AUTOINCREMENT` semantics
//! the app depends on.

use std::str::FromStr;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS accounts (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    account_number     TEXT    NOT NULL UNIQUE,
    kdf_salt           TEXT    NOT NULL,
    kdf_ops            INTEGER NOT NULL DEFAULT 3,
    kdf_mem_bytes      INTEGER NOT NULL DEFAULT 67108864,
    kdf_version        INTEGER NOT NULL DEFAULT 1,
    auth_verifier      TEXT    NOT NULL,
    recovery_blob      TEXT    NOT NULL,
    recovery_ack       INTEGER NOT NULL DEFAULT 0,
    tier               TEXT    NOT NULL DEFAULT 'basic',
    storage_used       INTEGER NOT NULL DEFAULT 0,
    storage_quota      INTEGER NOT NULL DEFAULT 0,
    created_at         INTEGER NOT NULL,
    gate_at            INTEGER,
    age_verified_at    INTEGER,
    tos_accepted_at    INTEGER,
    strikes            INTEGER NOT NULL DEFAULT 0,
    ban_flag           INTEGER NOT NULL DEFAULT 0,
    auth_failures      INTEGER NOT NULL DEFAULT 0,
    locked_until       INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT    PRIMARY KEY,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    gate_at     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sessions_account ON sessions(account_id);

CREATE TABLE IF NOT EXISTS files (
    id                TEXT    PRIMARY KEY,
    owner_id          INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    blob_ref          TEXT    NOT NULL UNIQUE,
    ciphertext_sha256 TEXT,
    plaintext_digest  TEXT    NOT NULL,
    plaintext_size    INTEGER NOT NULL,
    ciphertext_size   INTEGER,
    mime              TEXT    NOT NULL,
    duration_ms       INTEGER,
    visibility        TEXT    NOT NULL,
    status            TEXT    NOT NULL,
    thumb_ref         TEXT,
    view_count        INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL,
    dead_flag         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_files_digest ON files(plaintext_digest);

CREATE TABLE IF NOT EXISTS file_keys (
    file_id     TEXT    NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    wrap_type   TEXT    NOT NULL,
    wrapped_key TEXT    NOT NULL,
    PRIMARY KEY (file_id, wrap_type)
);

CREATE TABLE IF NOT EXISTS shares (
    id               TEXT    PRIMARY KEY,
    file_id          TEXT    NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    passphrase_salt  TEXT    NOT NULL,
    expires_at       INTEGER,
    max_views        INTEGER,
    views            INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    id          TEXT    PRIMARY KEY,
    file_id     TEXT    NOT NULL,
    reporter_id INTEGER,
    reason      TEXT    NOT NULL,
    detail      TEXT,
    created_at  INTEGER NOT NULL,
    state       TEXT    NOT NULL DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS idx_reports_file ON reports(file_id, created_at DESC);

-- Small key/value store for boot-time invariants (the pepper fingerprint lives
-- here so a wrong secrets volume is caught instead of silently breaking accounts).
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS mod_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    actor        TEXT    NOT NULL,
    action       TEXT    NOT NULL,
    subject      TEXT,
    evidence_ref TEXT,
    detail       TEXT,
    created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mod_log_subject ON mod_log(subject, created_at DESC);
"#;

pub async fn connect(url: &str) -> Result<SqlitePool, String> {
    if let Some(path) = url.strip_prefix("sqlite:") {
        let path = path.split('?').next().unwrap_or(path);
        if path != ":memory:" {
            if let Some(parent) = std::path::Path::new(path).parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("creating {}: {e}", parent.display()))?;
                }
            }
        }
    }
    let opts = SqliteConnectOptions::from_str(url)
        .map_err(|e| format!("bad DATABASE_URL: {e}"))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(5))
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(opts)
        .await
        .map_err(|e| format!("connecting to database: {e}"))?;
    sqlx::raw_sql(SCHEMA)
        .execute(&pool)
        .await
        .map_err(|e| format!("applying schema: {e}"))?;
    Ok(pool)
}
