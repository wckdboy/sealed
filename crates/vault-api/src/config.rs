//! Deployment configuration. Everything comes from the environment; nothing is read
//! from a config file, so a container restart with the same environment and the same
//! volumes is always the same server.
//!
//! ## The three load-bearing secrets
//!
//!   * `VAULT_PEPPER`     — HMAC key for login verifiers (DB + pepper = offline attack)
//!   * `VAULT_SIGNING`    — URL signing secret
//!   * `VAULT_PORTAL_KEY` — PKEK, released to 18+-gated sessions
//!
//! A deploy must not depend on a human running `openssl rand -hex 32` three times,
//! and it must not silently regenerate them either (that locks every account out).
//! `secrets::resolve` implements the safe middle: generate once into
//! `VAULT_SECRET_DIR` (0600), reuse forever, refuse to overwrite, and refuse to boot
//! if the database already has accounts but the secrets are new.
//!
//! Everything else has a safe default, so `docker compose up` yields a working and
//! defensible instance. Settings that weaken the system require
//! `VAULT_ALLOW_UNSAFE=1` — see [`Config::validate`].

use std::path::PathBuf;

use vault_core::{keys::Key, sign::Signer};

use crate::secrets::{self, SecretError, Secrets, Source};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} must be set")]
    Missing(&'static str),
    #[error("{0} is malformed: {1}")]
    Malformed(&'static str, String),
    #[error("{0}")]
    Secrets(#[from] SecretError),
    /// Deliberately unsafe settings are allowed, but only on purpose.
    #[error(
        "refusing to start with unsafe settings: {0}. \
         If this instance is genuinely a throwaway, set VAULT_ALLOW_UNSAFE=1"
    )]
    Unsafe(String),
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: String,
    pub database_url: String,
    pub blob_dir: PathBuf,

    // Secret material. Never logged; fingerprints are.
    pub pepper: Vec<u8>,
    pub signing_secret: Vec<u8>,
    pub portal_key_hex: String,
    /// True when the portal key was derived from non-32-byte material.
    pub portal_key_derived: bool,
    /// Bearer token for `/v1/admin/*`. `None` disables the whole admin surface.
    pub admin_token: Option<String>,
    /// Where secrets were persisted (env-supplied secrets ignore this).
    pub secret_dir: PathBuf,
    /// `env`, `file` or `generated`, per secret, exposed on `/healthz`.
    pub secret_sources: [Source; 3],
    /// 8 hex chars of SHA-256 per secret, so two boots can be compared.
    pub secret_fingerprints: [String; 3],
    /// True if any secret was created by this process (not loaded).
    pub secrets_generated: bool,
    /// The resolved secrets, including whether any still need persisting.
    pub secrets: Secrets,

    pub session_ttl_seconds: i64,
    pub dev: bool,
    pub default_tier: String,
    /// `(list name, path)` pairs. Missing files are a startup error: silently
    /// screening against nothing is the failure mode that gets you indicted.
    pub hash_lists: Vec<(String, PathBuf)>,
    pub max_upload_bytes: u64,
    pub allowed_origins: Vec<String>,
    /// Directory with the built PWA. When set the API also serves the static
    /// client, so production is one container and the browser talks to the same
    /// origin (no CORS, no second deploy).
    pub web_dir: Option<PathBuf>,
    /// `Cache-Control: public, max-age=N` on ciphertext blobs. Also the worst-case
    /// window in which a quarantined file is still served from an edge cache.
    pub blob_cache_seconds: u64,
    /// When set, `/v1/blobs/*` requires this value in `x-origin-secret`.
    pub origin_secret: Option<String>,
    /// Trust the first hop of `X-Forwarded-For`. Only behind a proxy you control.
    pub trust_forwarded: bool,
    pub rate_limit_enabled: bool,
    /// Escape hatch for deliberately weakened settings.
    pub allow_unsafe: bool,
}

impl Config {
    /// How much screening is actually possible right now. Shown on `/healthz` and in
    /// the admin panel so "screening ran" is never confused with "screening works".
    pub fn screening_mode(&self) -> &'static str {
        if self.hash_lists.is_empty() {
            "none"
        } else if self.hash_lists.iter().all(|(n, _)| n == "placeholder") {
            "placeholder-only"
        } else {
            "configured"
        }
    }

    pub fn from_env() -> Result<Self, ConfigError> {
        let dev = env_flag("VAULT_DEV");
        let allow_unsafe = env_flag("VAULT_ALLOW_UNSAFE");
        let bind = env_or(
            "VAULT_BIND",
            if dev {
                "127.0.0.1:8080"
            } else {
                "0.0.0.0:8080"
            },
        );
        let database_url = env_or("DATABASE_URL", "sqlite:data/vault.db");
        let blob_dir = PathBuf::from(env_or("VAULT_BLOB_DIR", "data/blobs"));
        let secret_dir = PathBuf::from(env_or("VAULT_SECRET_DIR", "secrets"));
        // Auto-generation is the container default: it is what makes a fresh deploy
        // work with no human step. VAULT_AUTO_SECRETS=0 requires all three from env.
        let auto_secrets = !matches!(
            std::env::var("VAULT_AUTO_SECRETS").as_deref(),
            Ok("0") | Ok("false")
        );

        let resolved = secrets::resolve(
            &secret_dir,
            auto_secrets,
            env_secret("VAULT_PEPPER")?,
            env_secret("VAULT_SIGNING")?,
            env_secret("VAULT_PORTAL_KEY")?,
        )?;
        // The portal key feeds crypto_secretbox, which needs exactly 32 bytes. A
        // generated file is always 32; material from a secret manager (Coolify's
        // SERVICE_PASSWORD_64_*, Doppler, Infisical, a hand-typed passphrase) is a
        // long alphanumeric string. Derive a stable key from it rather than reject
        // the deployment — same input, same key, forever.
        let (portal_key, portal_key_derived) = match resolved.portal.bytes().len() {
            32 => (resolved.portal.bytes().to_vec(), false),
            n if n > 32 => (
                vault_core::keys::derive_portal_key(resolved.portal.bytes()).to_vec(),
                true,
            ),
            n => {
                return Err(ConfigError::Malformed(
                    "VAULT_PORTAL_KEY",
                    format!("needs at least 32 bytes, got {n}"),
                ))
            }
        };
        if portal_key_derived {
            tracing::warn!(
                bytes = resolved.portal.bytes().len(),
                "portal key is not exactly 32 bytes: deriving it with \
                 vault/portal-key/v1 (stable, but not the same bytes as the source)"
            );
        }
        let secret_sources = [
            resolved.pepper.source,
            resolved.signing.source,
            resolved.portal.source,
        ];
        let secret_fingerprints = [
            resolved.pepper.fingerprint(),
            resolved.signing.fingerprint(),
            resolved.portal.fingerprint(),
        ];
        let secrets_generated = resolved.any_generated();

        for (name, source, fp) in ["pepper", "signing", "portal"]
            .iter()
            .zip(secret_sources)
            .zip(secret_fingerprints.iter())
            .map(|((n, s), f)| (*n, s, f.clone()))
        {
            tracing::info!(secret = name, source = source.as_str(), fingerprint = %fp, "secret loaded");
        }

        let hash_lists = parse_hash_lists(&env_or("VAULT_HASH_LISTS", ""))?;

        let cfg = Self {
            bind,
            database_url,
            blob_dir,
            pepper: resolved.pepper.bytes().to_vec(),
            signing_secret: resolved.signing.bytes().to_vec(),
            portal_key_hex: hex::encode(&portal_key),
            portal_key_derived,
            admin_token: std::env::var("VAULT_ADMIN_TOKEN")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| v.len() >= 16),
            secret_dir,
            secret_sources,
            secret_fingerprints,
            secrets_generated,
            secrets: resolved,
            session_ttl_seconds: env_or("VAULT_SESSION_TTL", "2592000")
                .parse()
                .unwrap_or(2_592_000),
            dev,
            default_tier: env_or("VAULT_DEFAULT_TIER", if dev { "premium1" } else { "basic" }),
            hash_lists,
            max_upload_bytes: env_or("VAULT_MAX_UPLOAD", "20000000000")
                .parse()
                .unwrap_or(vault_core::wire::MAX_UPLOAD_BYTES),
            allowed_origins: env_or("VAULT_ALLOWED_ORIGINS", "http://localhost:5173")
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            web_dir: std::env::var("VAULT_WEB_DIR")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .map(PathBuf::from),
            blob_cache_seconds: env_or("VAULT_BLOB_CACHE_SECONDS", "3600")
                .parse()
                .unwrap_or(3600),
            origin_secret: std::env::var("VAULT_ORIGIN_SECRET")
                .ok()
                .filter(|v| !v.trim().is_empty()),
            trust_forwarded: env_flag("VAULT_TRUST_PROXY"),
            rate_limit_enabled: !matches!(
                std::env::var("VAULT_RATE_LIMIT").as_deref(),
                Ok("0") | Ok("false")
            ),
            allow_unsafe,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Refuse the configurations that turn a small mistake into an incident.
    ///
    /// Each of these is one env var away from a production instance that *looks*
    /// fine and is not. Rather than trust the operator to remember, they require an
    /// explicit `VAULT_ALLOW_UNSAFE=1`.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut unsafe_settings: Vec<&'static str> = Vec::new();

        if !self.rate_limit_enabled {
            unsafe_settings.push("VAULT_RATE_LIMIT=0 disables per-IP abuse limits");
        }
        if self.hash_lists.is_empty() && !self.dev {
            unsafe_settings.push(
                "VAULT_HASH_LISTS is empty, so no upload is screened (set it, or run with VAULT_DEV=1)",
            );
        }
        if self.blob_cache_seconds == 0 {
            unsafe_settings.push("VAULT_BLOB_CACHE_SECONDS=0 makes every CDN request a miss");
        }

        if !unsafe_settings.is_empty() && self.allow_unsafe {
            tracing::warn!(
                settings = ?unsafe_settings,
                "VAULT_ALLOW_UNSAFE=1: continuing with weakened settings"
            );
            return Ok(());
        }
        if unsafe_settings.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Unsafe(unsafe_settings.join("; ")))
        }
    }

    pub fn signer(&self) -> Signer {
        Signer::new(&self.signing_secret).expect("validated at startup")
    }

    pub fn portal_key(&self) -> Key {
        Key::from_hex(&self.portal_key_hex).expect("validated at startup")
    }

    /// Deterministic configuration for tests: fixed secrets, caller-supplied
    /// directory, no hash lists, unsafe settings allowed.
    pub fn for_test(root: &std::path::Path) -> Self {
        Self {
            bind: "127.0.0.1:0".into(),
            database_url: format!("sqlite:{}", root.join("test.db").display()),
            blob_dir: root.join("blobs"),
            pepper: b"test-pepper-0123456789abcdef01234567".to_vec(),
            signing_secret: b"test-signing-0123456789abcdef0123456".to_vec(),
            portal_key_hex: "07".repeat(32),
            portal_key_derived: false,
            admin_token: None,
            secret_dir: root.join("secrets"),
            secret_sources: [Source::Env, Source::Env, Source::Env],
            secret_fingerprints: ["test0001".into(), "test0002".into(), "test0003".into()],
            secrets_generated: false,
            secrets: Secrets::for_test(
                b"test-pepper-0123456789abcdef01234567",
                b"test-signing-0123456789abcdef0123456",
                &[7u8; 32],
            ),
            session_ttl_seconds: 3600,
            dev: true,
            default_tier: "premium1".into(),
            hash_lists: Vec::new(),
            max_upload_bytes: vault_core::wire::MAX_UPLOAD_BYTES,
            allowed_origins: Vec::new(),
            web_dir: None,
            blob_cache_seconds: 3600,
            origin_secret: None,
            // Tests drive rate limiting through X-Forwarded-For.
            trust_forwarded: true,
            rate_limit_enabled: false,
            allow_unsafe: true,
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_flag(key: &str) -> bool {
    matches!(
        std::env::var(key).as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

fn env_secret(name: &'static str) -> Result<Option<Vec<u8>>, ConfigError> {
    match std::env::var(name) {
        Ok(v) => Ok(parse_secret_value(&v)),
        _ => Ok(None),
    }
}

/// Interpret a secret supplied as text. Hex is decoded (that is what `openssl rand
/// -hex 32` and the docs produce, and what the `/secrets/*.hex` files contain);
/// anything else is taken as raw UTF-8 bytes, which is what Coolify's
/// `SERVICE_PASSWORD_64_*`, Doppler, Infisical and a typed passphrase produce.
///
/// Empty (or whitespace-only) means "not supplied", so a blank variable in a
/// deployment UI falls through to the file / generation path instead of becoming a
/// zero-length secret.
fn parse_secret_value(raw: &str) -> Option<Vec<u8>> {
    let v = raw.trim();
    if v.is_empty() {
        return None;
    }
    if v.len() % 2 == 0 && v.len() >= 64 && v.bytes().all(|b| b.is_ascii_hexdigit()) {
        if let Ok(bytes) = hex::decode(v) {
            if bytes.len() >= 32 {
                return Some(bytes);
            }
        }
    }
    Some(v.as_bytes().to_vec())
}

/// `name=path,name=path`. Relative paths resolve from the working directory.
fn parse_hash_lists(spec: &str) -> Result<Vec<(String, PathBuf)>, ConfigError> {
    let mut out = Vec::new();
    for item in spec.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let (name, path) = item.split_once('=').ok_or_else(|| {
            ConfigError::Malformed(
                "VAULT_HASH_LISTS",
                format!("expected name=path, got {item}"),
            )
        })?;
        out.push((name.to_string(), PathBuf::from(path)));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_env_accepts_hex_or_raw_text() {
        // 64 hex chars == 32 bytes: decoded, exactly as the /secrets files are.
        let hex64 = "ab".repeat(32);
        assert_eq!(parse_secret_value(&hex64).unwrap().len(), 32);

        // A Coolify SERVICE_PASSWORD_64_* value: 64 alphanumeric chars, not hex.
        let alnum = "qG7hkL9mpQ2rT4vXw8BnP6sYd".repeat(3)[..64].to_string();
        assert!(alnum.len() == 64 && alnum.bytes().any(|b| !b.is_ascii_hexdigit()));
        let raw = parse_secret_value(&alnum).unwrap();
        assert_eq!(raw.len(), 64, "raw text is used verbatim, not hex-decoded");
        assert_eq!(raw, alnum.as_bytes());

        // An even-length hex-looking value shorter than 64 chars is still text.
        assert_eq!(parse_secret_value("deadbeef").unwrap(), b"deadbeef");

        // Blank means "not supplied", so a blank UI variable falls through to the
        // /secrets file or first-boot generation instead of becoming a 0-byte key.
        assert!(parse_secret_value("").is_none());
        assert!(parse_secret_value("   \n").is_none());

        // Trailing newlines from `$(cat file)` must not become part of the secret.
        assert_eq!(parse_secret_value(&format!("{hex64}\n")).unwrap().len(), 32);
    }

    #[test]
    fn portal_key_is_derived_only_when_it_is_not_32_bytes() {
        let material = b"a 64 character alphanumeric secret from some secret manager x";
        assert_eq!(
            vault_core::keys::derive_portal_key(material).len(),
            32,
            "derived keys always fit crypto_secretbox"
        );
        // 32 bytes of hex is used as-is: no silent re-derivation of an existing key.
        let cfg = Config::for_test(std::path::Path::new("/tmp"));
        assert!(!cfg.portal_key_derived);
        assert_eq!(cfg.portal_key().as_bytes().len(), 32);
    }

    #[test]
    fn unsafe_settings_need_an_explicit_flag() {
        let root = std::env::temp_dir().join(format!("vault-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();

        let mut cfg = Config::for_test(&root);
        cfg.allow_unsafe = false;
        cfg.dev = false;
        cfg.rate_limit_enabled = false;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("VAULT_RATE_LIMIT"), "{err}");
        assert!(err.contains("VAULT_HASH_LISTS"), "{err}");
        assert!(err.contains("VAULT_ALLOW_UNSAFE"), "{err}");

        // Fixing them makes it valid with no escape hatch.
        let mut cfg = Config::for_test(&root);
        cfg.allow_unsafe = false;
        cfg.dev = false;
        cfg.rate_limit_enabled = true;
        cfg.hash_lists = vec![("t".into(), root.join("list.txt"))];
        assert!(cfg.validate().is_ok());

        // Allow-unsafe lets a throwaway instance through.
        let mut cfg = Config::for_test(&root);
        cfg.allow_unsafe = true;
        cfg.rate_limit_enabled = false;
        assert!(cfg.validate().is_ok());

        std::fs::remove_dir_all(&root).ok();
    }
}
