//! Secret handling: generate once, persist, never silently replace.
//!
//! The deploy goal is "clone, compose up, it works and it is safe". That means the
//! three load-bearing secrets (pepper, URL signing key, portal key) must not be a
//! manual step — but auto-generation has one catastrophic failure mode:
//!
//!   regenerate on every boot  →  every stored verifier stops matching (nobody can
//!                                log in) and every public file stops decrypting.
//!
//! So the rules here are deliberately paranoid:
//!
//!   1. Precedence: environment variable > file > (only if enabled) generate.
//!   2. Generation happens exactly once; the value is written 0600 to
//!      `VAULT_SECRET_DIR` and atomically renamed into place.
//!   3. An existing file is **never** overwritten. If it does not parse, that is a
//!      boot failure, not a reason to make a new one.
//!   4. `build_state` refuses to start when the database already has accounts and
//!      the secrets were generated this boot: that means the secrets volume was
//!      lost while the data survived, and starting anyway would silently break
//!      every account on the box.
//!   5. Secrets live in a *separate* volume from `/data`, so a backup of the
//!      ciphertext and the database does not also contain the pepper.
//!
//! Fingerprints (8 hex chars of SHA-256) are logged and exposed on `/healthz` so an
//! operator can tell whether a restart reused the same secrets without ever
//! printing a secret itself.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};
use vault_core::sodium;

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("{name}: {detail}")]
    Io { name: &'static str, detail: String },
    #[error("{name} from {origin} is unusable: {reason}")]
    Invalid {
        name: &'static str,
        origin: &'static str,
        reason: &'static str,
    },
    #[error("cannot generate {name}: {dir} is not writable ({detail})")]
    NotWritable {
        dir: String,
        name: &'static str,
        detail: String,
    },
}

/// Where a secret came from. Exposed on `/healthz` on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Env,
    File,
    Generated,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Env => "env",
            Source::File => "file",
            Source::Generated => "generated",
        }
    }

    /// A generated secret exists only because this boot created it. If the process
    /// restarts without the volume, it is gone.
    pub fn is_ephemeral(self) -> bool {
        matches!(self, Source::Generated)
    }
}

#[derive(Clone)]
pub struct Secret {
    bytes: Vec<u8>,
    pub source: Source,
    /// Generated here but not yet written: the write happens only after the startup
    /// guard has agreed that generating is safe. See `persist_generated`.
    pending_write: bool,
}

impl Secret {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// 8 hex chars of SHA-256. Enough to compare two boots, useless to an attacker.
    pub fn fingerprint(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"vault/secret-fingerprint/v1");
        h.update(&self.bytes);
        hex::encode(&h.finalize()[..4])
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Secret({}, fp={})",
            self.source.as_str(),
            self.fingerprint()
        )
    }
}

#[derive(Clone)]
pub struct Secrets {
    pub pepper: Secret,
    pub signing: Secret,
    pub portal: Secret,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets")
            .field("pepper", &self.pepper)
            .field("signing", &self.signing)
            .field("portal", &self.portal)
            .finish()
    }
}

impl Secrets {
    /// Fixed secrets for tests and for `Config::for_test`. Never persisted.
    pub fn for_test(pepper: &[u8], signing: &[u8], portal: &[u8]) -> Self {
        let make = |b: &[u8]| Secret {
            bytes: b.to_vec(),
            source: Source::Env,
            pending_write: false,
        };
        Self {
            pepper: make(pepper),
            signing: make(signing),
            portal: make(portal),
        }
    }
}

impl Secrets {
    /// True when at least one secret was created by this process (i.e. not read from
    /// env or disk). Used by the startup guard.
    pub fn any_generated(&self) -> bool {
        self.pepper.source.is_ephemeral()
            || self.signing.source.is_ephemeral()
            || self.portal.source.is_ephemeral()
    }
}

/// Reject values that only look like secrets. These are the copy-paste mistakes.
fn validate(name: &'static str, source: &'static str, bytes: &[u8]) -> Result<(), SecretError> {
    if bytes.len() < 32 {
        return Err(SecretError::Invalid {
            name,
            origin: source,
            reason: "shorter than 32 bytes",
        });
    }
    // All-identical bytes: "0000…", "aaaa…", a pasted constant.
    if bytes.windows(2).all(|w| w[0] == w[1]) {
        return Err(SecretError::Invalid {
            name,
            origin: source,
            reason: "every byte is identical (placeholder?)",
        });
    }
    // Very low byte diversity: hex of a short word, "abcabcabc…" and friends.
    let mut seen = [false; 256];
    for b in bytes {
        seen[*b as usize] = true;
    }
    if seen.iter().filter(|s| **s).count() < 8 {
        return Err(SecretError::Invalid {
            name,
            origin: source,
            reason: "fewer than 8 distinct byte values",
        });
    }
    Ok(())
}

fn secret_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.hex"))
}

/// Load one secret: env wins, then an existing file, then (if `auto`) generate.
pub fn load_or_create(
    dir: &Path,
    name: &'static str,
    len: usize,
    from_env: Option<Vec<u8>>,
    auto: bool,
) -> Result<Secret, SecretError> {
    if let Some(bytes) = from_env {
        validate(name, "environment", &bytes)?;
        return Ok(Secret {
            bytes,
            source: Source::Env,
            pending_write: false,
        });
    }

    let path = secret_path(dir, name);
    match fs::read_to_string(&path) {
        Ok(text) => {
            let bytes = hex::decode(text.trim()).map_err(|_| SecretError::Invalid {
                name,
                origin: "file",
                reason: "not hex",
            })?;
            validate(name, "file", &bytes)?;
            Ok(Secret {
                bytes,
                source: Source::File,
                pending_write: false,
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !auto {
                return Err(SecretError::Invalid {
                    name,
                    origin: "file",
                    reason: "missing and auto-generation is disabled",
                });
            }
            let bytes = sodium::random_bytes(len);
            validate(name, "generated", &bytes)?;
            // Deliberately NOT written yet: if the startup guard refuses (existing
            // accounts, or a recorded fingerprint that does not match), nothing may
            // be persisted. Otherwise the *next* boot would "load" a secret that
            // never protected the existing data and the guard would pass.
            Ok(Secret {
                bytes,
                source: Source::Generated,
                pending_write: true,
            })
        }
        // Exists but unreadable (permissions, a directory, I/O): never guess.
        Err(e) => Err(SecretError::Io {
            name,
            detail: format!("{}: {e}", path.display()),
        }),
    }
}

/// Atomic write: temp file in the same directory, 0600, fsync, rename.
fn write_secret(
    dir: &Path,
    path: &Path,
    name: &'static str,
    bytes: &[u8],
) -> Result<(), SecretError> {
    fs::create_dir_all(dir).map_err(|e| SecretError::NotWritable {
        dir: dir.display().to_string(),
        name,
        detail: e.to_string(),
    })?;
    // Refuse to clobber: another process may have won the race.
    if path.exists() {
        return Err(SecretError::Io {
            name,
            detail: "refusing to overwrite an existing secret".into(),
        });
    }
    let tmp = dir.join(format!(".{name}.tmp.{}", std::process::id()));
    {
        let mut f = fs::File::create(&tmp).map_err(|e| SecretError::NotWritable {
            dir: dir.display().to_string(),
            name,
            detail: e.to_string(),
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| SecretError::Io {
                    name,
                    detail: e.to_string(),
                })?;
        }
        f.write_all(hex::encode(bytes).as_bytes())
            .map_err(|e| SecretError::Io {
                name,
                detail: e.to_string(),
            })?;
        f.write_all(b"\n").map_err(|e| SecretError::Io {
            name,
            detail: e.to_string(),
        })?;
        f.sync_all().map_err(|e| SecretError::Io {
            name,
            detail: e.to_string(),
        })?;
    }
    fs::rename(&tmp, path).map_err(|e| SecretError::Io {
        name,
        detail: e.to_string(),
    })?;
    // Make the rename durable too, so a crash cannot leave a half-seen secret dir.
    #[cfg(unix)]
    {
        if let Ok(dirf) = fs::File::open(dir) {
            let _ = dirf.sync_all();
        }
    }
    Ok(())
}

/// Resolve all three secrets.
pub fn resolve(
    dir: &Path,
    auto: bool,
    pepper_env: Option<Vec<u8>>,
    signing_env: Option<Vec<u8>>,
    portal_env: Option<Vec<u8>>,
) -> Result<Secrets, SecretError> {
    Ok(Secrets {
        pepper: load_or_create(dir, "pepper", 32, pepper_env, auto)?,
        signing: load_or_create(dir, "signing", 32, signing_env, auto)?,
        portal: load_or_create(dir, "portal", 32, portal_env, auto)?,
    })
}

/// Write any generated secrets to `dir`. Called only after the startup guard agrees.
/// Refuses to overwrite: if a file appeared in the meantime, that is a failure, not a
/// reason to pick a winner.
pub fn persist_generated(dir: &Path, secrets: &Secrets) -> Result<(), SecretError> {
    for (name, secret) in [
        ("pepper", &secrets.pepper),
        ("signing", &secrets.signing),
        ("portal", &secrets.portal),
    ] {
        if !secret.pending_write {
            continue;
        }
        let path = secret_path(dir, name);
        write_secret(dir, &path, name, &secret.bytes)?;
        tracing::warn!(
            secret = name,
            path = %path.display(),
            fingerprint = %secret.fingerprint(),
            "generated a new secret and persisted it; it exists only on this volume — back it up"
        );
    }
    Ok(())
}

/// What the boot decided to do about secrets vs. the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Startup {
    /// No accounts and nothing recorded: a brand new instance.
    Fresh,
    /// Accounts exist, but no fingerprint was ever recorded (instance predates the
    /// check). Adopt the current secrets as authoritative and record them.
    Adopt,
    /// Fingerprint in the database matches the loaded pepper.
    Verified,
}

/// Decide whether it is safe to start, given what the database remembers.
///
/// `recorded` is the pepper fingerprint stored in the database at first boot. This is
/// the check that catches the mistakes the "generated this boot" heuristic cannot:
/// a restored *different* secrets volume, a pasted `VAULT_PEPPER`, or a secrets dir
/// that was already regenerated once by an earlier failed boot.
pub fn decide_startup(
    recorded: Option<&str>,
    current_fingerprint: &str,
    accounts: i64,
    any_generated: bool,
    allow_unsafe: bool,
) -> Result<Startup, String> {
    let forced = |msg: String| -> Result<Startup, String> {
        if allow_unsafe {
            tracing::error!(reason = %msg, "VAULT_ALLOW_UNSAFE=1: starting anyway");
            Ok(Startup::Adopt)
        } else {
            Err(msg)
        }
    };

    if any_generated && accounts > 0 {
        return forced(format!(
            "refusing to start: the database has {accounts} account(s) but the secrets on \
             VAULT_SECRET_DIR are new. Starting would change the pepper (every account fails to \
             log in) and the portal key (every public file becomes unreadable). Restore the \
             secrets volume, or set VAULT_PEPPER/VAULT_SIGNING/VAULT_PORTAL_KEY to the originals. \
             Starting a deliberately fresh instance on this data requires VAULT_ALLOW_UNSAFE=1 \
             (the old accounts will be unusable)."
        ));
    }
    match recorded {
        None if accounts > 0 => {
            tracing::warn!(
                accounts,
                "no pepper fingerprint recorded in this database; adopting the loaded secrets as \
                 authoritative and recording their fingerprint"
            );
            Ok(Startup::Adopt)
        }
        None => Ok(Startup::Fresh),
        Some(fp) if fp == current_fingerprint => Ok(Startup::Verified),
        Some(fp) => forced(format!(
            "refusing to start: the pepper in use (fingerprint {current_fingerprint}) does not \
             match the one this database was created with (fingerprint {fp}). Every existing \
             account would fail to log in and the portal key would be wrong. Restore the original \
             secrets volume or VAULT_PEPPER value."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "vault-secrets-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn generates_in_memory_then_persists_only_when_asked() {
        let dir = tmpdir("once");
        let first = resolve(&dir, true, None, None, None).unwrap();
        assert_eq!(first.pepper.source, Source::Generated);
        // Nothing on disk yet: persistence is a separate, deliberate step.
        assert!(!secret_path(&dir, "pepper").exists());

        persist_generated(&dir, &first).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(secret_path(&dir, "pepper"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let second = resolve(&dir, true, None, None, None).unwrap();
        assert_eq!(second.pepper.source, Source::File, "must not regenerate");
        assert_eq!(first.pepper.bytes(), second.pepper.bytes());
        assert_eq!(first.pepper.fingerprint(), second.pepper.fingerprint());
        assert!(!second.any_generated());

        // A second persist is a no-op, not an overwrite.
        persist_generated(&dir, &second).unwrap();
        assert_eq!(
            fs::read_to_string(secret_path(&dir, "pepper"))
                .unwrap()
                .trim(),
            hex::encode(first.pepper.bytes())
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_broken_file_is_a_failure_not_a_rotation() {
        let dir = tmpdir("broken");
        let path = secret_path(&dir, "pepper");
        fs::write(&path, "not-hex-at-all\n").unwrap();
        let err = load_or_create(&dir, "pepper", 32, None, true).unwrap_err();
        assert!(matches!(err, SecretError::Invalid { .. }), "{err:?}");
        assert_eq!(fs::read_to_string(&path).unwrap(), "not-hex-at-all\n");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn env_wins_and_is_validated() {
        let dir = tmpdir("env");
        let from_env: Vec<u8> = (0u8..32).collect();
        let s = load_or_create(&dir, "pepper", 32, Some(from_env.clone()), false).unwrap();
        assert_eq!(s.source, Source::Env);
        assert_eq!(s.bytes(), from_env.as_slice());
        assert!(!secret_path(&dir, "pepper").exists());

        let err = load_or_create(&dir, "pepper", 32, Some(vec![0u8; 32]), true).unwrap_err();
        assert!(matches!(err, SecretError::Invalid { .. }));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn short_and_low_entropy_secrets_rejected() {
        let dir = tmpdir("weak");
        for bad in [vec![1u8; 16], b"aaaa".repeat(8), b"changeme".repeat(4)] {
            let err = load_or_create(&dir, "pepper", 32, Some(bad), true).unwrap_err();
            assert!(matches!(err, SecretError::Invalid { .. }), "should reject");
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn auto_disabled_requires_explicit_secrets() {
        let dir = tmpdir("noauto");
        let err = load_or_create(&dir, "pepper", 32, None, false).unwrap_err();
        assert!(matches!(err, SecretError::Invalid { .. }));
        assert!(!secret_path(&dir, "pepper").exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn startup_guard_matrix() {
        // Fresh instance: nothing recorded, no accounts.
        assert_eq!(
            decide_startup(None, "aaaa1111", 0, false, false).unwrap(),
            Startup::Fresh
        );
        // Fresh instance whose secrets were just generated: still fine.
        assert_eq!(
            decide_startup(None, "aaaa1111", 0, true, false).unwrap(),
            Startup::Fresh
        );
        // Pre-existing database with no recorded fingerprint: adopt.
        assert_eq!(
            decide_startup(None, "aaaa1111", 5, false, false).unwrap(),
            Startup::Adopt
        );
        // Match: verified.
        assert_eq!(
            decide_startup(Some("aaaa1111"), "aaaa1111", 5, false, false).unwrap(),
            Startup::Verified
        );
        // Accounts exist and the secrets are brand new: refuse.
        let err = decide_startup(Some("aaaa1111"), "bbbb2222", 5, true, false).unwrap_err();
        assert!(err.contains("refusing to start"), "{err}");
        // Mismatch without generation (e.g. restored wrong volume): refuse.
        let err = decide_startup(Some("aaaa1111"), "cccc3333", 5, false, false).unwrap_err();
        assert!(
            err.contains("does not \n") || err.contains("does not"),
            "{err}"
        );
        // Explicit override on a throwaway.
        assert_eq!(
            decide_startup(Some("aaaa1111"), "cccc3333", 5, false, true).unwrap(),
            Startup::Adopt
        );
    }

    #[test]
    fn fingerprints_are_stable_and_do_not_leak() {
        let dir = tmpdir("fp");
        let s = resolve(&dir, true, None, None, None).unwrap();
        let fp = s.pepper.fingerprint();
        assert_eq!(fp.len(), 8);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        let hex_secret = hex::encode(s.pepper.bytes());
        assert!(
            !hex_secret.contains(&fp),
            "fingerprint must not be a substring of the secret"
        );
        // Debug output never contains the secret.
        assert!(!format!("{:?}", s.pepper).contains(&hex_secret));
        assert!(!format!("{:?}", s).contains(&hex_secret));
        fs::remove_dir_all(&dir).ok();
    }
}
