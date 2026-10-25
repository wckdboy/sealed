//! Key derivation: passphrase -> UKEK (file-key wrapping key) + auth secret.
//!
//! One Argon2id call produces 64 bytes, split in two halves with independent
//! jobs:
//!
//! ```text
//! k        = Argon2id(passphrase, salt, ops=3, mem=64MiB, out=64)
//! UKEK     = k[0..32]      stays in client RAM; wraps every FEK
//! auth_sec = k[32..64]     sent to the server (TLS) to authenticate
//! ```
//!
//! Splitting matters. The server stores `verifier = HMAC(pepper, auth_sec ||
//! account_number)`, never `auth_sec` and never `UKEK`. A stolen database
//! therefore does not hand out an offline passphrase oracle *unless* the
//! attacker also has the deployment pepper — which lives in the server
//! environment and in the operator's password manager, not in SQL.
//!
//! Why not a PAKE (OPAQUE/SRP): it removes the pepper dependency entirely, but
//! it is a bigger lift on both clients and needs a vetted implementation on
//! Kotlin + JS. Tracked in docs/adr/0005-verifier-pepper.md; the wire format
//! here already separates auth material from key material, so swapping in
//! OPAQUE later touches only this module and the two clients' login screens.

use crate::error::{Error, Result};
use crate::keys::Key;
use crate::sodium;
use libsodium_sys as sodium_sys;

/// Argon2id salt length required by libsodium.
pub const SALT_BYTES: usize = 16;
/// Minimum passphrase length we will accept (characters, not bytes).
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// Argon2id cost. One constant, both clients, no drift.
///
/// 64 MiB / 3 passes ≈ 150 ms on a 2024 phone and ≈ 60 ms on a server core.
/// Tuning up is a one-line change here plus a re-wrap migration, so the salt
/// blob carries a params version (see [`KdfParams::version`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub ops: u64,
    pub mem_bytes: usize,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::v1()
    }
}

impl KdfParams {
    pub const fn v1() -> Self {
        Self {
            ops: 3,
            mem_bytes: 64 * 1024 * 1024,
        }
    }

    /// Cheap parameters for unit tests that are not testing the KDF itself.
    pub const fn test_only_fast() -> Self {
        Self {
            ops: 1,
            mem_bytes: 8 * 1024 * 1024,
        }
    }

    /// Stored alongside the salt so a future cost bump can re-wrap per account.
    pub fn version(&self) -> u8 {
        match (self.ops, self.mem_bytes) {
            (3, 67_108_864) => 1,
            _ => 0,
        }
    }
}

/// A 16-byte Argon2id salt, generated client-side at signup.
#[derive(Clone, PartialEq, Eq)]
pub struct Salt([u8; SALT_BYTES]);

impl Salt {
    pub fn random() -> Self {
        sodium::init();
        Self(sodium::random_array())
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; SALT_BYTES] = bytes
            .try_into()
            .map_err(|_| Error::InvalidParameter("salt must be 16 bytes"))?;
        Ok(Self(arr))
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        Self::from_slice(&sodium::from_hex(s)?)
    }

    pub fn as_bytes(&self) -> &[u8; SALT_BYTES] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for Salt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Salt({})", self.to_hex())
    }
}

/// Output of the passphrase KDF.
pub struct Derived {
    /// Wraps FEKs. Never leaves the client.
    pub ukek: Key,
    /// Authentication material. Sent to the server to prove passphrase knowledge.
    pub auth_secret: Key,
}

impl std::fmt::Debug for Derived {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Derived { ukek: <redacted>, auth_secret: <redacted> }")
    }
}

/// Derive UKEK + auth secret. This is the single expensive call per unlock.
pub fn derive(passphrase: &str, salt: &Salt, params: KdfParams) -> Result<Derived> {
    check_passphrase_strength(passphrase)?;
    kdf_split(passphrase, salt, params)
}

/// Same as [`derive`] but skips the strength gate — for legacy accounts whose
/// passphrase policy predates the current check.
pub fn kdf_split(passphrase: &str, salt: &Salt, params: KdfParams) -> Result<Derived> {
    if passphrase.is_empty() {
        return Err(Error::WeakPassphrase("empty"));
    }
    sodium::init();
    let mut out = [0u8; 64];
    let rc = unsafe {
        sodium_sys::crypto_pwhash(
            out.as_mut_ptr(),
            out.len() as u64,
            passphrase.as_ptr() as *const i8,
            passphrase.len() as u64,
            salt.as_bytes().as_ptr(),
            params.ops,
            params.mem_bytes,
            sodium_sys::crypto_pwhash_ALG_ARGON2ID13 as i32,
        )
    };
    if rc != 0 {
        return Err(Error::KdfFailure);
    }
    let mut ukek = [0u8; 32];
    let mut auth_secret = [0u8; 32];
    ukek.copy_from_slice(&out[..32]);
    auth_secret.copy_from_slice(&out[32..]);
    sodium::memzero(&mut out);
    Ok(Derived {
        ukek: Key::from_bytes(ukek),
        auth_secret: Key::from_bytes(auth_secret),
    })
}

/// Coarse strength policy. Not an entropy meter: it rejects the two failure
/// modes we actually see (short passphrases, and a 4-digit PIN padded), and
/// requires either length or multiple words.
pub fn check_passphrase_strength(passphrase: &str) -> Result<()> {
    let chars = passphrase.chars().count();
    if chars < MIN_PASSPHRASE_CHARS {
        return Err(Error::WeakPassphrase("at least 12 characters"));
    }
    if chars > 1024 {
        return Err(Error::WeakPassphrase("at most 1024 characters"));
    }
    let words = passphrase.split_whitespace().count();
    let distinct = {
        let mut v: Vec<char> = passphrase.chars().filter(|c| !c.is_whitespace()).collect();
        v.sort_unstable();
        v.dedup();
        v.len()
    };
    if distinct < 5 {
        return Err(Error::WeakPassphrase("too few distinct characters"));
    }
    const BANNED: [&str; 8] = [
        "passwordpassword",
        "password1234",
        "qwertyuiop12",
        "letmein12345",
        "123456789012",
        "vaultvault12",
        "correcthorseb",
        "iloveyou1234",
    ];
    let lower = passphrase.to_lowercase();
    if BANNED.iter().any(|b| lower.contains(b)) {
        return Err(Error::WeakPassphrase("too common"));
    }
    // Either a long single token, or at least three words.
    if words < 3 && chars < 20 {
        return Err(Error::WeakPassphrase(
            "use a passphrase of 3+ words or 20+ characters",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "harbor violet tractor cinder";

    #[test]
    fn deterministic_and_split() {
        let salt = Salt::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let a = derive(PW, &salt, KdfParams::test_only_fast()).unwrap();
        let b = derive(PW, &salt, KdfParams::test_only_fast()).unwrap();
        assert_eq!(a.ukek, b.ukek);
        assert_eq!(a.auth_secret, b.auth_secret);
        assert_ne!(a.ukek, a.auth_secret, "halves must be independent");
    }

    #[test]
    fn salt_changes_output() {
        let a = derive(PW, &Salt::random(), KdfParams::test_only_fast()).unwrap();
        let b = derive(PW, &Salt::random(), KdfParams::test_only_fast()).unwrap();
        assert_ne!(a.ukek, b.ukek);
    }

    #[test]
    fn passphrase_changes_output() {
        let salt = Salt::random();
        let a = derive(PW, &salt, KdfParams::test_only_fast()).unwrap();
        let b = derive(
            "harbor violet tractor cindez",
            &salt,
            KdfParams::test_only_fast(),
        )
        .unwrap();
        assert_ne!(a.ukek, b.ukek);
        assert_ne!(a.auth_secret, b.auth_secret);
    }

    #[test]
    fn strength_policy() {
        assert!(check_passphrase_strength("short").is_err());
        assert!(check_passphrase_strength("aaaaaaaaaaaaaaaa").is_err());
        assert!(check_passphrase_strength("password1234").is_err());
        assert!(check_passphrase_strength("harbor violet tractor").is_ok());
        assert!(check_passphrase_strength("a-long-single-token-passphrase").is_ok());
    }

    #[test]
    fn params_version_matches_default() {
        assert_eq!(KdfParams::default().version(), 1);
        assert_eq!(KdfParams::test_only_fast().version(), 0);
    }
}
