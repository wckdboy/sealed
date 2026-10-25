//! Login verifiers and session tokens.
//!
//! The passphrase is never transmitted. The client derives `auth_secret`
//! (see `kdf`) and sends that over TLS; the server stores only
//! `HMAC(pepper, auth_secret || account_number)`.
//!
//! The pepper is the thing that keeps a SQL dump from being an offline
//! passphrase-cracking oracle, so it must not live in the same place as the
//! data: environment variable or KMS entry, backed up separately.

use crate::error::{Error, Result};
use crate::keys::Key;
use crate::sodium;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Minimum pepper length. A short pepper is worse than none because it
/// invites confidence.
pub const MIN_PEPPER_BYTES: usize = 32;

pub fn verifier(pepper: &[u8], auth_secret: &Key, account_number: &str) -> Result<String> {
    if pepper.len() < MIN_PEPPER_BYTES {
        return Err(Error::InvalidParameter("pepper must be >= 32 bytes"));
    }
    let mut mac = <HmacSha256 as Mac>::new_from_slice(pepper)
        .map_err(|_| Error::InvalidParameter("bad pepper"))?;
    mac.update(b"vault/auth-verifier/v1");
    mac.update(auth_secret.as_bytes());
    mac.update(account_number.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Constant-time verifier comparison.
pub fn verify(
    pepper: &[u8],
    auth_secret: &Key,
    account_number: &str,
    stored_hex: &str,
) -> Result<bool> {
    let expected_hex = verifier(pepper, auth_secret, account_number)?;
    let stored = sodium::from_hex(stored_hex)?;
    let expected = sodium::from_hex(&expected_hex)?;
    Ok(sodium::ct_eq(&stored, &expected))
}

/// 32 random bytes, hex. Bearer token for API sessions.
pub fn new_session_token() -> String {
    hex::encode(sodium::random_bytes(32))
}

/// What we store: the hash, so a database read does not yield live sessions.
pub fn token_hash(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"vault/session-token/v1");
    h.update(token.as_bytes());
    hex::encode(h.finalize())
}

/// Short, human-shareable download token (not a session, never a key).
pub fn new_short_token(len: usize) -> String {
    let alphabet = b"23456789abcdefghjkmnpqrstuvwxyz";
    let bytes = sodium::random_bytes(len);
    bytes
        .iter()
        .map(|b| alphabet[(*b as usize) % alphabet.len()] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEPPER: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[test]
    fn verifier_is_stable_and_bound_to_account() {
        let secret = Key::random();
        let a = verifier(PEPPER, &secret, "482739105642").unwrap();
        let b = verifier(PEPPER, &secret, "482739105642").unwrap();
        let c = verifier(PEPPER, &secret, "482739105643").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(verify(PEPPER, &secret, "482739105642", &a).unwrap());
        assert!(!verify(PEPPER, &secret, "482739105642", &c).unwrap());
    }

    #[test]
    fn pepper_matters() {
        let secret = Key::random();
        let a = verifier(PEPPER, &secret, "482739105642").unwrap();
        let other: &[u8] = b"ffffffffffffffffffffffffffffffff";
        assert_ne!(a, verifier(other, &secret, "482739105642").unwrap());
        assert!(!verify(other, &secret, "482739105642", &a).unwrap());
    }

    #[test]
    fn short_pepper_rejected() {
        assert!(verifier(b"short", &Key::random(), "1").is_err());
    }

    #[test]
    fn malformed_stored_verifier_is_error_not_panic() {
        let secret = Key::random();
        assert!(verify(PEPPER, &secret, "1", "not-hex").is_err());
        assert!(!verify(PEPPER, &secret, "1", "").unwrap());
    }

    #[test]
    fn tokens_are_unique_and_hashed() {
        let t1 = new_session_token();
        let t2 = new_session_token();
        assert_ne!(t1, t2);
        assert_eq!(t1.len(), 64);
        assert_ne!(token_hash(&t1), token_hash(&t2));
        assert_ne!(token_hash(&t1), t1);
        let short = new_short_token(9);
        assert_eq!(short.len(), 9);
        assert!(short.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
