//! Identifiers and digests.
//!
//! Public identifiers are random, opaque, and prefixed so a stray id in a log
//! or a support paste is self-describing. Nothing is derived from user data.

use crate::sodium;
use sha2::{Digest, Sha256};

/// `f_` + 32 hex chars (128-bit random).
pub fn new_file_id() -> String {
    format!("f_{}", hex::encode(sodium::random_bytes(16)))
}

/// `v_` vault, `s_` share, `p_` post, `t_` thread, `r_` report.
pub fn new_prefixed_id(prefix: &str) -> String {
    format!("{}_{}", prefix, hex::encode(sodium::random_bytes(16)))
}

/// Storage reference for a ciphertext blob. Random: the storage layer learns
/// nothing about ownership from the name.
pub fn new_blob_ref() -> String {
    hex::encode(sodium::random_bytes(20))
}

/// SHA-256 of arbitrary bytes, lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Domain-separated digest of a plaintext file, as sent by the client for
/// screening and dedup. Must match the clients byte for byte.
pub fn plaintext_digest(bytes: &[u8]) -> String {
    let mut h = plaintext_digest_init();
    h.update(bytes);
    plaintext_digest_finalize(h)
}

/// Start a streaming plaintext digest. For clients that cannot hold a whole file in
/// memory: the CLI hashes while it encrypts, in one pass over the source.
pub fn plaintext_digest_init() -> Sha256 {
    let mut h = Sha256::new();
    h.update(b"vault/plaintext-sha256/v1");
    h
}

pub fn plaintext_digest_finalize(h: Sha256) -> String {
    hex::encode(h.finalize())
}

/// Validate a hex SHA-256 as supplied by a client (64 lowercase hex chars).
pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes().all(|b| b.is_ascii_hexdigit())
        && !s.bytes().any(|b| b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn ids_are_unique_and_prefixed() {
        let ids: HashSet<String> = (0..5000).map(|_| new_file_id()).collect();
        assert_eq!(ids.len(), 5000);
        assert!(ids.iter().all(|i| i.starts_with("f_") && i.len() == 34));
        assert_eq!(new_blob_ref().len(), 40);
        assert!(new_prefixed_id("v").starts_with("v_"));
    }

    #[test]
    fn digest_is_domain_separated() {
        // Not just sha256(content): keeps our digests out of generic rainbow
        // tables and makes cross-protocol confusion impossible.
        assert_ne!(plaintext_digest(b"abc"), sha256_hex(b"abc"));
        assert_eq!(plaintext_digest(b"abc"), plaintext_digest(b"abc"));
        assert_ne!(plaintext_digest(b"abc"), plaintext_digest(b"abd"));
    }

    #[test]
    fn digest_hex_validator() {
        let d = sha256_hex(b"abc");
        assert!(is_sha256_hex(&d));
        assert!(!is_sha256_hex(&d.to_uppercase()));
        assert!(!is_sha256_hex("abc"));
        assert!(!is_sha256_hex(&"z".repeat(64)));
    }
}
