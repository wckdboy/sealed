//! 32-byte symmetric keys, wrapped keys, and the `CWRP` envelope.
//!
//! Two envelopes exist and they are deliberately different byte layouts so a
//! blob can never be mistaken for the other:
//!
//! * `CWRP` — a wrapped key (FEK under UKEK, PKEK, or a share passphrase).
//! * `COOMF1` — a secretstream file body (see `stream`).

use crate::error::{Error, Result};
use crate::sodium;
use libsodium_sys as sodium_sys;
use sha2::{Digest, Sha256};
use std::fmt;

pub const KEY_BYTES: usize = 32;

const WRAP_MAGIC: [u8; 4] = *b"CWRP";
const WRAP_VERSION: u8 = 1;
/// magic(4) + version(1) + nonce(24)
const WRAP_HEADER: usize = 4 + 1 + 24;
/// secretbox_MACBYTES
const WRAP_TAG: usize = 16;

/// A 32-byte symmetric key. Zeroized on drop, redacted when printed.
#[derive(Clone, PartialEq, Eq)]
pub struct Key([u8; KEY_BYTES]);

impl Key {
    pub fn random() -> Self {
        sodium::init();
        Self(sodium::random_array::<KEY_BYTES>())
    }

    pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; KEY_BYTES] = bytes
            .try_into()
            .map_err(|_| Error::InvalidParameter("key must be 32 bytes"))?;
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        Self::from_slice(&sodium::from_hex(s)?)
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        sodium::memzero(&mut self.0);
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key(<redacted>)")
    }
}

/// Wrap `target` under `kek` with XSalsa20-Poly1305 (`crypto_secretbox_easy`).
///
/// Layout: `CWRP | ver | nonce(24) | ciphertext(32 + 16)`.
pub fn wrap_key(kek: &Key, target: &Key) -> Result<Vec<u8>> {
    wrap_bytes(kek, target.as_bytes())
}

/// Unwrap a key blob produced by [`wrap_key`].
pub fn unwrap_key(kek: &Key, blob: &[u8]) -> Result<Key> {
    let plain = unwrap_bytes(kek, blob)?;
    Key::from_slice(&plain)
}

/// Wrap arbitrary short metadata (thumbnails headers, share envelopes).
/// Capped at 64 KiB so the envelope stays a "key box", not a data channel.
pub fn wrap_bytes(kek: &Key, plaintext: &[u8]) -> Result<Vec<u8>> {
    if plaintext.is_empty() {
        return Err(Error::Empty);
    }
    if plaintext.len() > 64 * 1024 {
        return Err(Error::InvalidParameter(
            "wrap_bytes payload capped at 64 KiB",
        ));
    }
    sodium::init();

    let nonce: [u8; 24] = sodium::random_array();
    let mut out = Vec::with_capacity(WRAP_HEADER + plaintext.len() + WRAP_TAG);
    out.extend_from_slice(&WRAP_MAGIC);
    out.push(WRAP_VERSION);
    out.extend_from_slice(&nonce);

    let mut ct = vec![0u8; plaintext.len() + WRAP_TAG];
    let rc = unsafe {
        sodium_sys::crypto_secretbox_easy(
            ct.as_mut_ptr(),
            plaintext.as_ptr(),
            plaintext.len() as u64,
            nonce.as_ptr(),
            kek.as_bytes().as_ptr(),
        )
    };
    if rc != 0 {
        return Err(Error::AuthFailed);
    }
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a `CWRP` envelope.
pub fn unwrap_bytes(kek: &Key, blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < WRAP_HEADER + WRAP_TAG {
        return Err(Error::MalformedBlob);
    }
    if blob[..4] != WRAP_MAGIC {
        return Err(Error::MalformedBlob);
    }
    if blob[4] != WRAP_VERSION {
        return Err(Error::UnsupportedVersion {
            found: blob[4],
            expected: WRAP_VERSION,
        });
    }
    let nonce: &[u8] = &blob[5..29];
    let ct = &blob[WRAP_HEADER..];
    let mut plain = vec![0u8; ct.len() - WRAP_TAG];

    let rc = unsafe {
        sodium_sys::crypto_secretbox_open_easy(
            plain.as_mut_ptr(),
            ct.as_ptr(),
            ct.len() as u64,
            nonce.as_ptr(),
            kek.as_bytes().as_ptr(),
        )
    };
    if rc != 0 {
        return Err(Error::AuthFailed);
    }
    Ok(plain)
}

/// Length of a `CWRP` blob holding one 32-byte key. Handy for size assertions.
pub const WRAPPED_KEY_LEN: usize = WRAP_HEADER + KEY_BYTES + WRAP_TAG;

/// Wrap with an explicit nonce. Only for deterministic conformance vectors —
/// never call this in production paths, it destroys secretbox's guarantees.
#[doc(hidden)]
pub fn wrap_key_with_nonce(kek: &Key, target: &Key, nonce: &[u8; 24]) -> Result<Vec<u8>> {
    sodium::init();
    let mut out = Vec::with_capacity(WRAPPED_KEY_LEN);
    out.extend_from_slice(&WRAP_MAGIC);
    out.push(WRAP_VERSION);
    out.extend_from_slice(nonce);
    let mut ct = vec![0u8; KEY_BYTES + WRAP_TAG];
    let rc = unsafe {
        sodium_sys::crypto_secretbox_easy(
            ct.as_mut_ptr(),
            target.as_bytes().as_ptr(),
            KEY_BYTES as u64,
            nonce.as_ptr(),
            kek.as_bytes().as_ptr(),
        )
    };
    if rc != 0 {
        return Err(Error::AuthFailed);
    }
    out.extend_from_slice(&ct);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let kek = Key::random();
        let fek = Key::random();
        let blob = wrap_key(&kek, &fek).unwrap();
        assert_eq!(blob.len(), WRAPPED_KEY_LEN);
        assert_eq!(&blob[..4], b"CWRP");
        assert_eq!(unwrap_key(&kek, &blob).unwrap(), fek);
    }

    #[test]
    fn wrong_key_fails() {
        let kek = Key::random();
        let blob = wrap_key(&kek, &Key::random()).unwrap();
        assert_eq!(unwrap_key(&Key::random(), &blob), Err(Error::AuthFailed));
    }

    #[test]
    fn bitflip_fails() {
        let kek = Key::random();
        let mut blob = wrap_key(&kek, &Key::random()).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert_eq!(unwrap_key(&kek, &blob), Err(Error::AuthFailed));
    }

    #[test]
    fn truncated_and_foreign_blobs_fail() {
        let kek = Key::random();
        let blob = wrap_key(&kek, &Key::random()).unwrap();
        assert_eq!(unwrap_key(&kek, &blob[..10]), Err(Error::MalformedBlob));
        let mut other = blob.clone();
        other[0] = b'X';
        assert_eq!(unwrap_key(&kek, &other), Err(Error::MalformedBlob));
        let mut newer = blob.clone();
        newer[4] = 9;
        assert_eq!(
            unwrap_key(&kek, &newer),
            Err(Error::UnsupportedVersion {
                found: 9,
                expected: 1
            })
        );
    }

    #[test]
    fn key_is_redacted() {
        let k = Key::random();
        assert_eq!(format!("{k:?}"), "Key(<redacted>)");
        assert_eq!(Key::from_hex(&k.to_hex()).unwrap(), k);
    }
}

/// Derive the 32-byte portal key from arbitrary secret material.
///
/// The portal key wraps FEKs for public content, so `crypto_secretbox` requires
/// exactly 32 bytes. A secret manager (Coolify's `SERVICE_PASSWORD_64_*`, Doppler,
/// Infisical) hands out long alphanumeric strings, not 32-byte hex; hashing with a
/// domain separator turns any such value into a stable key without inventing a
/// scheme or truncating entropy. Deterministic: same input, same key, forever.
pub fn derive_portal_key(material: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"vault/portal-key/v1");
    hasher.update(material);
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

#[cfg(test)]
mod portal_derivation_tests {
    use super::*;

    #[test]
    fn derivation_is_stable_and_separated() {
        let material = b"qG7hkL9mpQ2rT4vXw8BnP6sYd...64 chars of alphanumeric secret";
        let a = derive_portal_key(material);
        let b = derive_portal_key(material);
        assert_eq!(a, b, "same input must give the same key");
        assert_eq!(a.len(), 32);

        // Domain separation: derivations must not collide with a plain SHA-256 of
        // the same material (which is what an ad-hoc `sha256(secret)` would give).
        let mut plain = Sha256::new();
        plain.update(material);
        assert_ne!(a.to_vec(), plain.finalize().to_vec());

        assert_ne!(a, derive_portal_key(b"another secret"));
    }
}
