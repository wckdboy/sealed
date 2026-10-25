//! Signed, expiring URLs for ciphertext blobs.
//!
//! The CDN in front of the origin sees only ciphertext, so a leaked URL leaks
//! bytes nobody can read. What signatures protect is *bandwidth*: a hotlinked
//! or scraped URL must expire.
//!
//! Token = `HMAC-SHA256(secret, "GET\n<resource>\n<expiry>")`, hex. The secret
//! is per-deployment and rotated by allowing two valid secrets during overlap.

use crate::error::{Error, Result};
use crate::sodium;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const MIN_SECRET_BYTES: usize = 32;
/// Longest URL lifetime we will issue.
pub const MAX_TTL_SECONDS: u64 = 6 * 60 * 60;

#[derive(Clone)]
pub struct Signer {
    secret: Vec<u8>,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Signer(<redacted>)")
    }
}

impl Signer {
    pub fn new(secret: &[u8]) -> Result<Self> {
        if secret.len() < MIN_SECRET_BYTES {
            return Err(Error::InvalidParameter(
                "signing secret must be >= 32 bytes",
            ));
        }
        Ok(Self {
            secret: secret.to_vec(),
        })
    }

    pub fn random() -> Self {
        sodium::init();
        Self {
            secret: sodium::random_bytes(32),
        }
    }

    fn mac(&self, method: &str, resource: &str, expires_at: u64) -> Result<String> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.secret)
            .map_err(|_| Error::InvalidParameter("bad signing secret"))?;
        mac.update(b"vault/url/v1\n");
        mac.update(method.as_bytes());
        mac.update(b"\n");
        mac.update(resource.as_bytes());
        mac.update(b"\n");
        mac.update(expires_at.to_string().as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    /// Sign any origin resource (upload target, download path) for `method`.
    pub fn sign_resource(
        &self,
        method: &str,
        resource: &str,
        expires_at: u64,
    ) -> Result<SignedUrl> {
        let token = self.mac(method, resource, expires_at)?;
        Ok(SignedUrl {
            resource: resource.to_string(),
            expires_at,
            token,
        })
    }

    pub fn verify_resource(
        &self,
        method: &str,
        resource: &str,
        expires_at: u64,
        token: &str,
        now: u64,
    ) -> Result<()> {
        if now > expires_at {
            return Err(Error::AuthFailed);
        }
        if expires_at.saturating_sub(now) > MAX_TTL_SECONDS {
            return Err(Error::InvalidParameter("expiry too far in the future"));
        }
        let expected = self.mac(method, resource, expires_at)?;
        let a = sodium::from_hex(&expected)?;
        let b = sodium::from_hex(token).map_err(|_| Error::AuthFailed)?;
        if sodium::ct_eq(&a, &b) {
            Ok(())
        } else {
            Err(Error::AuthFailed)
        }
    }

    /// Sign a download of `blob_ref` valid until unix `expires_at`.
    pub fn sign_download(&self, blob_ref: &str, expires_at: u64) -> Result<SignedUrl> {
        self.sign_resource("GET", &download_resource(blob_ref), expires_at)
    }

    pub fn verify_download(
        &self,
        blob_ref: &str,
        expires_at: u64,
        token: &str,
        now: u64,
    ) -> Result<()> {
        self.verify_resource("GET", &download_resource(blob_ref), expires_at, token, now)
    }
}

fn download_resource(blob_ref: &str) -> String {
    format!("/v1/blobs/{blob_ref}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedUrl {
    pub resource: String,
    pub expires_at: u64,
    pub token: String,
}

impl SignedUrl {
    /// Path + query, ready to prefix with the origin or CDN host.
    pub fn to_path(&self) -> String {
        format!(
            "{}?exp={}&sig={}",
            self.resource, self.expires_at, self.token
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[test]
    fn roundtrip() {
        let s = Signer::new(SEED).unwrap();
        let url = s.sign_download("abc123", 1_800_000_000).unwrap();
        assert_eq!(url.resource, "/v1/blobs/abc123");
        assert!(s
            .verify_download("abc123", url.expires_at, &url.token, 1_799_999_000)
            .is_ok());
    }

    #[test]
    fn expiry_enforced() {
        let s = Signer::new(SEED).unwrap();
        let url = s.sign_download("abc123", 1_800_000_000).unwrap();
        assert!(s
            .verify_download("abc123", url.expires_at, &url.token, 1_800_000_001)
            .is_err());
    }

    #[test]
    fn wrong_blob_or_token_rejected() {
        let s = Signer::new(SEED).unwrap();
        let url = s.sign_download("abc123", 1_800_000_000).unwrap();
        assert!(s
            .verify_download("abc124", url.expires_at, &url.token, 1_799_999_000)
            .is_err());
        assert!(s
            .verify_download("abc123", url.expires_at, &"0".repeat(64), 1_799_999_000)
            .is_err());
        assert!(s
            .verify_download("abc123", url.expires_at, "zz", 1_799_999_000)
            .is_err());
    }

    #[test]
    fn ttl_cap() {
        let s = Signer::new(SEED).unwrap();
        let now = 1_700_000_000u64;
        let too_far = now + MAX_TTL_SECONDS + 10;
        let url = s.sign_download("abc", too_far).unwrap();
        assert!(s.verify_download("abc", too_far, &url.token, now).is_err());
        let ok = now + MAX_TTL_SECONDS;
        let url = s.sign_download("abc", ok).unwrap();
        assert!(s.verify_download("abc", ok, &url.token, now).is_ok());
    }

    #[test]
    fn other_secret_rejected() {
        let a = Signer::new(SEED).unwrap();
        let b = Signer::random();
        let url = a.sign_download("abc", 1_800_000_000).unwrap();
        assert!(b
            .verify_download("abc", url.expires_at, &url.token, 1_799_999_000)
            .is_err());
    }

    #[test]
    fn short_secret_rejected() {
        assert!(Signer::new(b"short").is_err());
    }
}
