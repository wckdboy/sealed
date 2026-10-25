//! Wire types shared by the API and both clients.
//!
//! Everything here is public (it crosses the network), so it is plain serde with
//! `snake_case` field names, and every request has a `validate()` that runs
//! before the handler touches the database. The API is versioned by path
//! prefix (`/v1`), not by payload negotiation.

use serde::{Deserialize, Serialize};

/// Bytes in a gigabyte as we sell it (10^9), matching consumer expectations and
/// the price sheet in docs/MASTER-PLAN.md.
pub const GB: u64 = 1_000_000_000;
pub const TB: u64 = 1_000 * GB;

/// Largest single upload we accept (a 4K feature at high bitrate fits).
pub const MAX_UPLOAD_BYTES: u64 = 20 * GB;
/// Largest thumbnail blob.
pub const MAX_THUMB_BYTES: u64 = 512 * 1024;
/// Longest accepted MIME type string.
pub const MAX_MIME_LEN: usize = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    /// FEK wrapped by UKEK only. Owner-only, unreadable by the server.
    Private,
    /// FEK wrapped by UKEK and PKEK. Streamable by any 18+-gated session.
    Public,
    /// FEK wrapped by UKEK and by a share passphrase. Server never holds the
    /// share passphrase; the blob is handed to the client to unwrap.
    Passphrase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WrapType {
    /// Wrapped under the owner's UKEK.
    User,
    /// Wrapped under the portal key (public files only).
    Portal,
    /// Wrapped under Argon2id(share passphrase) (passphrase files only).
    Passphrase,
}

/// One `CWRP` envelope, hex-encoded, as stored in `file_keys`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKey {
    pub wrap_type: WrapType,
    pub blob: String,
}

impl WrappedKey {
    /// A wrapped 32-byte key is exactly 77 bytes: CWRP|ver|nonce|ct(32+16).
    pub const HEX_LEN: usize = 77 * 2;

    pub fn is_well_formed(&self) -> bool {
        self.blob.len() == Self::HEX_LEN
            && self.blob.bytes().all(|b| b.is_ascii_hexdigit())
            && self.blob.starts_with("43575250") // "CWRP"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Free: browse, organise, forum. No upload, no download.
    Basic,
    /// 1 TB, $3-10/mo.
    Premium1,
    /// 5 TB, $10-30/mo.
    Premium2,
    /// Early-promo lifetime, capped at the tier-1 quota.
    Lifetime,
}

impl Tier {
    pub fn quota_bytes(self) -> u64 {
        match self {
            Tier::Basic => 0,
            Tier::Premium1 | Tier::Lifetime => TB,
            Tier::Premium2 => 5 * TB,
        }
    }

    pub fn can_upload(self) -> bool {
        self.quota_bytes() > 0
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Basic => "basic",
            Tier::Premium1 => "premium1",
            Tier::Premium2 => "premium2",
            Tier::Lifetime => "lifetime",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "basic" => Some(Tier::Basic),
            "premium1" => Some(Tier::Premium1),
            "premium2" => Some(Tier::Premium2),
            "lifetime" => Some(Tier::Lifetime),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    /// Upload accepted, waiting for body.
    Pending,
    /// Blob stored, screening passed, playable.
    Ready,
    /// Matched a bad-hash list or reported: frozen for legal hold. Never served.
    Quarantined,
    /// Removed after a valid complaint or by owner.
    Dead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    SealedAndroid,
    SealedWeb,
    Cli,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountCreateRequest {
    /// 16-byte client-generated Argon2 salt, hex.
    pub kdf_salt: String,
    /// 32-byte auth secret derived from the passphrase, hex. Server keeps only
    /// `HMAC(pepper, auth_secret || account_number)`.
    pub auth_secret: String,
    /// `CWRP` envelope of the UKEK under the recovery phrase, hex.
    pub recovery_blob: String,
    #[serde(default)]
    pub kdf_version: Option<u8>,
    pub client: ClientKind,
}

impl AccountCreateRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.kdf_salt.len() != 32 || !self.kdf_salt.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("kdf_salt must be 16 bytes of hex");
        }
        if self.auth_secret.len() != 64 || !self.auth_secret.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("auth_secret must be 32 bytes of hex");
        }
        if !self.recovery_blob.starts_with("43575250")
            || self.recovery_blob.len() != WrappedKey::HEX_LEN
        {
            return Err("recovery_blob must be a CWRP envelope");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountCreateResponse {
    /// Human form, "4827 3910 5642". Also returned as bare digits in `digits`.
    pub account_number: String,
    pub digits: String,
    pub fingerprint: String,
    pub recovery_acknowledged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthPrepareRequest {
    pub account_number: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthPrepareResponse {
    pub kdf_salt: String,
    pub kdf_ops: u64,
    pub kdf_mem_bytes: u64,
    pub kdf_version: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthRequest {
    pub account_number: String,
    pub auth_secret: String,
}

impl AuthRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.auth_secret.len() != 64 || !self.auth_secret.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("auth_secret must be 32 bytes of hex");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub expires_at: i64,
    pub tier: Tier,
    pub storage_used: u64,
    pub storage_quota: u64,
    pub gate_passed: bool,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileInitRequest {
    /// Plaintext length. The server enforces quota against this and against the
    /// bytes actually uploaded; the two must agree.
    pub size: u64,
    /// Domain-separated SHA-256 of the plaintext, lowercase hex (ids::plaintext_digest).
    pub plaintext_digest: String,
    pub mime: String,
    #[serde(default)]
    pub duration_ms: Option<u64>,
    pub visibility: Visibility,
    /// One `User` entry always; plus `Portal` for public, `Passphrase` for
    /// passphrase.
    pub keys: Vec<WrappedKey>,
    #[serde(default)]
    pub thumb_bytes: Option<u64>,
}

impl FileInitRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.size == 0 {
            return Err("size must be > 0");
        }
        if self.size > MAX_UPLOAD_BYTES {
            return Err("file exceeds maximum upload size");
        }
        if !crate::ids::is_sha256_hex(&self.plaintext_digest) {
            return Err("plaintext_digest must be lowercase sha256 hex");
        }
        if self.mime.is_empty() || self.mime.len() > MAX_MIME_LEN {
            return Err("mime is empty or too long");
        }
        // We only ever carry video and image payloads. Anything else is either a
        // mistake or an attempt to use the vault as generic file storage.
        if !(self.mime.starts_with("video/") || self.mime.starts_with("image/")) {
            return Err("mime must be video/* or image/*");
        }
        if let Some(t) = self.thumb_bytes {
            if t > MAX_THUMB_BYTES {
                return Err("thumbnail too large");
            }
        }
        for k in &self.keys {
            if !k.is_well_formed() {
                return Err("wrapped key is not a CWRP envelope");
            }
        }
        let has = |t: WrapType| self.keys.iter().any(|k| k.wrap_type == t);
        if !has(WrapType::User) {
            return Err("missing user-wrapped key");
        }
        match self.visibility {
            Visibility::Private => {
                if has(WrapType::Portal) {
                    return Err("private files must not carry a portal wrap");
                }
            }
            Visibility::Public => {
                if !has(WrapType::Portal) {
                    return Err("public files require a portal-wrapped key");
                }
            }
            Visibility::Passphrase => {
                if !has(WrapType::Passphrase) {
                    return Err("passphrase files require a passphrase-wrapped key");
                }
                if has(WrapType::Portal) {
                    return Err("passphrase files must not carry a portal wrap");
                }
            }
        }
        if self.keys.len()
            != self
                .keys
                .iter()
                .map(|k| k.wrap_type)
                .collect::<std::collections::HashSet<_>>()
                .len()
        {
            return Err("duplicate wrap types");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedUpload {
    /// e.g. `/v1/files/f_ab12/blob`
    pub path: String,
    pub expires_at: i64,
    pub token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileInitResponse {
    pub file_id: String,
    pub blob_ref: String,
    pub status: FileStatus,
    pub upload: SignedUpload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSummary {
    pub file_id: String,
    pub mime: String,
    pub size: u64,
    pub duration_ms: Option<u64>,
    pub visibility: Visibility,
    pub status: FileStatus,
    pub created_at: i64,
    pub view_count: u64,
    pub thumb_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileListResponse {
    pub files: Vec<FileSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyResponse {
    pub file_id: String,
    pub keys: Vec<WrappedKey>,
}

/// What a guest needs to stream a public file: the portal-wrapped FEK and
/// signed blob URLs. Deliberately contains no owner information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicManifest {
    pub file_id: String,
    pub mime: String,
    pub size: u64,
    pub duration_ms: Option<u64>,
    pub created_at: i64,
    pub view_count: u64,
    /// Hex `CWRP` envelope (wrap_type = portal).
    pub portal_key: String,
    #[serde(default)]
    pub thumb_ref: Option<String>,
    pub blob: SignedUpload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateRequest {
    /// Set true only after the client has shown the interstitial and the user
    /// confirmed 18+ and the ToS. Stored, timestamped, and rate limited.
    pub confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateResponse {
    pub gate_passed: bool,
    pub gate_at: i64,
    /// Hex portal key (PKEK) material for clients that need to wrap public
    /// uploads. Only released to gated, upload-capable sessions.
    #[serde(default)]
    pub portal_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeResponse {
    pub fingerprint: String,
    pub account_number: String,
    pub tier: Tier,
    pub storage_used: u64,
    pub storage_quota: u64,
    pub gate_passed: bool,
    pub created_at: i64,
    pub strikes: u32,
    pub ban_flag: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportRequest {
    pub file_id: String,
    /// Free-form category; validated against a fixed allowlist server-side.
    pub reason: String,
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportResponse {
    pub report_id: String,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ack {
    pub ok: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrap(t: WrapType) -> WrappedKey {
        WrappedKey {
            wrap_type: t,
            blob: format!("43575250{}", "0".repeat(WrappedKey::HEX_LEN - 8)),
        }
    }

    fn req(vis: Visibility, keys: Vec<WrappedKey>) -> FileInitRequest {
        FileInitRequest {
            size: 1024,
            plaintext_digest: crate::ids::plaintext_digest(b"x"),
            mime: "video/mp4".into(),
            duration_ms: Some(1000),
            visibility: vis,
            keys,
            thumb_bytes: Some(1000),
        }
    }

    #[test]
    fn valid_private_public_passphrase() {
        assert!(req(Visibility::Private, vec![wrap(WrapType::User)])
            .validate()
            .is_ok());
        assert!(req(
            Visibility::Public,
            vec![wrap(WrapType::User), wrap(WrapType::Portal)]
        )
        .validate()
        .is_ok());
        assert!(req(
            Visibility::Passphrase,
            vec![wrap(WrapType::User), wrap(WrapType::Passphrase)]
        )
        .validate()
        .is_ok());
    }

    #[test]
    fn under_wrapped_requests_rejected() {
        // The whole point of the matrix: a private file with only a portal wrap
        // would be readable by the server. Refuse to store it.
        assert!(req(Visibility::Private, vec![wrap(WrapType::Portal)])
            .validate()
            .is_err());
        assert!(req(Visibility::Public, vec![wrap(WrapType::User)])
            .validate()
            .is_err());
        assert!(req(Visibility::Passphrase, vec![wrap(WrapType::User)])
            .validate()
            .is_err());
        assert!(req(
            Visibility::Private,
            vec![wrap(WrapType::User), wrap(WrapType::User)]
        )
        .validate()
        .is_err());
    }

    #[test]
    fn limits_enforced() {
        let mut r = req(Visibility::Private, vec![wrap(WrapType::User)]);
        r.size = 0;
        assert!(r.validate().is_err());
        r.size = MAX_UPLOAD_BYTES + 1;
        assert!(r.validate().is_err());
        r.size = 10;
        r.mime = "application/zip".into();
        assert!(r.validate().is_err());
        r.mime = "video/mp4".into();
        r.plaintext_digest = crate::ids::sha256_hex(b"raw"); // missing domain prefix is fine format-wise
        assert!(r.validate().is_ok());
        r.plaintext_digest = "ABC".into();
        assert!(r.validate().is_err());
    }

    #[test]
    fn wrapped_key_shape() {
        assert!(wrap(WrapType::User).is_well_formed());
        let mut bad = wrap(WrapType::User);
        bad.blob = "00".into();
        assert!(!bad.is_well_formed());
    }

    #[test]
    fn tiers() {
        assert!(!Tier::Basic.can_upload());
        assert_eq!(Tier::Premium1.quota_bytes(), TB);
        assert_eq!(Tier::Premium2.quota_bytes(), 5 * TB);
        assert_eq!(Tier::parse("premium2"), Some(Tier::Premium2));
        assert_eq!(Tier::parse("nope"), None);
    }
}
