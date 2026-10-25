use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("blob is truncated or has a bad magic")]
    MalformedBlob,
    #[error("blob version {found} is not supported (expected {expected})")]
    UnsupportedVersion { found: u8, expected: u8 },
    #[error("chunk is larger than the framing allows")]
    ChunkTooLarge,
    #[error("authentication failed: wrong key, wrong blob, or tampering")]
    AuthFailed,
    #[error("stream ended before the final chunk")]
    TruncatedStream,
    #[error("data after the final chunk")]
    TrailingData,
    #[error("empty payload")]
    Empty,
    #[error("bad account number: {0}")]
    BadAccountNumber(&'static str),
    #[error("bad recovery phrase: {0}")]
    BadRecoveryPhrase(&'static str),
    #[error("passphrase too weak: {0}")]
    WeakPassphrase(&'static str),
    #[error("invalid hex: {0}")]
    BadHex(String),
    #[error("kdf failure (out of memory, or parameters rejected)")]
    KdfFailure,
    #[error("invalid parameter: {0}")]
    InvalidParameter(&'static str),
}
