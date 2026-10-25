//! Sealed core.
//!
//! One implementation of every cryptographic and wire-format decision in the
//! Sealed/Sealed system. The Android app (Kotlin + lazysodium) and the PWA
//! (libsodium-wrappers-sumo) are held to this crate by
//! `spec/crypto-vectors.json`, which this crate generates and verifies.
//!
//! Design rules enforced here (see docs/adr):
//!   * One blob format, versioned, parsed by a total function that never panics.
//!   * No hand-rolled primitives: everything is a libsodium construction.
//!   * Every secret is a `Key`: zeroized on drop, redacted in Debug.
//!   * Argon2id parameters live in exactly one place (`kdf::Params`).
//!
//! The server never calls `stream::*` — it stores and serves ciphertext only.
//! Those functions exist for clients, the CLI, and the conformance suite.

pub mod account;
pub mod auth;
pub mod error;
pub mod ids;
pub mod kdf;
pub mod keys;
pub mod recovery;
pub mod screen;
pub mod sign;
pub mod sodium;
pub mod stream;
pub mod wire;

pub use error::{Error, Result};

/// Initialise libsodium. Safe to call many times; the first call wins.
pub fn init() {
    sodium::init();
}
