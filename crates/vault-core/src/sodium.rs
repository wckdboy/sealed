//! Thin, auditable wrappers over the handful of libsodium calls we allow.
//!
//! Everything unsafe in this crate is in this file or in `keys`/`stream`/`kdf`
//! next to the FFI call it wraps. Nothing here parses untrusted input.

use core::ffi::c_void;
use libsodium_sys as sodium;
use std::sync::Once;

static INIT: Once = Once::new();

pub fn init() {
    INIT.call_once(|| {
        // sodium_init() returns 1 on first init, 0 if already done, < 0 on error.
        let rc = unsafe { sodium::sodium_init() };
        assert!(rc >= 0, "libsodium sodium_init() failed: {rc}");
    });
}

/// Cryptographically secure random bytes.
pub fn random_bytes(len: usize) -> Vec<u8> {
    init();
    let mut out = vec![0u8; len];
    if len > 0 {
        unsafe { sodium::randombytes_buf(out.as_mut_ptr() as *mut c_void, len) };
    }
    out
}

pub fn random_array<const N: usize>() -> [u8; N] {
    init();
    let mut out = [0u8; N];
    if N > 0 {
        unsafe { sodium::randombytes_buf(out.as_mut_ptr() as *mut c_void, N) };
    }
    out
}

/// Constant-time comparison. Length mismatch is public information.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Best-effort zeroing that the optimiser may not elide.
pub fn memzero(buf: &mut [u8]) {
    init();
    if !buf.is_empty() {
        unsafe { sodium::sodium_memzero(buf.as_mut_ptr() as *mut c_void, buf.len()) };
    }
}

/// Decode lowercase/uppercase hex without pulling in a dependency at call sites.
pub fn from_hex(s: &str) -> crate::Result<Vec<u8>> {
    hex::decode(s).map_err(|e| crate::Error::BadHex(e.to_string()))
}

pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}
