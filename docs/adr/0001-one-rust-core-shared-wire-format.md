# ADR 0001 — One Rust core defines the wire format; clients conform via vectors

**Status:** accepted
**Date:** 2026-10-25

## Context

The master plan's rule #1 is "one shared library, one implementation, both
platforms". The plan proposes libsodium on Android (JNI) and libsodium.js (WASM)
in the browser, which is *one primitive library* but necessarily *two
implementations of every byte layout*: the framing, the envelope, the KDF split,
the digest domain separation, the account-number format.

Two implementations of a byte layout drift. Silently. The failure mode is the
worst one in this product: a file encrypted on the phone that the web app cannot
open, discovered years later when the phone is gone.

Compiling the Rust core to WASM was considered and rejected for now:
`libsodium-sys` does not cross-compile to `wasm32-unknown-unknown` without an
emscripten/wasi-sdk toolchain in the build, and that adds a heavyweight build
dependency to a project whose first job is to ship. Revisit in phase 2 if the
conformance burden grows.

## Decision

1. `crates/vault-core` is the single normative implementation of every format
   and every derivation.
2. It emits `spec/crypto-vectors.json` (`cargo run -p vault-core --bin vecgen`).
   Deterministic primitives are byte-pinned; the secretstream vector is a
   committed ciphertext that other implementations must *read*.
3. Every other implementation must pass the vectors:
   - web: `web/src/conformance.test.ts` (14 tests)
   - android: same vectors, same assertions (test file to be added with the APK)
4. The reverse direction is also tested: `web` writes a blob it produced, and
   `crates/vault-core/tests/interop_js.rs` decrypts it. CI enforces the order.
5. `vecgen --check` fails the build if the committed vectors no longer match the
   code.

## Consequences

- A format change is a three-file change (core, vectors, JS) and the test suite
  refuses to let them land out of sync.
- The browser carries a hand-written implementation of ~250 lines. That is the
  cost; it is small, pure, and covered end-to-end against a real server
  (`web/src/live.test.ts`).
- Kotlin will carry a third. It will be written against the same vectors, not
  against the JS.
