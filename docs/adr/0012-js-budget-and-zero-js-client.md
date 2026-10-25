# ADR 0012 — JS budget: lazy crypto in the browser, a zero-JS CLI alongside

**Status:** accepted
**Date:** 2026-10-25

## Context

Decryption in a browser *is* JavaScript (or WASM). A page with scripting disabled
cannot unwrap a key, so "no JS" is impossible for the web client by construction —
the honest question is how much script ships before the user does anything, and
what a no-script client looks like.

The first build was a single 1,048 kB bundle (328 kB gzip), of which ~1,040 kB was
libsodium-sumo, loaded on first paint to render a form that mostly formats a
16-digit number.

## Decision

1. **Split pure code from crypto code.** `web/src/codec.ts` (hex, Damm check digit,
   account formatting, chunk arithmetic) has no imports beyond itself;
   `web/src/crypto.ts` holds everything that needs libsodium and re-exports codec
   for tests.
2. **Load crypto on demand.** The UI imports `codec` statically and calls
   `import('./crypto')` at the first cryptographic action (signup, unlock, upload,
   play). Measured: initial JS 12.1 kB (5.1 kB gzip), crypto chunk 1,040 kB
   (324 kB gzip) fetched once, cached thereafter.
3. **Ship a zero-JS client.** `crates/vault-cli` (`vault`) speaks the same protocol
   with the same `vault-core`: signup, login, gate, put, ls, cat, get. `vault cat
   f_… | mpv -` is a complete video player with no script anywhere. The passphrase
   is never stored; only a 0600 session token is; the UKEK is re-derived per command.
4. **Say it in the page.** `<noscript>` explains why one script is required and
   points at the CLI. No pretending the web client works without script.

## Alternatives rejected

- **Server-side encryption/decryption.** Destroys the product claim; the server
  would hold keys.
- **Re-implementing `secretstream`/`secretbox` in RustCrypto for a wasm-only core.**
  Byte-compatibility with libsodium would have to be reproduced by hand — exactly
  the "invent your own scheme" failure this project forbids (ADR 0001).
- **Compiling libsodium to wasm now.** Needs emscripten or zig plus a wasm libc;
  `libsodium-sys-stable`'s wasm path calls `zig build` on libsodium's own
  `build.zig`, which the vendored release tarball does not ship. Real work, and not
  on the critical path while the JS mirror passes the same conformance vectors.
  This is the phase-3 revisit in ADR 0001, unchanged.

## Consequences

- Slow devices, metered links and strict-CSP deployments get a 5 kB first paint.
- Two crypto implementations remain (Rust + JS), which is exactly why
  `spec/crypto-vectors.json` and the two-way interop test exist.
- The CLI is the audit-friendly path: one libsodium binding, no JS, no browser, and
  it exercises the same server contract (`crates/vault-cli/tests/e2e.rs` drives the
  real API in-process).
- A wasm single-core build remains the only way to delete the JS mirror, and its
  precondition (toolchain + libsodium build) is documented rather than hand-waved.
