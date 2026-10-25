# Roadmap — what exists, what does not

Phase 0 is the only phase with code today. Everything below is written so that
"done" is checkable, not so it sounds good.

## Phase 0 — MVP (in progress)

| Item | State | Evidence |
|---|---|---|
| Anonymous 16-digit accounts + recovery phrase | **done** | `core::account`, `core::recovery`, `POST /v1/accounts` |
| UKEK/auth split, Argon2id, pepper verifier | **done** | `core::kdf`, `core::auth`, ADR 0004 |
| Session tokens, lockout, enumeration resistance | **done** | `routes/accounts.rs`, tests `wrong_passphrase_and_lockout` |
| 18+ gate + portal key release | **done** | `POST /v1/gate`, `routes/files.rs::public_manifest` |
| File init → signed upload → complete | **done** | `routes/files.rs`, 10 API integration tests |
| Exact ciphertext-length enforcement | **done** | `stream::ciphertext_len_for`, `oversized_body...` test |
| Wrap matrix validation (no under-wrapped files) | **done** | `FileInitRequest::validate` |
| Hash screening + auto-quarantine | **done** | `core::screen`, `hash_match_blocks_upload_and_bans` |
| Community reports → immediate quarantine | **done** | `routes/misc.rs::report` |
| Web PWA: signup, unlock, encrypt, upload, stream | **done** | `web/src/main.ts`, `web/src/live.test.ts` |
| Cross-implementation conformance (Rust ↔ JS) | **done** | `spec/crypto-vectors.json`, 14 JS tests + 1 Rust interop test |
| Zero-JS CLI client (signup, login, put, ls, cat, get) | **done** | `crates/vault-cli`, 2 end-to-end tests against the real API; `vault cat f_… \| mpv -` verified byte-identical round trip |
| Web JS budget (12 kB first paint, libsodium lazy-loaded) | **done** | ADR 0012, measured in `npm run build` |
| Android APK | **scaffold only** | `android/` — not compiled here (no JDK/SDK in this container) |
| Shared/public streaming by a second account | **done** | `live.test.ts` (`stranger` streams via PKEK) |
| Payments (XMR / vouchers) | **not started** | tier is set by `VAULT_DEFAULT_TIER` or SQL |
| Thumbnails | **schema only** | `files.thumb_ref` + `MAX_THUMB_BYTES` validation |
| Passphrase shares | **schema only** | `shares` table, `POST /v1/files/:id/share` not implemented |
| Vaults / playlists | **not started** | — |
| Chat / forum | **not started** | deliberately after phase 2 |

Exit criteria for phase 0: "it works and it's private" — met on the web path,
pending on Android.

## Phase 0.5 — the boring things that must land before real users

1. **Rate limiting by IP** on `/v1/auth/prepare` and `/v1/auth` (currently only
   per-account lockout; an attacker can spray account numbers). Cheap: token
   bucket in a `rate_limits` table or in-process map + `X-Forwarded-For` from Bunny.
2. **Resumable uploads** (chunked PUT with offset), because a 4 GB upload over a
   phone connection fails today and there is no retry.
3. **Range requests** on `/v1/blobs/:ref` (needs the chunk index sidecar) so the
   player can seek without re-downloading.
4. **Hash-list reload without restart** + a signed-feed fetcher for NCMEC/Thorn.
5. **Passphrase shares** (`POST /v1/files/:id/share`): store `passphrase_salt`,
   return a share id, serve `GET /v1/s/:id` with the passphrase-wrapped FEK.
6. **Thumbnails**: second blob per file, encrypted with the same FEK, served under
   the same signature rules.
7. **Pepper/PKEK rotation tooling** (operationally documented, not yet coded).
8. **Backups + restore drill** automated.

## Phase 1 — public site

- PWA public feed with 18+ interstitial, guest streaming via PKEK.
- Payments: XMR (own node or BTCPay-style invoice), vouchers; tier upgrade flips
  `accounts.tier` + `storage_quota`.
- Download for premium (decrypted at the client, never at the server).
- Audit: one external review of `vault-core` + the JS mirror before growth.

Exit: 25 paying users.

## Phase 2 — community

- Forum + chat (separate datastore, see ADR 0007).
- Uploader channels, RSS, favorites, vaults.
- Async fuzzy hash matching (SSDeep/PhotoDNA robust) on reported files.
- Mod preview tooling for public files (PKEK), with an audit trail per preview.

Exit: DAU retention > login count.

## Phase 3 — ecosystem

- Sealed as universal viewer (Bunkr/Gofile/Pixeldrain links in one library).
- On-device CLIP tagging (tags only, no frames).
- Dedup/refcounting by ciphertext hash.
- Cover traffic / padding if traffic analysis matters.
- Revisit compiling `vault-core` to WASM to collapse the JS mirror (ADR 0001).

## Explicitly not planned

- Cloudflare anywhere (plan §4).
- Server-side transcoding (it would require plaintext; if it becomes necessary,
  it becomes a *client* feature).
- Email, phone, or any PII at signup.
- Keyword search over content. Filenames and client-supplied tags only.
