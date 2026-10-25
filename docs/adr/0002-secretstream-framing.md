# ADR 0002 — secretstream framing (COOMF1)

**Status:** accepted
**Date:** 2026-10-25

## Context

Video needs in-order chunked encryption where a truncated file is *detectably*
truncated, a reordered chunk is *detectably* reordered, and the reader can start
playing before the whole file has arrived.

`crypto_secretbox` alone gives none of that (no nonce ordering, no final marker).
AES-GCM via WebCrypto would need hand-rolled counter management, which is the
classic catastrophic bug. `crypto_secretstream_xchacha20poly1305` is built for
this: it rekeys per chunk, rejects replays and reorderings, and has an explicit
final tag.

## Decision

**Framing (normative, pinned by `spec/crypto-vectors.json`):**

```
COOMF1                      6 bytes magic
<header>                   24 bytes, from init_push
repeat: u32le ct_len, ct   ct = plaintext chunk + 17
```

- Plaintext chunk size: 4 MiB (`stream::CHUNK_PLAINTEXT`).
- Max ciphertext chunk: 4 MiB + 17.
- Every chunk uses `TAG_MESSAGE` except the last, which uses `TAG_FINAL`.
- A reader that hits EOF without `TAG_FINAL` MUST reject the file. Truncation is
  an attack, not a partial download — a player that plays a prefix silently
  hides it.
- Trailing bytes after the final chunk MUST be rejected.
- Empty files still get exactly one chunk (of zero bytes) carrying `TAG_FINAL`.
- The server enforces the exact ciphertext length for the declared plaintext
  size (`stream::ciphertext_len_for`), so nobody smuggles extra bytes into a
  blob and nobody under-declares to dodge quota.

## Alternatives rejected

- **One big `secretbox` over the whole file:** no streaming, 20 GB of RAM, no
  truncation signal.
- **Per-chunk independent secretbox with random nonces:** ~48 bytes/chunk of
  plaintext-identifiable nonce, no ordering guarantees, no final marker, and the
  client must invent nonce discipline.
- **AES-GCM + WebCrypto counters:** footgun, and slower on cheap Android SoCs.

## Consequences

- 17 bytes of overhead per 4 MiB chunk (0.0004%) plus 30 bytes fixed.
- Seek/range requests need a chunk index; phase 2 adds a sidecar index blob
  (encrypted under the same FEK) for instant `#t=` seek. Until then, a range
  request costs a re-scan from the start, which is fine at these file sizes for
  progressive playback.
- The final-tag rule means the upload body must be complete before `complete` is
  called; a resumable upload (planned) will keep the last chunk until the end.
