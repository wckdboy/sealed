# ADR 0004 — Auth: UKEK/auth split, server-side pepper, no passphrase on the wire

**Status:** accepted
**Date:** 2026-10-25

## Context

The plan says "passphrase never sent to the server" and also
`Login(account_number, passphrase) → session`. Those cannot both be literal: the
server has to authenticate *something*.

There is also a subtler trap. The server necessarily stores wrapped FEKs
(`file_keys.wrapped_fek`, wrap_type = user). If the same KDF output is used both
to authenticate and to wrap keys, then anyone who can test a passphrase guess
against the stored verifier can also unwrap every file — a stolen database plus a
weak passphrase decrypts the entire vault offline.

## Decision

One Argon2id call, 64 bytes, split into two independent halves:

```
k        = Argon2id(passphrase, salt, ops=3, mem=64 MiB, out=64)
UKEK     = k[0..32]     stays in client RAM forever
auth_sec = k[32..64]    sent over TLS once per login
verifier = HMAC-SHA256(pepper, "vault/auth-verifier/v1" || auth_sec || account_digits)
```

- The server stores **only** `verifier`. It never stores `auth_sec`, never the
  passphrase, and never the UKEK (except the recovery blob, see below).
- The **pepper** lives in the server environment (or KMS), not in SQL. A stolen
  database alone yields no passphrase-testing oracle. Losing the pepper logs
  everyone out (acceptable); leaking the pepper plus the database allows offline
  cracking (mitigated by Argon2id cost + passphrase policy, and by rotation).
- Login rate limiting: 5 consecutive failures → 15-minute lock, tracked per
  account.
- Account enumeration: `/v1/auth/prepare` returns a deterministic *fake* salt
  (HMAC of the pepper over the digits) for unknown account numbers, and login
  returns one identical error body for "no such account" and "wrong secret".
- The recovery blob is a `CWRP` envelope of the UKEK under a 256-bit key derived
  from the 24-word phrase, so it is not a passphrase-cracking target.
- Passphrase policy at derivation time: ≥12 chars, ≥5 distinct characters, either
  3+ words or 20+ characters, small banned-substring list.

## Alternatives considered

- **OPAQUE / SRP-6a (a real PAKE):** strictly better — no verifier that can be
  attacked offline at all, and the server never sees even a derived secret. It
  needs a vetted implementation in Rust, Kotlin, and JS. Deferred, not rejected:
  the wire format already separates auth material from key material, so swapping
  the login protocol later touches `auth.rs` and the two login screens only.
- **Send the passphrase (simplest):** violates the plan's core promise and makes
  every TLS-terminating hop a key-theft vector.
- **Single 32-byte KDF output reused for both jobs:** the trap described above.
  Rejected.

## Consequences

- Pepper rotation = verifier rotation; do it as "accept old and new pepper for
  24 h, re-verify on next login, then drop the old". Documented in `docs/ops.md`.
- A pepper leak is a real incident: rotate, force re-login, notify.
- Client implementations must not cache `auth_sec` beyond the login call.
