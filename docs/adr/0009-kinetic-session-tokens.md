# ADR 0009 — Session tokens: random, server-side hashed, no JWT

**Status:** accepted
**Date:** 2026-10-25

## Context

Sessions carry two facts that matter: `account_id`, and whether the 18+ gate was
passed. They must be revocable (ban, strikes, lost device) and must not leak
anything if the database is dumped.

## Decision

- Token = 32 random bytes, hex, returned once at login.
- Storage = `SHA-256("vault/session-token/v1" || token)`, primary key of
  `sessions`.
- Expiry: 30 days, absolute (no sliding renewal in phase 0; a fresh login is one
  Argon2id call, which the client has already paid).
- The gate flag lives in two places on purpose: `sessions.gate_at` (this device,
  this session) and `accounts.gate_at` (this account, remembered so a re-login
  does not re-prompt). Both must be checked where it matters — the code checks
  `session.gate_at` first, then the account.
- Expired sessions are deleted lazily at login; a cron job can do it later.

## Why not JWT

- Revocation requires either a deny-list (which is a session table anyway) or
  short TTLs (which means re-deriving the passphrase constantly).
- Claims would need to include the gate state, which must be revocable
  independently of the token.
- A signed blob in localStorage is a worse security posture than an opaque
  identifier in localStorage, for no operational gain at this scale.

## Consequences

- Every authenticated request costs one indexed lookup. At projected load that is
  nothing.
- Logout, ban, and "revoke all devices" are one `DELETE`.
- The gate is a server-side fact, not a client-side promise: a client cannot
  assert its way into the portal key.
