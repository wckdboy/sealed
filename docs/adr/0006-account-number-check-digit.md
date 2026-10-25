# ADR 0006 — Account numbers: 15 random digits + Damm check digit (16 total)

**Status:** accepted · supersedes the 12-digit decision of this ADR
**Date:** 2026-10-25

## Context

The plan asked for a random 12-digit account number, no email, Mullvad-style. The
first implementation was 11 random digits + 1 Damm check digit, i.e. 10^11 ≈ 100
billion numbers.

That is plenty to stop someone *guessing* an account, but the number is the account's
only identifier: it is spoken in support, shown on screen shares, captured in
screenshots of the signup screen, and repeated in every "what is my account number"
message. 10^11 is a needlessly tight ceiling for a system that never reuses a number,
and the check digit buys the same two things it always did:

- typos and OCR slips are caught *before* a login attempt, so users do not burn a
  lockout on a slip;
- support can say "that number cannot exist" instead of "try again".

## Decision

**16 digits: 15 random from the CSPRNG + 1 Damm check digit.** 10^15 = one
quadrillion numbers — five orders of magnitude of headroom for four extra keystrokes.

- Display form: four groups of four, `4827 3910 5649 0182`. Storage form: bare
  digits. QR/paste form: `vault:acct:4827391056490182`.
- Damm catches every single-digit error and every adjacent transposition (including
  0↔9, which Luhn misses).
- All-identical numbers (`0000000000000000`) are rejected as degenerate even though
  they pass the check digit.
- A 6-hex **fingerprint** = `SHA-256("vault/acct-fingerprint/v1" || digits)`
  truncated to 3 bytes, shown at signup and in the app header: a "is this my account"
  hint for a human, not a security boundary.
- The account number is a *name*, not a secret. Possession authenticates nothing;
  login also requires the passphrase-derived secret (ADR 0004).

## This is a breaking change, and it is enforced loudly

Numbers created by the 12-digit build no longer parse. Rather than let each user find
that out at login, the API **refuses to start** when the database holds account
numbers whose length is not 16, naming the count and the remedies (export or delete
them, or run the previous release). `VAULT_ALLOW_UNSAFE=1` overrides at `ERROR` — the
same pattern as the other startup guards (ADR 0013).

Nothing else changes: the verifier is `HMAC(pepper, auth_secret || digits)` so any
length works, the column is `TEXT`, and the fingerprint, QR prefix and Damm table are
length-independent. The change is confined to generation, parsing, formatting and the
conformance vectors — exactly the boundary ADR 0001 exists to police.

## Consequences

- The conformance vectors pin a 16-digit account (`4827391056490182`, fingerprint
  `D34364`); the Rust core, the browser codec and the Kotlin client all validate
  against it.
- Any deployment with pre-change accounts must migrate or reset. Pre-launch that is
  nothing; live, it is a deliberate logged operation.
- Support tooling that matches 12-digit numbers must be updated; the boot guard is
  what turns "we forgot" into a startup error instead of a wave of failed logins.
