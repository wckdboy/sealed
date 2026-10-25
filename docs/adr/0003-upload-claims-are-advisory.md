# ADR 0003 — The upload's plaintext digest is advisory; screening is best-effort

**Status:** accepted (this is a *limitation*, documented on purpose)
**Date:** 2026-10-25

## Context

The plan says: "Comoofy sends plaintext SHA-256; server checks NCMEC hash list".
That is the right instinct, but it hides three facts that must be written down,
because they define the legal and operational risk of the whole business:

1. **The digest is self-reported.** A hostile client sends the hash of a picture
   of a cat and uploads whatever it likes. Hash screening therefore stops only
   honest clients and re-uploads of previously-seen material. It is a filter,
   not a control.
2. **Novel material is invisible.** No hash matches material the lists have not
   seen. Only content inspection (CSAM classifiers) or human review can catch
   that, and both require plaintext the server does not have.
3. **Our own digest is domain-separated** (`vault/plaintext-sha256/v1`), so
   NCMEC/PhotoDNA/Thorn feeds must be re-hashed into our space at ingest. Nothing
   public will ever match our digests byte-for-byte by accident; the ingest step
   is mandatory, and a broken ingest silently turns screening into a no-op.

## Decision

1. Screen on upload against every configured list, in the digest space defined by
   `ids::plaintext_digest`.
2. A match: quarantine the account (`ban_flag`), record a `mod_log` row, refuse
   the upload with a generic error that does not reveal detection.
3. A `csam`/`underage` community report: immediately quarantine the file, freeze
   the account, log it, and page the operator (runbook step 1).
4. **No hash lists configured = loud startup warning**, and `VAULT_HASH_LISTS`
   is mandatory for production deploys (see `docs/ops.md`).
5. Because screening cannot be complete, upload access is gated three ways:
   paid tier, quota, and account-level strikes/ban. Cheap anonymous upload is the
   single largest amplifier of CSAM risk, and the plan's paywall instinct is
   correct — keep it.

## Consequences

- We must be able to prove, in a courtroom, that a screening process existed and
  ran. The `mod_log` table, the startup warning, and the CI test that a listed
  digest is refused are the evidence trail.
- The product must never advertise "CSAM-proof" or "moderated". It advertises:
  uploads cost money, lists are screened, reports are actioned within 48 h, and
  content we cannot inspect is exactly why we cannot promise more.
- Phase 1 additions: async fuzzy matching (SSDeep/PhotoDNA robust) on a
  quarantined candidate set, and Thorn Safer for classification of *reported*
  files where the reporter supplies a passphrase.
- The shipped image configures a **placeholder list that matches nothing**, so the
  screening path is wired and observable from the first boot instead of being
  absent. It is labelled: `healthz.screening` reports `placeholder-only`, and boot
  logs a warning naming the distinction between "screening ran" and "screening
  can catch anything". Replace it with real feeds before opening a public feed —
  the boot-time refusal for an empty `VAULT_HASH_LISTS` still applies, and a
  placeholder-only configuration is the one case that deliberately starts.
