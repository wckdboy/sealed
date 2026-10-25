# ADR 0010 — One codebase, brand as data, brand-neutral internals

**Status:** accepted
**Date:** 2026-10-25

## Context

There are two products to ship from one source: the private branded deployment
and a public repository under a different name with identical behaviour and
design. The naive approach — fork and rename — doubles the maintenance of a
security-sensitive codebase, and the copies drift in exactly the places that hurt
(crypto constants, validation rules, migrations).

Worse, a rename touches things a rename must never touch. The first cut of this
repo had the brand baked into:
- digest domain separators (`sealed/plaintext-sha256/v1`, `sealed/auth-verifier/v1`, …),
- the account-number QR prefix (`sealed:acct:`),
- session-token hashing, recovery-key derivation, URL signing,
- env var names (`SEALED_PEPPER`),
- crate names and the response header `x-sealed-cipher`.

Renaming any of those would have changed stored verifiers (every account locked
out), invalidated recovery blobs, broken signed URLs, and silently changed the
screening digest space (which would have turned hash matching into a no-op).

## Decision

1. **Internals are brand-neutral and stay that way.** Domain separators are
   `vault/*`, the QR prefix is `vault:acct:`, env vars are `VAULT_*`, crates are
   `vault-core`/`vault-api`, headers are `x-vault-*`. The brand may never appear
   in a byte that is hashed, signed, stored, or matched — this is now a review
   rule, not just a convention.
2. **Brand is data.** `brand/brand.json` (name, app name, tagline, accent colour,
   homepage, DMCA default, account noun) is `include_str!`-ed by the API and
   imported by the web bundle. `VAULT_BRAND_NAME` may override the display name at
   runtime; the accent colour has a `VITE_BRAND_ACCENT` build override.
3. **The public mirror is generated, never hand-edited.** `scripts/publish-public.sh`
   exports a clean tree at `HEAD`, swaps `brand/public.json` into
   `brand/brand.json`, renders the public README from `brand/README.public.md`,
   drops the private business plan, replaces remaining brand prose, **fails if any
   brand string survives**, and force-pushes to the public repo. Fixes go to the
   private repo first; the mirror is a build artefact.
4. **`brand/public.json` also carries the neutral name** so the mirror is
   reproducible from committed state alone.

## Consequences

- A rebrand is a JSON edit plus a re-run of the publish script. No code diff.
- The public repo is a strict subset of the private one, so a security fix lands
  once and propagates on the next publish.
- Tests do not depend on the brand (asserted by `brand::tests` and by the publish
  script's residual scan), which is what keeps "same functionality" true.
- The mirror cannot contain anything the private repo does not already have,
  except for the two generated files (README, brand.json) — so anything that must
  stay private must never be committed here, not merely be excluded later.
