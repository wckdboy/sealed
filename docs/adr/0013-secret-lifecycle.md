# ADR 0013 — Secret lifecycle: generate once, fingerprint-checked, never regenerate

**Status:** accepted
**Date:** 2026-10-25

## Context

"Dead simple to host" and "hard to break badly" pull against each other on exactly
one question: who creates the pepper, the URL signing key and the portal key?

Before this ADR, the compose file required a human to run `openssl rand -hex 32`
three times and paste the results into Coolify. That is a manual step people skip —
by pasting `changeme`, by copying one value into all three, or by letting a redeploy
generate new ones "just this once". All three of those are incidents:

- a new **pepper** invalidates every stored verifier → nobody can log in;
- a new **portal key** makes every public file undecryptable;
- a placeholder pepper makes a stolen database an offline cracking exercise.

`VAULT_DEV=1` used to generate secrets in memory and drop them on exit, which is the
same catastrophe with a smaller blast radius: the container restarted and every
account was gone.

## Decision

1. **Generate once, on first boot, into `VAULT_SECRET_DIR`** (a volume), mode 0600,
   written atomically (temp → fsync → rename, refusing to overwrite). No human step,
   no `openssl` in the runbook.
2. **Precedence:** `VAULT_PEPPER` / `VAULT_SIGNING` / `VAULT_PORTAL_KEY` (env) win,
   then an existing file, then generation. Supplying all three disables generation
   (`VAULT_AUTO_SECRETS=0` makes that explicit).
3. **Validation before acceptance**, from any source: ≥32 bytes, not all-identical
   (`0000…`), ≥8 distinct byte values. A file that does not parse is a boot
   failure — never a reason to make a new one.
4. **Fingerprint in the database.** The SHA-256 prefix (8 hex chars) of the pepper
   is stored in `settings.pepper_fingerprint` on first boot and verified on every
   boot thereafter. This catches the mistake no "was it generated this boot?"
   heuristic can: a *restored old* secrets volume, or a pasted-but-wrong
   `VAULT_PEPPER`.
5. **Nothing is persisted until the guard agrees.** Generated secrets live in memory
   with a pending-write flag; `build_state` runs the check first, then persists. This
   closes a subtle hole found while testing the first implementation: the initial
   version wrote the files during config parsing, so a refused boot left fresh
   secrets on disk and the *next* boot happily "loaded" them — defeating the guard.
6. **Refuse, do not repair:**
   - accounts exist + secrets are new → refuse;
   - recorded fingerprint ≠ current → refuse;
   - a database that predates the fingerprint (accounts > 0, nothing recorded) →
     adopt once with a warning, then verify forever after.
7. **`VAULT_ALLOW_UNSAFE=1` is the only way past any of it**, and it is also required
   for genuinely unsafe settings (rate limiting off, no hash lists in production,
   cache TTL 0). One flag, loudly logged, never a silent default.
8. **Two volumes**: `/data` (database + ciphertext) and `/secrets`. A backup of one
   is not a backup of the other, and a stolen data backup contains no pepper.
9. Secrets appear in `/healthz` only as `{source, fingerprint}` — enough to compare
   two boots, useless to anyone reading a status page.

## Consequences

- `docker compose up` on an empty host is a working, correctly-keyed instance.
- The failure modes above become loud, actionable refusals naming the remediation.
- Backing up `/secrets` is now a first-class operational duty, documented in
  `docs/ops.md`; losing it while keeping the data is exactly the case the guard
  refuses to paper over.
- Rotation is unchanged in principle (dual-key window), but the fingerprint means a
  rotation must update `settings.pepper_fingerprint` deliberately — which is the
  point: rotation should be a decision, not an accident.

## Amendment — secrets from a secret manager (Coolify, Doppler, Infisical)

The first version of this ADR assumed secrets arrive as hex (`openssl rand -hex 32`
output) and that the portal key is exactly 32 bytes. Deployment platforms do not
work that way: Coolify's `SERVICE_PASSWORD_64_*` and most secret managers emit long
alphanumeric strings, so a strict hex rule would have forced an operator to transcode
by hand — a step that is skipped, or silently truncates, and that produces a different
key than the file path would have.

Rules now:

1. **Input is hex or text.** 64+ hex characters are decoded; anything else is used as
   raw UTF-8 bytes. Whitespace is trimmed (`$(cat secret)` newlines). Blank still
   means "not supplied", so an empty UI variable falls through to the volume.
2. **The portal key is exactly 32 bytes, by derivation if necessary.** Exactly 32
   bytes are used as-is; longer material is hashed with `vault/portal-key/v1` (the
   core's domain-separation convention). Deterministic, so the same input always
   yields the same key; `/healthz` reports `"derived": true` so the mode is never
   guessed at.
3. **The guards are unchanged.** Validation (≥32 bytes, not all-identical, ≥8 distinct
   values), the recorded pepper fingerprint, and refusal-on-mismatch all apply to env
   values exactly as to files. A regenerated platform secret is therefore a boot
   failure, not a silent lockout.
4. **Custody is a documented choice.** Volume-owned (default: the platform database
   never holds a secret) or platform-owned (`SERVICE_PASSWORD_64_*`: convenient, but
   now a platform backup contains the pepper). Switching after accounts exist is
   refused; migration is "paste the existing value into the variable", never "let the
   generator make a new one".
