# Threat model

What we defend against, what we explicitly do not, and what the operator must do
for the whole thing to hold together. Update this file when an assumption changes.

## Assets, in order of value

1. **User plaintext and passphrases.** Never touch our infrastructure.
2. **UKEKs.** Exist only in client memory. Loss = data loss, by design.
3. **PKEK.** Unlocks every public file. Highest-value server secret.
4. **Pepper.** Turns a stolen database into a passphrase oracle if leaked.
5. **Signing secret.** Mints blob URLs; leak = bandwidth theft, not content.
6. **Account/tier/billing metadata.** Small, non-secret, but identifying.
7. **Ciphertext blobs.** Large, unreadable, safe to mirror.

## Defended

| Threat | Control |
|---|---|
| Disk/DB theft at the provider | Content is ciphertext; verifier needs the pepper; recovery blobs are 2^256. |
| CDN or hosting provider reading content | They only ever store/serve ciphertext; keys never leave clients. |
| CDN hotlinking / scraping bandwidth | Signed, expiring URLs; TTL capped at 6 h; origin refuses unsigned requests. |
| Account enumeration | Fake deterministic salt for unknown numbers; identical login error bodies. |
| Online passphrase guessing | Argon2id 64 MiB/3 passes client-side, 5-failure lockout, 15 min. |
| Offline passphrase cracking after DB theft | Pepper outside SQL; UKEK/auth split; recovery phrase at 256 bits. |
| Session theft from DB | Tokens stored hashed; revocation is a DELETE. |
| Tampered/truncated/reordered blob | secretstream final-tag rule; exact ciphertext length enforced on upload; `decrypt_all` rejects trailing data. |
| Over/under-declared uploads (quota fraud, smuggling) | Server computes `ciphertext_len_for(declared)` and requires an exact match. |
| Under-wrapped files (server could read a "private" file) | `FileInitRequest::validate` refuses a private file carrying a portal wrap, and a public file without one. |
| Banned account continuing to serve | Quarantine flips status; blob endpoint refuses anything not `ready`, even with a valid old signature. |
| Admin reading private files | Not possible: no key material for private or passphrase files exists server-side. |

## Not defended (state plainly)

| Threat | Why not | Mitigation / posture |
|---|---|---|
| Malicious or novel CSAM | Requires plaintext inspection | Upload paywall + hash screening + reports (ADR 0003); jurisdiction decision (ADR 0008) |
| Server operator abusing PKEK for public files | Architectural tradeoff to make guest streaming work | ADR 0005; seasonal rotation; no PKEK on disk/logs |
| Client compromise (malware, keylogger) | Outside our boundary | Passphrase never persisted; device-side only |
| A user losing their passphrase and recovery phrase | By design | Aggressive signup UX, recovery acknowledgement flag |
| Legal compulsion to decrypt | We cannot comply — we do not hold the keys | Documented; counsel must be briefed (ADR 0008) |
| Traffic analysis (who watches what) | Content is encrypted, timing is not | Phase 3: cover traffic / CDN-level padding if it matters |
| Metadata correlation of account ↔ file (owner is stored) | Needed for quota and deletion | Owner IDs are server-side only; no public linkage except the uploader choosing to publish |

## Operator obligations (non-negotiable)

1. **Never** put PKEK, pepper, or signing secret in the repo, a log line, a crash
   dump, or a backup that also contains the database.
2. Rotate pepper/PKEK on staff change or suspected exposure (`docs/ops.md`).
3. Keep `VAULT_HASH_LISTS` populated; a deploy with an empty list is a
   knowingly unmoderated service.
4. Rehearse the CSAM runbook once before launch (`docs/ts-runbook.md`).
5. Never claim "zero-knowledge" for public content (ADR 0005).
