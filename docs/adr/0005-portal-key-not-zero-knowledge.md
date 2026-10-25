# ADR 0005 — The portal key means public files are not zero-knowledge

**Status:** accepted
**Date:** 2026-10-25

## Context

The plan's matrix says it: "Admin/server (live, abusing PKEK) → public: can
unwrap (accepted tradeoff)". This ADR makes the tradeoff explicit, because the
marketing line "zero-knowledge" is otherwise a lie with legal exposure
(misrepresentation, and worse: an expectation of privacy the architecture cannot
honour).

## Decision

Three distinct claims, kept distinct in code, docs, and UI copy:

| Content | Server at rest | Server live (with PKEK) | CDN | Mods |
|---|---|---|---|---|
| Private | cannot read | cannot read | cannot read | cannot read |
| Passphrase-shared | cannot read | cannot read | cannot read | cannot read without the passphrase |
| Public | cannot read | **can read** | cannot read (ciphertext + key is separate) | can read (via PKEK) |

- PKEK is generated server-side, rotated seasonally, and released only to sessions
  that have confirmed 18+ (`POST /v1/gate`).
- PKEK rotation is a re-wrap job: every public file's `wrap_type = portal` row is
  unwrapped with the old key and rewrapped with the new one. Until that job
  completes, both keys are valid. Budget: one pass over public files, no
  re-upload, no client involvement.
- **UI copy must say "public content is encrypted in transit and at rest, and is
  readable by the service so it can be served to everyone"** — never
  "zero-knowledge" for public content.
- Private and passphrase content may legitimately be called zero-knowledge.

## Why keep PKEK at all

The alternative is per-viewer key grants: each guest gets a session key and the
owner's client must be online to approve or pre-sign grants. That is a much worse
product (no guest streaming without the owner online) and a much bigger
implementation. The plan made this call already; this ADR just records the
honest wording and the rotation obligation.

## Consequences

- The trust anchor for public content is the origin server's memory. That means:
  the PKEK must live in an environment variable loaded at boot and must not be
  written to logs, crash dumps, or a disk file. `config.rs` reads it from the
  environment and never persists it.
- Moderation of public content is technically possible (mod holds PKEK) — which is
  a feature, not a bug: it is the only way to review a reported public file.
- Private content stays unreviewable, which is why the CSAM posture relies on
  upload gating + hash screening + account bans (ADR 0003) rather than review.
