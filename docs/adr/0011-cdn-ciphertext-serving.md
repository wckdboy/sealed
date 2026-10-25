# ADR 0011 — Serving ciphertext through a CDN: ranges, cache keys, origin lock

**Status:** accepted
**Date:** 2026-10-25

## Context

The CDN sits in front of an origin that serves opaque bytes with HMAC-signed query
strings. Three properties collide:

1. A player needs byte ranges to seek; Bunny (and most CDNs) answer `Range` from
   cache and, with video optimisation, issue their **own** range requests upstream.
   An origin that ignores `Range` breaks seeking and can corrupt CDN-fetched parts.
2. A CDN keys cache entries on the full URL by default. Our authorisation lives in
   `?exp=…&sig=…`, which changes on every mint — so naive caching yields a ~0% hit
   rate and full origin egress.
3. If the key ignores those params, a cached object outlives its signature until the
   TTL expires. For encrypted media that is a bounded, acceptable leak; it must be
   bounded deliberately.

## Decision

- `GET /v1/blobs/:ref` implements single-range requests: `206` with
  `Content-Range`, `Accept-Ranges: bytes`, and `416` with `bytes */len` for
  unsatisfiable ranges. Multi-range is ignored (legal under RFC 9110) rather than
  answered with `multipart/byteranges` — no player asks, and a half-right
  implementation corrupts playback.
- Strong `ETag` = ciphertext SHA-256, with `If-None-Match` → `304`. Lets edges
  revalidate cheaply and lets clients resume without re-downloading.
- `Cache-Control: public, max-age=N, s-maxage=N`, N = `VAULT_BLOB_CACHE_SECONDS`
  (default 3600). **Public** on purpose: these are immutable ciphertext objects and
  `private` silently disables CDN caching. N is also the worst-case window a
  quarantined file remains servable from an edge — hence the runbook's purge step.
- CDN should exclude `exp` and `sig` from the cache key (documented tradeoff in
  `docs/deploy-hetzner.md`), TTL ≤ 1 h, purge on quarantine.
- Optional `VAULT_ORIGIN_SECRET`: when set, blobs require an `x-origin-secret`
  header, so a direct hit on the origin is refused even if the firewall allowlist is
  wrong. Constant-time compare. Off by default because it needs CDN-side header
  injection.
- `VAULT_TRUST_PROXY=1` makes the rate limiter use `X-Forwarded-For`; Bunny replaces
  that header with the visitor IP and discards client-supplied values, so the key is
  trustworthy behind it.

## Consequences

- The origin is a correct HTTP file server for ciphertext (ranges, ETag, cacheable),
  which is also what makes it usable *without* a CDN in front.
- Quarantine requires a CDN purge to be immediate; the TTL is the fallback bound.
  Both are in the runbook.
- Phase 2 option: replace our query-string signature for CDN traffic with Bunny
  token auth (path-based token) + origin secret. That removes the expired-signature
  cache leak entirely; it is a client/protocol change, so it is deliberately not
  in this phase.
