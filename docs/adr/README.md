# ADR index

Architecture decisions, in the order they were made. An ADR here is binding:
code that contradicts one is a bug, or the ADR gets superseded by a new one.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-one-rust-core-shared-wire-format.md) | One Rust core defines the wire format; clients conform via vectors | accepted |
| [0002](0002-secretstream-framing.md) | `crypto_secretstream` with COOMF1 framing, 4 MiB chunks, final-tag rule | accepted |
| [0003](0003-upload-claims-are-advisory.md) | The upload's plaintext digest is advisory; screening is best-effort | accepted |
| [0004](0004-auth-verifier-pepper.md) | UKEK/auth split + HMAC pepper verifier; no passphrase on the wire | accepted |
| [0005](0005-portal-key-not-zero-knowledge.md) | PKEK means public files are *not* zero-knowledge; stated plainly | accepted |
| [0006](0006-account-number-check-digit.md) | 11 random digits + Damm check digit, plus a 6-hex fingerprint | accepted |
| [0007](0007-sqlite-now-postgres-later.md) | SQLite (WAL) now, Postgres-shaped schema | accepted |
| [0008](0008-jurisdiction-and-dmca-agent.md) | The DMCA-agent plan conflicts with the anonymity plan; pick a posture | **open** |
| [0009](0009-kinetic-session-tokens.md) | Session tokens are random + server-side hashed; no JWT | accepted |
| [0010](0010-one-codebase-brand-as-data.md) | One codebase, brand as data, brand-neutral internals | accepted |
| [0011](0011-cdn-ciphertext-serving.md) | Ranges, ETag, cacheable ciphertext, origin secret for CDN serving | accepted |
| [0012](0012-js-budget-and-zero-js-client.md) | Lazy-loaded crypto (5 kB first paint) + a zero-JS CLI client | accepted |
| [0013](0013-secret-lifecycle.md) | Secrets generated once, fingerprint-verified, refused rather than regenerated | accepted |
