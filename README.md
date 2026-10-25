# Sealed

An encrypted vault you can host yourself.

An encrypted vault you run yourself: the server stores ciphertext it cannot read,
keys live only on the client, and identity is a 16-digit number with no email, no
phone, and no name. Includes a web client that encrypts in the browser, a Rust
API, and a Docker/Compose deployment that works on a single small VPS.

## What it actually guarantees

| Content | Server at rest | Server live | CDN | Anyone with a DB dump |
|---|---|---|---|---|
| Private | cannot read | cannot read | cannot read | cannot read |
| Passphrase-shared | cannot read | cannot read | cannot read | cannot read without the passphrase |
| Public (published) | cannot read | **can read** (by design) | cannot read | cannot read |

Public content is wrapped under a server-held portal key so strangers can stream
it; that is a deliberate tradeoff, documented in
[ADR 0005](docs/adr/0005-portal-key-not-zero-knowledge.md). Private and
passphrase-shared content is genuinely unreadable by the operator. The docs and
the UI copy are written to match — "zero-knowledge" is never claimed for public
files.

## Verified

| Claim | Evidence |
|---|---|
| Argon2id split, key envelopes, chunked framing, digests, account numbers and the recovery phrase are byte-identical in Rust and TypeScript | `spec/crypto-vectors.json`, generated and self-checked by the core; 14 JS conformance tests |
| Interop both ways (core ↔ browser) | `crates/vault-core/tests/interop_js.rs` + the JS fixture |
| Signup/login/age-gate/upload/download/stream over real HTTP | 12 API integration tests + a live end-to-end test |
| The server cannot read private files | no key material for them ever exists server-side |
| A "private" file carrying a server-readable key wrap is rejected | request validation + tests |
| A second, unrelated account can stream a public file with only the portal key | integration + live tests |

Not included yet: payments, thumbnails, passphrase share links, forum/chat,
resumable uploads, HTTP range requests, and the Android client (scaffold only,
uncompiled).

## Little JS, or none

Decryption in a browser *is* JavaScript — a page with scripting disabled cannot
unwrap a key. So the honest goals are: keep first paint tiny, and ship a client with
no script at all.

| Client | JavaScript | Notes |
|---|---|---|
| Web | **12 kB** initial (5 kB gzip) | the 1 MB libsodium chunk is dynamically imported on the first signup/unlock/upload/play |
| CLI (`vault`) | **none** | Rust, same core and protocol |

```bash
cargo build --release -p vault-cli
export VAULT_API=https://your-host

vault signup                      # account number + 24 words, printed once
vault login 4827 3910 5649 0182   # stores a session token only
vault gate
vault put clip.mp4 --public
vault cat f_ab12… | mpv -         # decrypt to stdout and play
vault get f_ab12… clip.dec.mp4
```

The passphrase comes from a TTY prompt, `$VAULT_PASSPHRASE` or `--passphrase-file`;
it is never stored, and the key is re-derived per command. See
[ADR 0012](docs/adr/0012-js-budget-and-zero-js-client.md).

## Run it

```bash
# one container: API + built web client on the same origin
docker build -t sealed .
docker run -d --name sealed -p 8080:8080 \
  -v sealed-data:/data \
  -e VAULT_PEPPER=$(openssl rand -hex 32) \
  -e VAULT_SIGNING=$(openssl rand -hex 32) \
  -e VAULT_PORTAL_KEY=$(openssl rand -hex 32) \
  sealed
open http://localhost:8080
```

Or with compose (and with [Coolify](docs/deploy-coolify.md) on a VPS):

```bash
VAULT_PEPPER=$(openssl rand -hex 32) \
VAULT_SIGNING=$(openssl rand -hex 32) \
VAULT_PORTAL_KEY=$(openssl rand -hex 32) \
docker compose up -d --build
```

Node and Rust are build-time only. The runtime image is one static binary, the
web bundle, and a `/data` volume.

## How it works

```
passphrase --Argon2id(64 MiB, 3 passes)--> 64 bytes --> UKEK      (client only)
                                                   \--> auth_secret --HMAC(pepper)--> verifier
file --XChaCha20-Poly1305 secretstream (4 MiB chunks)--> ciphertext (server, CDN)
FEK  --secretbox--> envelope under UKEK              (private)
                 + envelope under the portal key     (public, server-readable — stated plainly)
```

- The server enforces *shape*, not semantics: exact ciphertext length for the
  declared plaintext size, the key-wrap matrix, quota, tier, ban state. It cannot
  see a frame, so those checks are the whole integrity story.
- Hash screening on a client-supplied digest is a filter for honest clients, not a
  control — see [ADR 0003](docs/adr/0003-upload-claims-are-advisory.md) and the
  [trust & safety runbook](docs/ts-runbook.md). Upload access is gated by tier and
  quota for that reason.

## Test

```bash
make check     # fmt, clippy -D warnings, cargo test, web typecheck + conformance + build, vector check
make live      # boots the API and runs the end-to-end HTTP test
```

## Docs

- [Deploy with Coolify](docs/deploy-coolify.md) / [operations](docs/ops.md)
- [ADRs](docs/adr/README.md) — every tradeoff, including the ones that hurt
- [Threat model](docs/threat-model.md)
- [Trust & safety runbook](docs/ts-runbook.md)
- [Roadmap](docs/ROADMAP.md)

## Licence

AGPL-3.0-only. Run it as a service and you publish your changes.
