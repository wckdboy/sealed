# Operations

Everything here assumes the deployment shape from `docs/MASTER-PLAN.md` §5: one
Hetzner box behind Bunny, blobs on a Storage Box, no Cloudflare anywhere.

## 1. Secrets

Three values, generated on first boot into `VAULT_SECRET_DIR` (`/secrets` in the
container, a separate volume from `/data`), mode `0600`, never overwritten:

| Variable | Also a file | What it is |
|---|---|---|
| `VAULT_PEPPER` | `/secrets/pepper.hex` | HMAC key for login verifiers |
| `VAULT_SIGNING` | `/secrets/signing.hex` | URL signing key |
| `VAULT_PORTAL_KEY` | `/secrets/portal.hex` | PKEK for public content |

Environment variables win over files; setting all three disables generation
(`VAULT_AUTO_SECRETS=0`). Validation applies to every source: ≥32 bytes, not
all-identical, ≥8 distinct byte values. See ADR 0013 for the reasoning.

**Fingerprints.** `/healthz` reports `{source, fingerprint}` per secret, and the
boot log prints the same. Fingerprints are the first 8 hex chars of SHA-256 — use
them to prove a restart reused the same secrets, and to compare two hosts after a
migration. Never print the secret itself.

**The pepper fingerprint is recorded in the database** (`settings.pepper_fingerprint`)
on first boot and verified on every boot. Consequences:

- Restoring an old database without its matching secrets volume → **refuses to
  start** (prints both fingerprints). This is the check that replaces "hope".
- A pre-fingerprint database is adopted once with a warning, then verified.
- Rotating the pepper on purpose means: dual-accept old/new for the login window,
  then `UPDATE settings SET value = '<new fingerprint>' WHERE key = 'pepper_fingerprint'`
  deliberately. It is a decision, not a side effect.

**Backups.** `vault-secrets` is a *separate* volume from `vault-data` on purpose: a
stolen data backup must not contain the pepper. Back it up to a different custodian
(password manager, offline copy), never next to the database dump. Losing it while
keeping the data is the one unrecoverable failure, and the app refuses to start
rather than pretend.

**Escape hatch.** `VAULT_ALLOW_UNSAFE=1` bypasses the secret guard *and* permits
deliberately unsafe settings (rate limiting off, empty hash lists in production,
cache TTL 0). It logs at `ERROR`. Throwaway instances only.

## 2. Deploy

**Preferred: the container.** One image carries the API and the built web client;
the process serves both on one origin. See
[`deploy-coolify.md`](deploy-coolify.md) for the Coolify walkthrough.

```bash
docker build -t vault .
docker run -d --name vault -p 8080:8080 -v vault-data:/data \
  --env-file /etc/vault/env vault
```

The compose file expects the three secrets via `${VAULT_*:?}` interpolation, so a
missing secret fails the deploy rather than booting with a generated key.

**Without Docker** (bare binary + systemd), for a hand-built box:

```bash
cargo build --release -p vault-api
( cd web && npm ci && npm run build )
install -m 0755 target/release/vault-api /usr/local/bin/vault-api
rsync -a --delete web/dist/ /srv/vault/web/
systemctl restart vault-api
curl -fsS http://127.0.0.1:8080/healthz
```

with `VAULT_WEB_DIR=/srv/vault/web` in `/etc/vault/env`. If `VAULT_WEB_DIR` is set
but has no `index.html`, the service refuses to boot — a misconfigured static dir
must never look like a 404 storm in production.

Systemd sketch:

```ini
[Service]
EnvironmentFile=/etc/vault/env
ExecStart=/usr/local/bin/vault-api
User=vault
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/vault
```

## 3. Data

- `DATABASE_URL=sqlite:/var/lib/vault/vault.db`
- `VAULT_BLOB_DIR=/var/lib/vault/blobs`
- Backups: `sqlite3 vault.db ".backup /backup/sealed-$(date +%F).db"` plus
  `rsync -a --delete blobs/ storagebox:/sealed/blobs/`. Both are safe to mirror
  anywhere: metadata is non-secret, blobs are ciphertext.
- **Never** back up `/etc/vault/env` next to the database. Keep it in a
  password manager with a separate custodian.
- Restore drill monthly: restore DB + one blob, start on a scratch port, confirm
  `/healthz` and one signed download with a fixture account.

## 4. CDN

Full Hetzner/Bunny setup (firewall rules, Storage Box, pull zone, cache keys):
[`deploy-hetzner.md`](deploy-hetzner.md). Summary below.


- Blobs answer `Cache-Control: public, max-age=N, s-maxage=N`
  (`VAULT_BLOB_CACHE_SECONDS`, default 3600), with `Accept-Ranges: bytes`, a strong
  `ETag`, and `206` range support — all of which a CDN needs, and Bunny's video
  optimisation issues its own range requests upstream.
- The CDN should exclude `exp`/`sig` from the cache key (otherwise every signed URL
  is a miss) and keep TTL ≤ 1 h; TTL is also the worst-case window in which a
  quarantined file is still served from an edge. **Purge on quarantine** — the
  origin 404s immediately, the edge does not.
- Behind Bunny set `VAULT_TRUST_PROXY=1`: Bunny replaces `X-Forwarded-For` with the
  visitor IP and discards client-supplied values, so rate limiting keys on the real
  client. Optionally set `VAULT_ORIGIN_SECRET` and inject the same header at the
  edge; direct hits on the origin are then refused by the app.
- Quarantine → **purge the URL at the CDN** as part of runbook step 1. The origin
  will 404 immediately; the edge may still hold bytes.

## 5. Monitoring

Minimum viable:

- `/healthz` (db + blob dir + list names) from an external prober every 60 s.
- Log-based alerts: `blocked upload on hash match`, `CSAM-class report`,
  `internal error`, 5xx rate > 1%, disk > 80%.
- Daily counts: accounts created, uploads, quarantines, bytes stored (all from
  `mod_log`/`files`, no per-user tracking).

## 6. Runbook for "we lost the box"

1. Provision new host, same secrets from the password manager.
2. Restore DB and blobs.
3. Point DNS back.
4. Verify: `/healthz`, login with a fixture account, download and decrypt one
   fixture file, `GET /v1/p/<public fixture>` with a gated session.
5. Post-mortem: what was in memory that was not on disk (nothing should be, except
   the PKEK — which is in the environment and therefore restorable).
