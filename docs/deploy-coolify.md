# Deploying with Coolify

Target: one container, one volume, HTTPS via Coolify's proxy, deploy on push.
Everything below is what the repo already supports — no extra services.

## 1. Prerequisites

- Coolify v4 instance with a server attached (`localhost` is fine for a single box).
- A DNS `A` record for the app domain pointing at that server.
- The repo reachable from Coolify. For the private repo use **GitHub App** or a
  deploy key (Settings → Sources); Coolify clones as a deploy, not as you.

## 2. Create the resource

1. **Project → + New → Docker Compose**.
2. Source: this repo, branch `main`, **Base directory** `/`.
3. Compose file: `docker-compose.yaml`.
4. Do not enable "Build pack: Nixpacks" — the Dockerfile is authoritative.

## 3. Secrets — nothing to do

There is no secret to generate and no variable to paste. On first boot the app
creates the three load-bearing values inside the `vault-secrets` volume, mode `0600`:

| Secret | Protects | If lost | If leaked |
|---|---|---|---|
| pepper | login verifiers | every account must re-enrol | a stolen DB becomes an offline crack target |
| signing | blob URL signatures | outstanding URLs 403 (nothing else) | bandwidth theft until rotated |
| portal | public playback (PKEK) | public files stop decrypting | every public file readable |

The rules that make this safe (`docs/adr/0013-secret-lifecycle.md`):

1. Generated **once**. The files are never overwritten; a broken file is a boot
   failure, not a rotation.
2. Values are validated before use — all-identical bytes (`0000…`) or fewer than 8
   distinct byte values are rejected, whatever their source.
3. The pepper's fingerprint is recorded in the database (`settings`) on first boot
   and checked on every boot after.
4. `/healthz` shows each secret's **source** (`env`/`file`/`generated`) and its
   8-character fingerprint — compare across restarts to prove the volume is working.

**Optional overrides.** If you keep secrets in a vault, set `VAULT_PEPPER`,
`VAULT_SIGNING`, `VAULT_PORTAL_KEY` in Coolify's environment (Runtime only, locked —
they are never build arguments). Environment values win over files.
`VAULT_AUTO_SECRETS=0` requires all three.

### How Coolify's variable UI lines up with this

The compose file declares every variable Coolify should show. On import you get these
rows, all already correct:

| Variable in Coolify | Default | What to do |
|---|---|---|
| `SERVICE_FQDN_APP_8080` | Coolify-generated | Leave it. It is the "generate me a domain for service `app`, port 8080" signal. |
| `VAULT_PEPPER` / `VAULT_SIGNING` / `VAULT_PORTAL_KEY` | empty | Leave empty: the volume owns the secrets. Fill in only to hand custody to Coolify. |
| `VAULT_DEFAULT_TIER` | `basic` | Leave it: new accounts get 0 bytes, so signup spam is worthless. Set `premium1` only for a private instance. |
| `VAULT_TRUST_PROXY` | `1` | Right for Traefik/Bunny. Set `0` only if the container is exposed directly, or rate limits key on the proxy's IP. |
| `VAULT_ALLOWED_ORIGINS` | empty | Correct: same origin needs no CORS. |
| `VAULT_HASH_LISTS` | placeholder | Replace with real feeds (§6). |
| `VAULT_ADMIN_TOKEN` | empty | Set a long random value to enable the operator panel at `/#admin`; empty keeps `/v1/admin/*` a 404. |
| `VAULT_ALLOW_UNSAFE` | `0` | Leave `0`. |

Two custody modes, both supported:

1. **Volume (default).** Nothing in Coolify's database is secret. `/healthz` reports
   `source: generated`.
2. **Coolify holds them.** Replace the three blanks with Coolify's magic generators —
   it generates once, persists across deploys, and shows them under Environment
   Variables:
   ```yaml
   VAULT_PEPPER: ${SERVICE_PASSWORD_64_PEPPER}
   VAULT_SIGNING: ${SERVICE_PASSWORD_64_SIGNING}
   VAULT_PORTAL_KEY: ${SERVICE_PASSWORD_64_PORTAL}
   ```
   `/healthz` then reports `source: env`. The tradeoff is real: a Coolify database
   backup now contains the pepper, so it must be protected like the secrets volume.

**Accepted secret formats** — no transcoding step:

- 64+ hex characters (`openssl rand -hex 32`, the `/secrets/*.hex` files) are decoded
  to bytes.
- Anything else (Coolify's `SERVICE_PASSWORD_64_*` is 64 alphanumerics, as are
  Doppler/Infisical values) is used as raw bytes. Whitespace is trimmed, so
  `$(cat secret.txt)` with a trailing newline is safe.
- The portal key must be exactly 32 bytes for `crypto_secretbox`; longer material is
  derived with a domain-separated hash (`vault/portal-key/v1`) and `/healthz` reports
  `"portal": {"derived": true}`.
- Blank means "not supplied", so a blank UI row falls through to the volume instead
  of becoming a zero-length key.

**Switching modes after accounts exist is refused**, by design: the pepper
fingerprint in the database will not match the new value. To migrate, copy the
current secret out of the volume into the variable — never let the generator create a
fresh one:

```bash
docker exec <container> cat /secrets/pepper.hex     # paste into VAULT_PEPPER
```

**Back up `vault-secrets` separately from `vault-data`.** That separation is the
whole point: a stolen database backup must not contain the pepper. Losing the
secrets volume while keeping the data is the one unrecoverable mistake, and the app
refuses to start in that state rather than silently locking everyone out.

### What the app refuses to do

| Situation | Behaviour |
|---|---|
| Database has accounts, secrets volume missing/empty | refuses to start, names the remedy, **writes nothing** |
| Pepper fingerprint ≠ the one this database was created with | refuses to start, prints both fingerprints |
| Secret is a placeholder or too short | refuses to start |
| `VAULT_RATE_LIMIT=0`, no hash lists in production, cache TTL 0 | refuses unless `VAULT_ALLOW_UNSAFE=1` |
| Throwaway instance where you want to ignore all of the above | `VAULT_ALLOW_UNSAFE=1`, logged at `ERROR` |

## 4. Domain + HTTPS

- **Domains → Add domain → service `app`, internal port `8080`**, value
  `https://vault.example.com:8080`. The `:8080` suffix is how Coolify learns which
  container port the public request should reach; visitors still use plain 443.
- Coolify writes Traefik labels for that service and port. The app already binds
  `0.0.0.0:8080` and serves the PWA itself, so no path rules are needed, and the
  compose deliberately publishes no host port (publishing one would bypass the proxy
  and its TLS).
- Enable "Force HTTPS". No CORS configuration is needed: one origin serves API, PWA
  and blobs, and blob URLs are relative on purpose.
- Redeploys keep the domain: it is stored by Coolify, not derived from the compose.

## 5. First boot

1. Deploy. Watch the log for `serving static client` and `listening on`.
2. `curl -fsS https://vault.example.com/healthz` →
   `{"status":"ok","product":"…","db":true,"blobs":true,"hash_lists":[]}`.
3. Open the domain, create an account with a 3+ word passphrase, **write down the
   account number and the 24 words**. The account starts on the `basic` tier with
   **no storage** — deliberate. For a private instance, set
   `VAULT_DEFAULT_TIER=premium1` (or bump `accounts.tier` in the database) before
   step 4.
4. Upload a small video and play it back: that path proves the whole pipeline
   (encrypt in the browser → ciphertext on disk → signed URL → decrypt in the tab).

## 6. Hash lists

The image ships `/srv/hashlists/placeholder.txt` and points `VAULT_HASH_LISTS` at
it, so screening is wired from the first boot. It **matches nothing** by
construction: `healthz.screening` reports `placeholder-only` and the log warns.
Replace it with real feeds — mount a list on the data volume and point the variable at
it:

```bash
# VAULT_HASH_LISTS=ncmec=/data/lists/ncmec.txt
```

Screening reads newline-delimited SHA-256 digests **in this project's digest
space** (domain-separated, see `docs/adr/0003-upload-claims-are-advisory.md`).
Third-party feeds must be re-hashed into it at ingest; dropping a raw NCMEC file
in will match nothing.

Lists live on the volume so they survive redeploys:

```bash
docker exec -it <container> mkdir -p /data/lists
docker cp ncmec.txt <container>:/data/lists/ncmec.txt
# then set VAULT_HASH_LISTS=ncmec=/data/lists/ncmec.txt and redeploy
```

The service refuses to start if a configured list is unreadable, and warns loudly
at boot when no list is configured.

## 7. Backups

Two things: the database and the blob directory. Both are non-secret by design
(the DB holds verifiers and metadata, blobs are ciphertext), so they are safe to
copy off-box — but keep the **secrets out of the same backup**.

```bash
# from the host, with the volume name from `docker volume ls`
docker run --rm -v vault_vault-data:/data -v "$PWD":/backup alpine \
  sh -c 'apk add --no-cache sqlite >/dev/null && sqlite3 /data/vault.db ".backup /backup/vault-$(date +%F).db" \
         && tar czf /backup/blobs-$(date +%F).tgz -C /data blobs'
```

Restore: stop the app, put `vault.db` and `blobs/` back on the volume, start,
`/healthz`, sign in with a fixture account. Rehearse it once — an unrehearsed
restore is not a backup.

## 8. Updates

Push to `main`; Coolify rebuilds and restarts with a health check gate (the compose
healthcheck is what gates it). Data lives on the volume; secrets live on the volume
too, or in Coolify's env if you opted into that mode — either way redeploys are
non-destructive, and the boot guard refuses to start rather than run with a mismatch.
Rollback = redeploy a previous commit from Coolify's deployment history.

## 9. DDoS, bots, spam

`docs/protection.md` is the layer-by-layer runbook: Hetzner's free L3/L4 filtering,
Bunny Shield (free tier) in learning mode before enforcement, the two edge rate-limit
rules worth having, and why the upload quota — not a WAF — is the anti-spam control.

## 10. Sizing

- CX22-class (2 vCPU / 4 GB) is ample: the API is I/O bound and Argon2id runs on
  the client.
- Blobs grow linearly with uploads; watch disk at 80%. When the local volume gets
  tight, bind-mount `/data/blobs` to a Hetzner Storage Box (or any block storage)
  and keep the database local.
- Put Bunny/Gcore in front for egress and origin-IP hiding. Cache `/v1/blobs/*`
  (they are immutable per `blob_ref`); purge by URL when quarantining a file.

## 11. What this deployment does not do

- No payments: tiers are set in the DB (`accounts.tier`, `accounts.storage_quota`)
  or by `VAULT_DEFAULT_TIER`. Wire XMR/vouchers before selling anything.
- No moderation UI: quarantine and reports are API/database operations — see
  `docs/ts-runbook.md` and do the rehearsal before opening a public feed.
- No public feed in this image beyond the API's public manifest endpoint; the web
  client uploads public files but there is no discovery surface yet.
