# Operator panel

`/#admin` in the web client, backed by `/v1/admin/*`. Off unless you switch it on.

## Turning it on

```bash
VAULT_ADMIN_TOKEN=$(openssl rand -base64 36)   # in Coolify / your env file
```

Then open `https://your-host/#admin` and paste the token. It is kept in
`sessionStorage` — this tab only, gone when the tab closes — and sent as
`Authorization: Bearer …`.

With the variable unset the entire namespace returns **404**, not 401: an instance
that never configured an admin has no admin surface to find, probe, or brute-force.
A wrong token gets 403 and no hint that a right one exists.

## What it shows

| Tab | Contents |
|---|---|
| Overview | account/file counts, bytes stored, quarantined, open reports, screening mode, which source each secret came from |
| Accounts | search by number, change tier (which sets the quota), ban/unban |
| Files | newest 50 with owner, size, visibility, state; quarantine |
| Reports | open reports with reason, detail, owner; resolve as quarantined / dismissed / warned |
| Branding | rename the instance, tagline, accent colour, optional mark |

Every mutating action is appended to `mod_log` with actor `admin`, so a moderation
decision always has a record of when and what.

## What it deliberately cannot do

- **Read a file.** The panel shows sizes and states. The keys live in users'
  browsers; there is no server-side decrypt path to expose. "Admin can see
  everything" is exactly what this product is built to make false.
- **Reset a passphrase.** Nobody can. Recovery is the 24 words, and only the user
  holds them.
- **See secrets.** The overview shows each secret's *source* (`file`, `env`,
  `generated`), never a value.

## Quarantine is two steps, on purpose

Quarantining sets `dead_flag` and `status=quarantined`; the origin immediately
returns `404` for that blob. But a CDN may still hold the object for up to
`VAULT_BLOB_CACHE_SECONDS`, so the response includes the path to purge:

```json
{"blob_ref": "dd34bc…", "purge_path": "/v1/blobs/dd34bc…", "cdn_ttl_seconds": 3600}
```

Purge it (Bunny dashboard or API) and treat the TTL as the worst-case window it stays
servable. That is why the docs keep telling you to run the cache TTL short.

## Hiding the panel

- Unset `VAULT_ADMIN_TOKEN` → the routes stop existing.
- Keep the token in a password manager, not in a bookmark. If it leaks, rotate by
  changing the variable and redeploying; old tokens stop working immediately
  because the token is compared on every request (constant-time) rather than
  exchanged for a session.

## Branding is a saved setting

Changing the name in the panel writes `brand.*` keys to `settings`, and `/v1/brand`
serves the merge of those over `brand/brand.json`. Clients pick it up on next load.
Validated as data: 1–32 characters, letters/digits/space/`_`/`-` only, no `vault`
prefix, accent must be `#rrggbb` — a brand string is rendered into the title and the
header, so it is never treated as markup.

Three ways to rename, in increasing permanence:

| Where | Effect | Rebuild? |
|---|---|---|
| `/#admin` → Branding | saved in the database, served by `/v1/brand`, applied to every client on load | no |
| `VAULT_BRAND_NAME` env | default served when nothing is saved | no |
| `brand/brand.json` | the shipped default — this is what the public mirror swaps | yes (`npm run build`) |

Nothing about the name is baked into accounts, verifiers, blobs or URLs, so renaming
an instance that has been running for a year is safe (ADR 0010).
