# Hetzner VPS + Storage Box + CDN

Concrete setup for the deployment shape this repo targets: one Hetzner VPS running
the container, a Storage Box for cold/backup copies of the ciphertext, and Bunny in
front as the CDN. Every fact below marked *(verified)* was checked against the
Hetzner API or Hetzner/Bunny documentation on 2026-10-25; the rest is labelled as
an assumption you should confirm on your account.

## 0. State of the account, checked

| Thing | Found |
|---|---|
| Servers | `invincible-lab-head`, `invincible-lab-peer` — cpx22, running, **fsn1** |
| Cloud Firewalls | **none attached to either server** — every port is reachable from the internet right now |
| Storage Boxes | **none** (BX11 is the smallest: 1 TB, ~€3.20/mo, 10 snapshots, 100 sub-accounts) *(verified)* |
| SSH keys | `galahad-lab` registered |

Those two servers are your Invincible lab, not this product. Nothing here was
applied to them: a firewall that is wrong for a lab node (custom SSH port, node
ports, peer traffic) locks you out of work in progress. Create the rules for the
*vault* server, and apply the same pattern to the lab if you want it — see the
JSON below, which you can run yourself.

## 1. Firewall (free, and the single biggest win)

Hetzner Cloud Firewalls are **free** and the default is deny-inbound / allow-outbound
once a firewall exists *(verified)*. Up to 5 per server, 500 rules each.

### Rules for the vault server

Inbound:

| Proto | Port | Source | Why |
|---|---|---|---|
| tcp | 22 | your admin IP(s) only | SSH. If you cannot pin an IP, use Hetzner's console VNC as the break-glass path. |
| tcp | 80 | 0.0.0.0/0, ::/0 | ACME HTTP-01 + redirect to 443 |
| tcp | 443 | 0.0.0.0/0, ::/0 | HTTPS (Coolify/Traefik, or the CDN if it terminates TLS) |

Outbound (add rules only for what the box needs; everything else stays blocked
once you define any outbound rule):

| Proto | Port | Destination | Why |
|---|---|---|---|
| tcp/udp | 53 | 0.0.0.0/0 | DNS |
| udp | 123 | 0.0.0.0/0 | NTP (clock skew breaks Argon2 timing assumptions and TLS) |
| tcp | 80, 443 | 0.0.0.0/0 | ACME, package updates, CDN purge API |
| tcp | 23 | the Storage Box IP only | rsync/SSH to the box *(verified: SSH is on port 23)* |
| tcp | 25, 465, 587 | — | **no rule = blocked.** The box is structurally incapable of sending mail, so it can never be a spam source or get the IP listed. |

Note: Hetzner already blocks port 25 for new accounts; an explicit missing outbound
rule makes it true even after you request unblocking.

### Apply it

Console → Firewalls → Create. Or API:

```bash
curl -X POST https://api.hetzner.cloud/v1/firewalls \
  -H "Authorization: Bearer $HCLOUD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "vault-web",
    "rules": [
      {"direction":"in","protocol":"tcp","port":"22","source_ips":["203.0.113.10/32"],"description":"admin ssh"},
      {"direction":"in","protocol":"tcp","port":"80","source_ips":["0.0.0.0/0","::/0"],"description":"acme"},
      {"direction":"in","protocol":"tcp","port":"443","source_ips":["0.0.0.0/0","::/0"],"description":"https"},
      {"direction":"out","protocol":"tcp","port":"80","destination_ips":["0.0.0.0/0","::/0"],"description":"http out"},
      {"direction":"out","protocol":"tcp","port":"443","destination_ips":["0.0.0.0/0","::/0"],"description":"https out"},
      {"direction":"out","protocol":"tcp","port":"23","destination_ips":["<STORAGEBOX_IP>/32"],"description":"storage box"},
      {"direction":"out","protocol":"udp","port":"53","destination_ips":["0.0.0.0/0","::/0"],"description":"dns"},
      {"direction":"out","protocol":"udp","port":"123","destination_ips":["0.0.0.0/0","::/0"],"description":"ntp"}
    ]
  }'
```

Then attach it to the server (or use a label selector so any server labelled
`role=vault` inherits it):

```bash
curl -X POST https://api.hetzner.cloud/v1/firewalls/<FIREWALL_ID>/actions/apply_to_resources \
  -H "Authorization: Bearer $HCLOUD_TOKEN" -H "Content-Type: application/json" \
  -d '{"apply_to":[{"type":"server","server":{"id":<SERVER_ID>}}]}'
```

Log out and back in after applying: if you mistyped your admin IP, the console
(and this firewall, applied to a server you still have a session on) is how you fix
it. Firewall rules are stateful, so return traffic for allowed connections is fine.

### SSH hardening (on the box)

```bash
# /etc/ssh/sshd_config.d/10-vault.conf
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowUsers vault admin
MaxAuthTries 3
```

`fail2ban` is close to pointless here: with 22 restricted to your IPs, there is
nothing to ban. Install it only if you must expose SSH widely.

## 2. Storage Box

### Create + enable access

1. Console → Storage Boxes → Create → **BX11** (1 TB, ~€3.20/mo) in **fsn1** (same
   location as the VPS keeps latency and egress inside Hetzner).
2. Change settings → enable **SSH support** and **External Reachability**
   *(verified requirement)*.
3. Add the VPS's public key under SSH keys (OpenSSH format, not RFC4716).
4. Create a **sub-account** per purpose (`vault-blobs`, `vault-backups`) so a
   compromised blob-sync credential cannot delete backups.

Access is `ssh -p 23 uXXXXX@uXXXXX.your-storagebox.de`; only `/home` is writable,
so use relative paths in rsync targets *(verified)*.

### Do not mount SMB for the blob directory

Hetzner documents SMB/CIFS support, but also documents **errors with files larger
than 4 GB** *(verified in their docs)*, and this service accepts uploads up to
20 GB. A video blob over 4 GB cannot be trusted to an SMB mount. SSHFS is worse for
serving: every player seek becomes a synchronous network round-trip.

### Recommended layout: local primary, rsync replica

```
/var/lib/vault/            local NVMe (the volume Coolify mounts at /data)
  vault.db                 SQLite (WAL)
  blobs/<blob_ref>         ciphertext, immutable per ref
Storage Box: /home/vault-blobs/  replica of blobs/
Storage Box: /home/vault-backups/ borg repo for vault.db
```

Nightly replication (systemd timer). `--delete-delay` keeps a window in which a
mistaken local delete has not yet propagated:

```ini
# /etc/systemd/system/vault-blobs-sync.service
[Unit]
Description=Replicate ciphertext blobs to Hetzner Storage Box
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/rsync -a --numeric-ids --delete-delay \
  -e "ssh -p 23 -i /root/.ssh/storagebox_vault -o StrictHostKeyChecking=yes" \
  /var/lib/vault/blobs/ u123456@u123456.your-storagebox.de:./vault-blobs/
Nice=10
IOSchedulingClass=idle
```

```ini
# /etc/systemd/system/vault-blobs-sync.timer
[Unit]
Description=Nightly blob replication
[Timer]
OnCalendar=*-*-* 03:30:00
RandomizedDelaySec=900
Persistent=true

[Install]
WantedBy=timers.target
```

Backups of the database (encrypted, deduplicated, append-only):

```bash
borg init --encryption=repokey-blake2 --remote-path=borg-1.4 \
  ssh://u123456@u123456.your-storagebox.de:23/./vault-backups
borg create --stats \
  ssh://u123456@u123456.your-storagebox.de:23/./vault-backups::vault-{now:%F} \
  /var/lib/vault/vault.db
```

Keep the borg passphrase in the password manager next to — but not identical to —
the pepper. Storage Box **snapshots** (10 automatic on BX11) give you point-in-time
rollback of the replica without any client-side work.

### What this does *not* give you

Restore-on-read. If a blob is evicted locally it is gone from the app until you copy
it back — the API has no tiered-storage support yet (roadmap: hot/cold split). For
phase 0/1, size the VPS volume for the whole library plus 20% headroom; the Storage
Box is for durability, not capacity.

## 3. CDN (Bunny)

For the full protection picture — Shield tiers, rate-limit rules, learning mode,
bot/spam economics, and the attack runbook — see `docs/protection.md`.

### Pull zone

- Origin: the VPS. Use **Direct IP Origin with Custom Hostname** (a documented Edge
  Rule pattern) or a hostname that resolves to the VPS and send the right
  `Host`/SNI. Origin must be HTTPS with a valid cert (Let's Encrypt from
  Coolify/Traefik).
- Hostnames: the app's public hostname (`app.example.com`) as the pull zone's custom
  hostname — blob URLs are relative, so the host the browser is on is the host that
  carries the bytes. TLS at the edge via Bunny's free certificate; the origin is a
  separate, non-proxied `origin.example.com`.
- Leave **Token Authentication off**: this app signs its own URLs
  (`?exp=…&sig=…`, HMAC-SHA256, 2 h TTL). Two signing layers only add a failure
  mode. (Bunny's advanced token auth is HMAC-SHA256 too, so migrating later is
  mechanical.)

### Caching rules

| Setting | Value | Why |
|---|---|---|
| Cache expiry | 1 h (match `VAULT_BLOB_CACHE_SECONDS`) | TTL is also the worst-case window a quarantined file stays servable from an edge |
| Ignore query string in cache key: `exp`, `sig` | on | otherwise every request mints a new signed URL and every hit misses — see the tradeoff below |
| Optimize for video | on | Bunny then fetches **byte ranges** from the origin |
| Smart cache | off | blobs have no file extension; Smart Cache would refuse to cache them |
| Tier | High Volume | cost-optimised for large files/video |
| Edge Rule: `/` and `/assets/*` → Override Cache Time 0 | on | keeps the SPA shell out of the cache so deploys take effect immediately |
| Optimize for video + ETag | slicing on, ETag passthrough lost | Bunny does not pass `ETag` through when video slicing is enabled *(verified: bunny FAQ)* |

**The query-string tradeoff, stated plainly:** our signature lives in the query
string. If the CDN keys on it, hit rate is ~0 and you pay origin egress on every
play. If the CDN ignores `exp`/`sig`, one cached object serves every later request
until it expires — including requests whose signature has already expired. That is
acceptable here because the object is ciphertext and because the TTL bounds it, but
it is a real weakening: an attacker holding one captured URL can keep streaming from
the edge for up to the TTL after it should have died. Countermeasures: keep TTL at
1 h or less, and purge on quarantine. The alternative (Bunny token auth with a
path-based token, origin locked to the CDN) removes the expiry leak and is the
phase-2 change if that matters to you.

### Origin lockdown

Bunny forwards `X-Forwarded-For` = the real visitor IP (it *discards* any
client-supplied XFF) and adds `X-Real-IP`, `CDN-RequestId`, `CDN-PullZoneId`,
`CDN-RequestCountryCode` *(verified: bunny.net/docs/cdn/request-headers-to-origin)*.
So:

- set `VAULT_TRUST_PROXY=1` — the rate limiter then keys on the true client IP, and
  a visitor cannot forge it;
- add an Edge Rule that sets `x-origin-secret: <random>` on requests to the origin,
  and set `VAULT_ORIGIN_SECRET` to the same value. Direct hits on the VPS are then
  refused by the app even if the firewall allowlist is wrong. (Edge Rules can modify
  request headers per Bunny's docs; if your plan lacks that action, skip it — the
  firewall is the primary control.)
- defence in depth: restrict inbound 80/443 on the Hetzner firewall to Bunny's
  published IP ranges. That list is long and changes; an app-level secret plus
  "origin IP not published in DNS" is usually the better trade.

Bunny does **not** forward the visitor's `Range`, `If-None-Match`,
`If-Modified-Since` to the origin — it answers those from cache and, with "Optimize
for video" on, issues its *own* range requests upstream *(verified)*. That is why the
origin must implement ranges correctly: `GET /v1/blobs/:ref` now returns
`206 + Content-Range`, `Accept-Ranges: bytes`, a strong `ETag`, and
`Cache-Control: public, max-age=N, s-maxage=N`.

### Purge on quarantine

The runbook's step 1 now has a CDN half:

```bash
curl -X POST "https://api.bunny.net/purge?url=https://cdn.example.com/v1/blobs/<blob_ref>%3Fexp%3D…%26sig%3D…&async=false" \
  -H "AccessKey: $BUNNY_API_KEY"
```

Because `exp`/`sig` are excluded from the cache key, purge with the base URL pattern
Bunny stores; check the purge response, do not assume.

## 4. Verify it end to end

```bash
# 1. firewall: 22 open only to you, 443 everywhere, 25 closed
nmap -Pn -p22,443,25 <VPS_IP>

# 2. direct origin must refuse blobs once VAULT_ORIGIN_SECRET is set
curl -s -o /dev/null -w '%{http_code}\n' https://<vps>/v1/blobs/<ref>?exp=1\&sig=00   # 403

# 3. through the CDN, with a real signed URL
curl -sI 'https://cdn.example.com/v1/blobs/<ref>?exp=…&sig=…' | grep -Ei 'HTTP/|cache-control|accept-ranges|etag|cdn-'
curl -sI -H 'Range: bytes=0-1023' 'https://cdn.example.com/v1/blobs/<ref>?…' | grep -Ei 'HTTP/|content-range|cdn-cache'

# 4. second request must be a hit
curl -sI 'https://cdn.example.com/v1/blobs/<ref>?…' | grep -i 'cdn-cache'
```

## 5. Costs at this shape

| Item | ~€/mo |
|---|---|
| CPX22 VPS (fsn1) | 8 |
| BX11 Storage Box (1 TB) | 3.20 |
| Bunny (per GB, minimum $1) | 1–10 depending on plays |
| Domain | ~1.5 |

## 6. What is not verified here

- Whether your Bunny plan exposes the "set request header" Edge Rule action (the
  docs list Edge Rules as covering header modification; the plan-level UI was not
  checked).
- Real Storage Box throughput from your VPS — measure with `rsync --progress` on a
  few GB before trusting the nightly window.
- The 4 GB SMB limit is Hetzner's own documented caveat, not something I
  reproduced (no Storage Box exists on this account yet).
