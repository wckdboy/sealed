# Protection: DDoS, bots, spam, and the CDN

One page, ordered by layer, with the settings that actually matter. Facts marked
*(verified)* were checked against Hetzner/Bunny/Cloudflare documentation on
2026-10-25; everything else is a judgement call you should re-check on your account.

**The short version:** three of the four layers are free and take twenty minutes.
The fourth — spam — cannot be solved at the edge at all, because this system is
end-to-end encrypted and an edge cannot inspect what it cannot read. It is solved
with economics: an account with no upload quota is worthless to a spammer.

## The layers, and who owns what

| Layer | Attack | Control | Cost |
|---|---|---|---|
| L3/L4 | volumetric flood, SYN flood, reflection | Hetzner's network, automatic *(verified)* | free |
| L7 | HTTP flood, credential stuffing, scanners | Bunny Shield WAF + rate limits; app rate limits | free → $9.5/mo |
| Cost | bandwidth/lookup burn | rate limits at the edge, signed URLs, short TTL, prepaid balance | free |
| Spam | fake signups, junk uploads | **tier economics + quotas**, app rate limits | free |
| Content | illegal uploads | report-driven review, hash lists (client-side awareness), DMCA | free |

### What no CDN can do for you

The origin only ever stores **ciphertext** (ADR 0002). Bunny Shield sells upload
scanning and CSAM/AV scanning; on this system it is structurally useless, because
the bytes crossing the edge are already encrypted and the edge has no keys. Any
moderation product that advertises "scan uploads at the edge" is selling you nothing
here. That is the price of zero-knowledge, and it is why the upload quota — not a
WAF rule — is the abuse control.

## 1. Hetzner: the free layer

**DDoS protection is included and automatic.** Hetzner's system detects and filters
attacks before traffic reaches the server; it costs nothing and cannot be turned off
*(verified: hetzner.com/unternehmen/ddos-schutz, and "continuously active DDoS
recognition" in their Technical and Organizational Measures)*. It is L3/L4 only —
it will not save you from an HTTP flood.

**Cloud Firewall: free, stateful, deny-inbound by default once any rule exists.**
Exact rules in `docs/deploy-hetzner.md` §1. The two that matter for a CDN setup:

| Proto | Port | Source | Why |
|---|---|---|---|
| tcp | 22 | your admin IP only | SSH; Hetzner console/VNC is the break-glass path |
| tcp | 80, 443 | 0.0.0.0/0 | ACME + the CDN's origin fetches |
| tcp | 25/465/587 | **no rule** | the box cannot send mail, ever |

Do **not** publish the origin's IP in DNS. Point `vault.example.com` at the CDN and
give the pull zone the origin as a plain IP/hostname. That single omission removes
most opportunistic attacks, because they can only find what DNS advertises.

## 2. Bunny: cache, WAF, and the only rate limits that scale

### Creating the pull zone — the fields, exactly

Dashboard → **+ Add** → **Add Pull Zone**. Five decisions, then done:

| Field | Value | Why |
|---|---|---|
| Name | `vault-cdn` (letters/numbers only) | becomes `vault-cdn.b-cdn.net`; invisible once the custom hostname is added |
| Origin type | **Origin URL** | the VPS runs a normal HTTPS server; not Storage Zone, not Load Balancer |
| Origin URL | `https://origin.example.com` | a **separate** hostname that resolves to the VPS and is *not* behind the CDN, or you build a proxy loop |
| Tier | **High Volume** | cost-optimised for large files and video (fewer, bigger PoPs). *Standard* is for small files and websites; a video origin is the textbook High Volume case |
| Pricing zones | EU + NA to start | disabling a region does not block visitors there — they are routed to the nearest enabled region |

Origin **Host header**: leave empty (Bunny then sends `origin.example.com`, which is the name Traefik holds a certificate for). Only set it when the origin is a bare IP.

**Two hostnames, and only one of them is public:**

| Name | DNS | Serves |
|---|---|---|
| `app.example.com` | CNAME → `vault-cdn.b-cdn.net` | everything visitors use: PWA, API, blobs |
| `origin.example.com` | A → VPS IP, **not** proxied | Bunny's origin only; add it in Coolify as a second domain for the service so Traefik issues a certificate for it |

The pull zone's custom hostname must be the hostname people browse, because this
app serves blobs from relative URLs (`/v1/blobs/…`) — whatever host the browser is
on is the host that carries the bytes. Pointing the CDN at a separate `cdn.` name
would leave it serving nothing.

Then, immediately after creation (same pull zone, three tabs):

| Tab | Setting | Value |
|---|---|---|
| Caching | Cache Expiry | `3600` (match `VAULT_BLOB_CACHE_SECONDS`) |
| Caching | Vary by Query String | **off** (a.k.a. ignore query strings) — the app signs every URL, so keying on `exp`/`sig` gives a 0% hit rate |
| Caching | Optimize for Video Delivery | **on** (cache slicing: partial responses on uncached files) |
| Caching | Smart Cache | **off** (blobs have no extension; Smart Cache would refuse them) |
| Security | Shield | enable; tier Basic (free) |
| Security | Token Authentication | **off** — the app already signs URLs |
| Security | Origin SSL verification | **on** |
| Hostnames | custom hostname | **`app.example.com`** — the app's public hostname, CNAME to the pull zone, free Bunny certificate |

One Edge Rule, because the shell and the blobs want opposite caching:

| Rule | Condition | Action |
|---|---|---|
| 1 | path is `/` **or** starts with `/assets/` | Override Cache Time = `0` (or `60`) |

Without it the zone's 1 h TTL also caches `index.html`, and a deploy leaves the edge
serving the old bundle hash until it expires. The origin now sends the right headers
(`no-cache` for the shell, `immutable` for hashed assets), but the Edge Rule makes it
true even if a CDN ignores origin headers.

**Known trade-off:** with *Optimize for Video Delivery* on, Bunny does not pass the
origin's `ETag` through to clients *(verified: bunny.net FAQ — "as long as Optimize
for Video Delivery is disabled and an ETag header is present, the header will be
passed through")*. Slicing is worth more than conditional GETs for video; the origin
still answers `304` for direct hits and for anything the edge revalidates.

### Pull zone settings (the ones that matter)

| Setting | Value | Why |
|---|---|---|
| Cache expiry | 1 h | matches `VAULT_BLOB_CACHE_SECONDS`; also the worst-case window a quarantined file stays servable at an edge |
| Ignore query string for `exp`, `sig` | **on** | the app signs every URL; keying on the signature gives a 0% hit rate |
| Optimize for video | on | Bunny then issues its own byte-range requests (origin implements `206`) |
| Smart cache | **off** | blobs have no file extension; Smart Cache would refuse them |
| Token authentication | off | the app already signs URLs; two signing layers is one failure mode too many |
| WebSocket | off | not used |
| Bunny Optimizer | off | it rewrites HTML; you serve your own SPA bundle |

### Shield (WAF + DDoS + rate limits)

Enable Shield on the pull zone. **Basic is free** and is enough to start:
71 managed WAF rules, DDoS protection, **2 rate-limit rules**, 25M requests/month
included, $0.70/million after *(verified: bunny.net/shield pricing table)*.
Advanced ($9.50/mo) adds 255 rules, 10 custom rules, 10 rate-limit rules, simple bot
mitigation and curated threat lists; Business ($99/mo) adds complex bot mitigation.

Use the two free rate-limit rules for the only two paths that can hurt you:

| # | Path | Rule | Why |
|---|---|---|---|
| 1 | `/v1/accounts/*` | ~30 requests/minute per IP, block for 1–5 min | signup and login. Anything above this is a script. |
| 2 | `/v1/blobs/*` | ~600 requests/minute per IP | stops a byte-range hammering loop from billing you into the ground |

**Turn it on in the right order.** Every pull zone starts Shield in **Learning
mode** *(verified)*: it logs what it *would* have blocked and blocks nothing. Leave
it there for 24–72 h, watch for false positives on `/v1/accounts/*` (login forms are
the classic casualty — WAF vendors block them by default), add exceptions, *then*
enforce. Enforcing on day zero blocks real users and teaches you nothing.

**Bunny bills attack traffic.** Volumetric floods are absorbed by the network, but
application-layer junk that reaches the edge is bandwidth you pay for. Rate-limit
rules are therefore cost control as much as security. Keep the prepaid balance low
with manual top-ups rather than auto-recharge, and watch the bandwidth graph for a
day before you trust the defaults.

## 3. The app's own limits (already shipped)

Per-IP sliding windows, `429` + `Retry-After`, keyed on the true client IP when
`VAULT_TRUST_PROXY=1` (Bunny replaces `X-Forwarded-For` with the real visitor, so a
client cannot forge it):

| Route | Limit |
|---|---|
| `POST /v1/accounts` (signup) | 3 / 10 min |
| `POST /v1/accounts/auth` (login) | 30 / min, plus Argon2id 64 MiB + lockout after repeated failures |
| `POST /v1/files` (upload init) | 120 / min |
| `POST /v1/reports` | 20 / min |
| everything else | 600 / min |

Plus: 16-digit account numbers (10^15, unguessable), signed blob URLs with a 2 h TTL,
an optional origin secret so direct hits on the VPS are refused, and per-tier storage
quotas.

## 4. Spam: the part that has to be economic

A residential botnet signs up like real users. No CAPTCHA vendor fixes that without
also watching every visitor, which is the one thing this product promises not to
allow. So the control is that **an account with no quota is not worth creating**:

| Tier | Quota | Can upload |
|---|---|---|
| `basic` | 0 bytes | **no** |
| `premium1` | 1 TB | yes |
| `premium2` | 5 TB | yes |

Therefore, before you open signup to the public:

```yaml
VAULT_DEFAULT_TIER: basic     # new accounts can log in, cannot store a byte
```

Flip it to `premium1` only for a private, single-user instance — which is also the
only case where an open signup endpoint is safe at all. With `basic`, a thousand junk
accounts cost a thousand database rows and nothing else; the storage bill and the
abuse surface both require a voucher/payment, which is the point.

Optional, in increasing order of effort, if free-tier signup ever gets hammered:

1. **Invite codes** (best fit: vouchers already exist in the product plan). Signup
   takes a code; you mint codes deliberately. No third party, no JS, no privacy cost.
2. **Proof of work** on signup (Argon2id, ~1–2 s client CPU, server-side verification
   of a cheap check). Stops scripts, not farms; zero privacy cost; works without JS.
3. **Turnstile/hCaptcha** — the wrong trade here: a third party sees every signup,
   it requires JS, and it breaks the no-JS client. Only if the other two fail.

## 5. When it is happening (runbook)

1. **Site down, network graphs spike** → likely volumetric. Nothing to do; Hetzner
   filters it. Confirm the box is alive with the console, not with `curl`.
2. **Site slow or 5xx but the box looks idle** → L7 flood. Bunny dashboard → Shield →
   check what the rate-limit rules are dropping; if the attack is bypassing the CDN
   (hitting the origin IP directly, possible if the IP leaked), the app's origin
   secret already returns `403` — if the IP is compromised, move the server: a new
   Hetzner IP is a five-minute fix that ends the attack.
3. **Bandwidth bill climbing with no traffic** → byte-range or range-less loops.
   Purge, tighten rule 2, and check `VAULT_BLOB_CACHE_SECONDS` is not 0.
4. **Signup spike** → the tier setting is doing its job: watch DB size and disk.
   Tighten `/v1/accounts` rule 1 to 3/minute while it lasts.
5. **Afterwards** → keep the logs for a week; the Shield learning-mode history is the
   cheapest threat intelligence you will ever get.

## 6. Costs at this shape

| Item | ~€/mo |
|---|---|
| CPX22 (fsn1) | 8 |
| Bunny CDN, EU/NA ($0.01/GB, $1 minimum) | 1–10 |
| Bunny Shield Basic | 0 |
| Bunny Shield Advanced (when you need custom WAF rules / bot mitigation) | ~8.80 |
| Storage Box BX11 1 TB | 3.20 |
| Domain | ~1.50 |

## 7. Checklist

- [ ] Hetzner Cloud Firewall attached: 22 from your IP, 80/443 open, no 25.
- [ ] Origin IP absent from DNS; `vault.example.com` → CDN.
- [ ] Pull zone: 1 h cache, ignore `exp`/`sig`, video optimization on, Smart Cache off.
- [ ] Shield enabled, **Learning mode for 24–72 h**, then enforce.
- [ ] Two rate-limit rules: `/v1/accounts/*` 30/min, `/v1/blobs/*` 600/min.
- [ ] `VAULT_TRUST_PROXY=1` and `VAULT_DEFAULT_TIER=basic` before opening signup.
- [ ] `VAULT_ORIGIN_SECRET` set, and an edge rule that injects it.
- [ ] `/healthz` monitored from outside the box (`status`, `db`, `blobs`).
- [ ] Disk alert at 80%, bandwidth alert on the Bunny dashboard.
- [ ] Restore rehearsal done (`docs/deploy-coolify.md` §7) before the first real user.
