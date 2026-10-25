# syntax=docker/dockerfile:1
#
# One image = API + built PWA. The browser hits the same origin as the API, so
# there is no CORS surface and no second deployment to keep in sync.
#
# Build:  docker build -t vault .
# Run:    docker run -p 8080:8080 -v vault-data:/data \
#           -e VAULT_PEPPER=$(openssl rand -hex 32) \
#           -e VAULT_SIGNING=$(openssl rand -hex 32) \
#           -e VAULT_PORTAL_KEY=$(openssl rand -hex 32) vault
#
# Rust and Node are build-time only; the runtime image carries a single static
# binary, the web bundle, and nothing else.

# ---------------------------------------------------------------- web bundle
FROM node:22-bookworm AS web-build
WORKDIR /build
# brand/ is outside web/ but the bundle imports it, so it must exist first.
COPY web/package.json web/package-lock.json ./web/
RUN cd web && npm ci --no-audit --no-fund
COPY brand ./brand
COPY web ./web
RUN cd web && npm run build

# ------------------------------------------------------------------- api build
FROM rust:1.91-bookworm AS api-build
# libsodium-sys-stable vendors libsodium and runs its ./configure + make install,
# so a C toolchain is required at build time (statically linked into the binary).
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential pkg-config \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY brand ./brand
RUN cargo build --release --locked -p vault-api

# --------------------------------------------------------------------- runtime
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl tini \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin vault \
 && mkdir -p /data/blobs /srv/web /secrets \
 && chown -R vault:vault /data /secrets

COPY --from=api-build /build/target/release/vault-api /usr/local/bin/vault-api
COPY --from=web-build /build/web/dist /srv/web
# A screening list that matches nothing, wired by default so the pipeline is live
# and observable from the first boot. Replace it: VAULT_HASH_LISTS=real=/srv/hashlists/x
COPY deploy/hashlists /srv/hashlists

# Secrets are generated once into /secrets (a volume) and reused forever; see
# crates/vault-api/src/secrets.rs. Nothing here needs a human with openssl.
ENV VAULT_BIND=0.0.0.0:8080 \
    DATABASE_URL=sqlite:/data/vault.db \
    VAULT_BLOB_DIR=/data/blobs \
    VAULT_WEB_DIR=/srv/web \
    VAULT_SECRET_DIR=/secrets \
    VAULT_AUTO_SECRETS=1 \
    VAULT_HASH_LISTS=placeholder=/srv/hashlists/placeholder.txt \
    RUST_LOG=info,tower_http=warn

EXPOSE 8080
# Two volumes on purpose: a backup of the data must not contain the pepper.
VOLUME ["/data", "/secrets"]

# The container is unhealthy if the database or the blob directory is unusable,
# which is exactly what /healthz checks.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

USER vault
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/vault-api"]
